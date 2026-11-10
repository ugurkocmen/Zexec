"""Active Directory enumeration.

Gathers users, groups, computers, SPNs, AS-REP accounts, delegation,
trusts, LAPS/gMSA, password policy and AD CS configuration. All read-only.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseModule


class ADEnumModule(BaseModule):
    name = "ad_enumeration"
    description = "Enumerate users, groups, computers, delegation, trusts, ADCS"

    def run(self, workdir: Path) -> dict:
        self.log.info("enumerating Active Directory")
        auth = self._pick_auth()
        if not auth:
            self.log.warn("no credentials available; enumeration will be "
                          "limited to anonymous/null sessions")
        else:
            domain, user, pwd, nth = auth
            self.log.ok("enumerating as %s\\%s", domain, user)

        # Run independent sub-enumerations in parallel (they only read and
        # write into the thread-safe state store).
        from concurrent.futures import ThreadPoolExecutor
        tasks = [
            (self._password_policy, (auth,)),
            (self._roasting_targets, (auth, workdir)),
            (self._users_groups_computers, (auth, workdir)),
            (self._delegation, (auth,)),
            (self._trusts, (auth,)),
            (self._laps_gmsa, (auth,)),
            (self._adcs, (auth,)),
        ]
        with ThreadPoolExecutor(max_workers=7) as pool:
            futures = [pool.submit(fn, *args) for fn, args in tasks]
            for fut in futures:
                try:
                    fut.result()
                except Exception as exc:
                    self.log.debug("enumeration task failed: %s", exc)
        return {"domain": self.state.domain}

    # ------------------------------------------------------------------
    def _pick_auth(self):
        """Return (domain, user, password, nthash) or None."""
        domain = self.state.domain
        creds = self.state.usable_credentials(domain)
        if not creds:
            creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or domain, c.username, c.password, c.nthash)

    def _nxc_base(self, auth, proto: str):
        """Build the nxc command prefix with auth args."""
        nxc = self.nxc_bin()
        if not auth:
            return [nxc, proto]
        domain, user, pwd, nth = auth
        args = [nxc, proto]
        if pwd:
            args += ["-u", user, "-p", pwd]
        elif nth:
            args += ["-u", user, "-H", nth]
        else:
            args += ["-u", user, "-p", ""]
        if domain:
            args += ["-d", domain]
        return args

    def _dc_targets(self) -> list[str]:
        dcs = self.state.domain_controllers
        if dcs:
            return dcs[:2]
        # Fall back to hosts marked as DCs by IP
        return [ip for ip, h in self.state.hosts.items() if h.is_dc][:2] or \
               list(self.state.hosts.keys())[:1]

    # ------------------------------------------------------------------
    def _password_policy(self, auth) -> None:
        dcs = self._dc_targets()
        if not dcs:
            return
        res = self.runner.run(
            [*self._nxc_base(auth, "ldap"), dcs[0], "--pass-pol"],
            timeout=120, silent=True)
        text = res.stdout
        m = re.search(r"Account Lockout Threshold\s*:\s*(\d+)", text)
        if m:
            self.state.meta["lockout_threshold"] = int(m.group(1))
            self.log.ok("account lockout threshold: %s", m.group(1))

    # ------------------------------------------------------------------
    def _roasting_targets(self, auth, workdir: Path) -> None:
        """Find Kerberoastable (SPN) and AS-REP (no preauth) accounts."""
        dcs = self._dc_targets()
        if not dcs:
            return
        dc = dcs[0]
        domain = self.state.domain or (auth[0] if auth else None)

        # Kerberoastable (SPN) accounts
        if auth:
            d, u, p, nth = auth
            cmd = self.runner.resolve("GetUserSPNs", prefix="impacket-")
            args = [cmd]
            cred_arg = f"{d}/{u}"
            if nth:
                args += ["-hashes", f"0x0:{nth}"]
            else:
                cred_arg += f":{p}"
            args += [cred_arg, "-dc-ip", dc]
            res = self.runner.run(args, timeout=300)
            for line in res.out_lines:
                # "svc_mssql  svc_mssql/CORP:1433"
                if re.match(r"^[\w.$\-]+", line) and "/" in line and "@" not in line:
                    name = line.split()[0]
                    self.log_finding(
                        "high", "Kerberoastable account (SPN)",
                        f"{name} has an SPN and can be Kerberoasted",
                        technique="Kerberoasting")
                    self.state.add_credential(username=name, domain=domain,
                                              source="kerberoastable-spn")

        # AS-REP (no preauth) accounts
        cmd = self.runner.resolve("GetNPUsers", prefix="impacket-")
        if auth:
            d, u, p, nth = auth
            args = [cmd, f"{d}/", "-usersfile", "/dev/null"]
            if nth:
                args += ["-hashes", f"0x0:{nth}"]
            else:
                args += ["-no-pass"]
            args += ["-dc-ip", dc]
            # Without a user list this won't enumerate; use nxc instead
            res = self.runner.run(
                [*self._nxc_base(auth, "ldap"), dc, "--asreproast",
                 str(workdir / "asreproast_hashes.txt")],
                timeout=300)
            if "error" in res.stdout.lower() and "KDC" in res.stdout.upper():
                self.log.debug("asrep enumeration not permitted with this account")
        else:
            self.log.debug("AS-REP enumeration requires credentials")

    # ------------------------------------------------------------------
    def _users_groups_computers(self, auth, workdir: Path) -> None:
        dcs = self._dc_targets()
        if not dcs:
            return
        dc = dcs[0]
        base = self._nxc_base(auth, "ldap")

        # Users
        res = self.runner.run([*base, dc, "--users"], timeout=300, silent=True)
        users = []
        for line in res.out_lines:
            # nxc prints user lines; capture samaccountnames
            m = re.search(r"(\w[\w.\-]*)\s+\d{3,}", line)
            if m and "user" in line.lower():
                users.append(m.group(1))
        users = sorted(set(users))
        user_file = workdir / "users.txt"
        user_file.write_text("\n".join(users), encoding="utf-8")
        self.state.meta["user_count"] = len(users)
        self.state.meta["user_list_file"] = str(user_file)
        self.log.ok("enumerated %d user(s)", len(users))

        # Groups (admin groups of interest)
        res = self.runner.run([*base, dc, "--groups"], timeout=300, silent=True)
        for line in res.out_lines:
            low = line.lower()
            if any(g in low for g in
                   ("domain admins", "enterprise admins", "schema admins",
                    "account operators", "server operators", "backup operators")):
                self.log_finding(
                    "info", "Privileged group present", line.strip(),
                    technique="Group Enumeration")

        # Computers
        res = self.runner.run([*base, dc, "--computers"], timeout=300, silent=True)
        comps = [ln for ln in res.out_lines if re.search(r"\$\s", ln)]
        self.state.meta["computer_count"] = len(comps)

    # ------------------------------------------------------------------
    def _delegation(self, auth) -> None:
        dcs = self._dc_targets()
        if not dcs:
            return
        dc = dcs[0]
        # Unconstrained delegation
        res = self.runner.run(
            [*self._nxc_base(auth, "ldap"), dc, "--trusted-for-delegation"],
            timeout=300, silent=True)
        for line in res.out_lines:
            if line.strip():
                self.log_finding(
                    "high", "Unconstrained delegation",
                    line.strip(),
                    technique="Unconstrained Delegation")
        # Constrained delegation via impacket findDelegation
        if auth:
            d, u, p, nth = auth
            cmd = self.runner.resolve("findDelegation", prefix="impacket-")
            args = [cmd, f"{d}/{u}"]
            if nth:
                args += ["-hashes", f"0x0:{nth}"]
            else:
                args += ["-no-pass"]
            args += ["-dc-ip", dc]
            res = self.runner.run(args, timeout=300, silent=True)
            for line in res.out_lines:
                if "AccountName" in line or "Constrained" in line or \
                        "msDS-AllowedToDelegateTo" in line:
                    self.log_finding(
                        "high", "Constrained delegation", line.strip(),
                        technique="Constrained Delegation")

    # ------------------------------------------------------------------
    def _trusts(self, auth) -> None:
        dcs = self._dc_targets()
        domain = self.state.domain
        if not dcs or not domain:
            return
        # Trust objects live under the domain root as trustedDomain entries.
        base = ",".join(f"DC={p}" for p in domain.split("."))
        args = ["ldapsearch", "-x", "-H", f"ldap://{dcs[0]}", "-b", base,
                "(objectClass=trustedDomain)",
                "cn", "flatName", "trustDirection", "trustType",
                "trustAttributes"]
        if auth:
            d, u, p, nth = auth
            args += ["-D", f"{u}@{d}", "-w", p or ""]
        res = self.runner.run(args, timeout=120, silent=True)
        for line in res.out_lines:
            if line.startswith("cn:") or line.startswith("flatName:"):
                self.log_finding("info", "Domain/forest trust", line.strip(),
                                 technique="Trust Enumeration")

    # ------------------------------------------------------------------
    def _laps_gmsa(self, auth) -> None:
        dcs = self._dc_targets()
        if not dcs:
            return
        dc = dcs[0]
        res = self.runner.run(
            [*self._nxc_base(auth, "ldap"), dc, "--module", "laps"],
            timeout=300, silent=True)
        if "LAPS" in res.stdout or "password" in res.stdout.lower():
            self.log_finding("high", "Readable LAPS passwords",
                             "LAPS passwords are readable by this account",
                             technique="LAPS")
        res = self.runner.run(
            [*self._nxc_base(auth, "ldap"), dc, "--gmsa"],
            timeout=300, silent=True)
        if res.stdout.strip():
            self.log_finding("info", "gMSA accounts present", res.stdout.strip()[:500],
                             technique="gMSA")

    # ------------------------------------------------------------------
    def _adcs(self, auth) -> None:
        """Run certipy find if AD CS is likely present and we have creds."""
        if not auth:
            return
        d, u, p, nth = auth
        dcs = self._dc_targets()
        if not dcs:
            return
        dc = dcs[0]
        certipy = self.certipy_bin()
        args = [certipy, "find", "-u", f"{u}@{d}", "-dc-ip", dc,
                "-ldap-scheme", "ldap"]
        if nth:
            args += ["-hashes", nth]
        else:
            args += ["-p", p or ""]
        args += ["-vulnerable", "-stdout"]
        res = self.runner.run(args, timeout=300, silent=True)
        text = res.stdout
        for esc in re.findall(r"(ESC\d+)", text):
            self.log_finding(
                "critical", f"AD CS {esc} vulnerable", "",
                technique=esc)
        # Look for template names marked vulnerable
        for m in re.finditer(r"Template Name\s*:\s*([^\n]+)", text):
            self.log_finding("high", "AD CS template", m.group(1).strip(),
                             technique="ADCS Template")
