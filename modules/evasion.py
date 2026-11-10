"""Firewall / IDS evasion.

Provides stealth scan configuration (via ``scan_flags``) and an adaptive
re-scan of hosts that came back fully filtered/blocked — a common firewall
behaviour. Re-scans those hosts with a slower, quieter timing template and
optional packet fragmentation to slip past simple filtering.
"""
from __future__ import annotations

from pathlib import Path

from .base import BaseModule


class EvasionModule(BaseModule):
    name = "evasion"
    description = "Firewall/IDS evasion: stealth scans + adaptive retry"

    def run(self, workdir: Path, hosts: list[str] | None = None) -> dict:
        ev = self.evasion()
        self.log.info(
            "evasion profile: timing=T%s fragment=%s jitter=%.1fs scan-delay=%s",
            ev.get("nmap_timing", 2),
            bool(ev.get("fragment_packets")),
            float(ev.get("auth_jitter", 1.0)),
            ev.get("scan_delay") or "none",
        )

        if not ev.get("adaptive_retry", True):
            return {"rescanned": 0}

        blocked = [ip for ip, h in self.state.hosts.items() if not h.ports]
        if not blocked:
            return {"rescanned": 0}

        self.log.info("re-scanning %d filtered host(s) with stealth settings",
                      len(blocked))
        rescan = self._stealth_rescan(blocked)
        return {"rescanned": rescan}

    def _stealth_rescan(self, ips: list[str]) -> int:
        """Re-scan hosts with slower timing + fragmentation, updating state."""
        import tempfile
        found = 0
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(ips))
            tmp = fh.name

        ev = self.evasion()
        flags = ["-T" + str(min(int(ev.get("nmap_timing", 2)), 1)),
                 "--min-rate", "300", "--max-retries", "2",
                 "--scan-delay", ev.get("scan_delay") or "500ms"]
        if ev.get("fragment_packets"):
            flags.append("-f")

        # Reuse the same AD/Windows port set as recon
        from .recon import AD_PORTS
        res = self.runner.run(
            ["nmap", "-Pn", "-sS", "-n", *flags, "-p", AD_PORTS,
             "-iL", tmp, "-oG", "-"],
            timeout=1200, silent=True)
        for line in res.out_lines:
            if line.startswith("Host:") and "Ports:" in line:
                ip = line.split()[1]
                ports = []
                for entry in line.split("Ports: ", 1)[1].split(","):
                    f = entry.split("/")
                    if len(f) >= 2 and f[1] == "open":
                        try:
                            ports.append(int(f[0]))
                        except ValueError:
                            continue
                if ports:
                    host = self.state.add_host(ip)
                    for p in ports:
                        host.ports[p] = ""
                        self.state.set_host_port(ip, p, "")
                    found += 1
                    self.log.ok("evasion re-scan found open ports on %s", ip)
        import os
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return found
