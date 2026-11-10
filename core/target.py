"""Target parsing and host discovery.

Accepts a CIDR range, a single IP, a hostname, or a file containing any of
the above. CIDR ranges are expanded and live hosts are discovered.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from .runner import Runner


class TargetError(ValueError):
    """Raised for malformed target input."""


def parse_target(raw: str) -> list[str]:
    """Turn a target string into a list of IP addresses (no host discovery yet).

    Raises TargetError on invalid input.
    """
    raw = raw.strip()
    if not raw:
        raise TargetError("empty target")

    # A file containing targets (one per line)
    if Path(raw).is_file():
        ips = []
        for line in Path(raw).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.extend(parse_target(line))
        return ips

    # CIDR range
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid CIDR: {raw}") from exc
        # Guard against absurdly large ranges
        if net.num_addresses > 65536:
            raise TargetError(
                f"CIDR {raw} has {net.num_addresses} addresses (limit 65536). "
                "Refuse to scan something this large by default.")
        return [str(ip) for ip in net.hosts()]

    # Single IP or hostname
    try:
        ip = ipaddress.ip_address(raw)
        return [str(ip)]
    except ValueError:
        pass
    # Treat as hostname (resolve later) — return as-is
    return [raw]


class HostDiscovery:
    """Discovers live hosts within a target scope."""

    def __init__(self, runner: Runner, log: logging.Logger):
        self.runner = runner
        self.log = log

    def discover(self, target: str) -> list[str]:
        """Return live host IPs for the given target.

        For a single IP (or resolved hostname) we return it directly without a
        liveness check — the port scan will confirm reachability.
        """
        try:
            ips = parse_target(target)
        except TargetError:
            raise

        # If only one address was supplied, don't bother with host discovery.
        if len(ips) == 1:
            return ips

        self.log.info("host discovery on %d addresses", len(ips))
        return self._ping_scan(ips)

    def _ping_scan(self, ips: list[str]) -> list[str]:
        """Fast ping sweep using nmap -sn across the address list."""
        import tempfile
        live: list[str] = []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(ips))
            tmp = fh.name

        result = self.runner.run(
            ["nmap", "-sn", "-n", "--min-rate", "1000", "-iL", tmp],
            timeout=600,
        )
        import os
        try:
            os.unlink(tmp)
        except OSError:
            pass
        for line in result.out_lines:
            # "Nmap scan report for 10.10.10.5"
            if "Nmap scan report for" in line:
                host = line.split()[-1]
                if _is_ip(host):
                    live.append(host)
        tmp.unlink(missing_ok=True)
        return live


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
