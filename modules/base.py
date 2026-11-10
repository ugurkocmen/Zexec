"""Base class for all Zexec modules."""
from __future__ import annotations

import abc
import logging

from core.config import Config
from core.runner import Runner
from core.state import State


class BaseModule(abc.ABC):
    """Common interface every attack/recon module implements.

    Subclasses receive the shared Config, Runner, Logger and State and expose a
    ``run()`` method that returns a dict of module-level results (if any).
    """

    name: str = "base"
    description: str = ""

    def __init__(self, config: Config, runner: Runner,
                 logger: logging.Logger, state: State):
        self.config = config
        self.runner = runner
        self.log = logger
        self.state = state
        self.aggressive = bool(config.get("general.aggressive", False))

    @abc.abstractmethod
    def run(self, **kwargs) -> dict:
        """Execute the module. Return a small results dict."""
        raise NotImplementedError

    # ---- small helpers ----
    def nxc_bin(self) -> str:
        """Resolve the netexec/crackmapexec binary name once."""
        cached = getattr(self, "_nxc_bin", None)
        if cached:
            return cached
        name = self.runner.which("nxc") or self.runner.which("netexec") \
            or self.runner.which("crackmapexec") or "nxc"
        self._nxc_bin = name
        return name

    def certipy_bin(self) -> str:
        """Resolve the certipy binary name once (certipy-ad on Kali)."""
        cached = getattr(self, "_certipy_bin", None)
        if cached:
            return cached
        name = self.runner.which("certipy-ad") or self.runner.which("certipy") \
            or "certipy-ad"
        self._certipy_bin = name
        return name

    # ---- evasion helpers ----
    def evasion(self) -> dict:
        """Return the evasion config section (for firewall/IDS avoidance)."""
        return self.config.get("evasion", {}) or {}

    def scan_flags(self) -> list[str]:
        """Build nmap flags from the evasion config (stealth-aware)."""
        ev = self.evasion()
        flags = ["-T" + str(ev.get("nmap_timing", 2))]
        flags += ["--min-rate", str(ev.get("nmap_min_rate", 1000))]
        flags += ["--max-retries", str(ev.get("nmap_max_retries", 1))]
        if ev.get("fragment_packets"):
            flags.append("-f")
        if ev.get("scan_delay"):
            flags += ["--scan-delay", str(ev["scan_delay"])]
        if ev.get("source_port"):
            flags += ["--source-port", str(ev["source_port"])]
        return flags

    def auth_delay(self) -> None:
        """Sleep a small random amount to avoid lockout / brute-force detection."""
        import random
        import time
        jitter = float(self.evasion().get("auth_jitter", 1.0))
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))

    def log_finding(self, severity: str, title: str, detail: str = "",
                    host: str | None = None, technique: str = "",
                    evidence: str = "") -> None:
        self.state.add_finding(severity, title, detail, host, technique, evidence)
        self.log.ok("[%s] %s%s", severity.upper(), title,
                    f" — {detail}" if detail else "")

    def aggressive_enabled(self, key: str) -> bool:
        """Whether a specific aggressive technique is enabled.

        Only returns True when the global ``--aggressive`` flag is set AND the
        technique is listed in the config's aggressive_only section.
        """
        if not self.aggressive:
            return False
        allowed = self.config.get("safety.aggressive_only", [])
        return key in allowed
