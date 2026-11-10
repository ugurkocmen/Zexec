"""Pipeline engine: orchestrates phases toward the "Domain Admin" goal."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from .config import Config
from .logger import Logger
from .runner import Runner
from .state import State
from .target import HostDiscovery
from modules.recon import ReconModule
from modules.evasion import EvasionModule
from modules.ad_ident import ADIdentifyModule
from modules.ad_enum import ADEnumModule
from modules.cred_attack import CredentialAttackModule
from modules.cred_more import CredMoreModule
from modules.database import DatabaseModule
from modules.abuse import AbuseModule
from modules.pathfind import PathFindModule
from modules.delegation import DelegationModule
from modules.relay import RelayModule
from modules.lateral import LateralModule
from modules.domain_admin import DomainAdminModule
from modules.report import ReportModule


class Engine:
    """Runs the attack pipeline."""

    def __init__(self, config: Config):
        self.config = config
        self.output_dir = Path(config.get("general.output_dir", "./zexec_output"))
        self.logger = Logger(self.output_dir, verbose=bool(config.get("general.verbose", False)))
        self.log = self.logger.logger
        self.runner = Runner(self.log, timeout=int(config.get("general.timeout", 180)))
        self.state = State()
        self._check_root()

    def _check_root(self) -> None:
        if os.geteuid() != 0:
            self.log.warning(
                "not running as root — SYN scans, raw sockets and some "
                "attacks will fail. Run with: sudo python3 zexec.py ...")

    def _checkpoint(self, workdir: Path) -> None:
        """Persist partial results so a crash/interrupt never loses findings."""
        try:
            self.state.save(workdir)
            self.log.debug("checkpoint saved to %s", workdir / "results.json")
        except Exception as exc:
            self.log.debug("checkpoint save failed: %s", exc)

    def run(self, target: str, username: str | None = None,
            password: str | None = None, nthash: str | None = None,
            domain: str | None = None) -> State:
        self.state.target_input = target
        if domain:
            self.state.domain = domain
        if username:
            self.state.add_credential(
                username=username, password=password, nthash=nthash,
                domain=domain, source="user-supplied")

        workdir = self.output_dir
        workdir.mkdir(parents=True, exist_ok=True)

        self.log.info("=" * 60)
        self.log.info("Zexec starting — target: %s", target)
        self.log.info("=" * 60)

        # Phase 0: host discovery
        live = HostDiscovery(self.runner, self.log).discover(target)
        if not live:
            self.log.error("no live hosts discovered — aborting")
            return self.state
        for ip in live:
            self.state.add_host(ip)

        # Phase 1: port scan
        ReconModule(self.config, self.runner, self.log, self.state).run(live)

        # Phase 1.5: firewall/IDS evasion — adaptive re-scan of filtered hosts
        EvasionModule(self.config, self.runner, self.log, self.state).run(workdir, hosts=live)

        # Phase 2: AD identification
        ADIdentifyModule(self.config, self.runner, self.log, self.state).run()

        # Phase 3: AD enumeration
        ADEnumModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 4: credential attacks
        CredentialAttackModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 5: additional credential sources (GPP/LAPS/gMSA)
        CredMoreModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 6: database attacks (Oracle / PostgreSQL / MSSQL / MySQL)
        DatabaseModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 7: misconfiguration abuse (AD CS ESC1, shadow creds, DCSync test)
        AbuseModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 8: BloodHound ACL pathfinding + exploitation
        PathFindModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 9: delegation abuse (RBCD) — aggressive-gated
        DelegationModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 10: NTLM relay + coercion — aggressive-gated
        RelayModule(self.config, self.runner, self.log, self.state).run(workdir)

        self._checkpoint(workdir)

        # Phase 11: lateral movement (harvest more creds)
        before = len(self.state.usable_credentials())
        LateralModule(self.config, self.runner, self.log, self.state).run(workdir)
        after = len(self.state.usable_credentials())

        # Phase 12: if we gained new creds, re-run abuse + pathfinding
        if after > before and not self.state.domain_admin_achieved:
            self.log.info("new credentials discovered — re-running abuse phases")
            AbuseModule(self.config, self.runner, self.log, self.state).run(workdir)
            PathFindModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 13: domain dominance + trust attacks
        DomainAdminModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Phase 14: report
        ReportModule(self.config, self.runner, self.log, self.state).run(workdir)

        # Summary
        self.log.info("=" * 60)
        self.log.ok("COMPLETE — DA: %s | EA: %s | creds: %d",
                    self.state.domain_admin_achieved,
                    self.state.enterprise_admin_achieved,
                    len(self.state.usable_credentials()))
        self.log.info("=" * 60)
        return self.state
