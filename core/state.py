"""Shared state: hosts, credentials, and findings.

The State object is the single source of truth that all modules read from and
write to. It also produces the final structured report data.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Credential:
    """A credential usable for authentication."""
    username: str
    password: str | None = None
    nthash: str | None = None
    domain: str | None = None
    # Provenance / how we got it
    source: str = ""
    # Whether we've already "used" this credential for lateral movement
    used: bool = False

    def key(self) -> str:
        return f"{self.domain or ''}\\{self.username}"

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "nthash": self.nthash,
            "domain": self.domain,
            "source": self.source,
        }


@dataclass
class Host:
    ip: str
    hostname: str | None = None
    ports: dict[int, str] = field(default_factory=dict)  # port -> service
    is_dc: bool = False
    os: str | None = None
    smb_signing: bool | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "ports": {str(k): v for k, v in self.ports.items()},
            "is_dc": self.is_dc,
            "os": self.os,
            "smb_signing": self.smb_signing,
        }


@dataclass
class Finding:
    """A single discovered item (vulnerability / misconfiguration / cred)."""
    severity: str          # info | low | medium | high | critical
    title: str
    detail: str = ""
    host: str | None = None
    technique: str = ""    # e.g. "ESC1", "Kerberoasting", "DCSync"
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "host": self.host,
            "technique": self.technique,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


class State:
    """Thread-safe store shared across modules."""

    def __init__(self):
        self._lock = threading.Lock()
        self.hosts: dict[str, Host] = {}
        self.credentials: dict[str, Credential] = {}
        self.findings: list[Finding] = []
        self.domain: str | None = None
        self.domain_sid: str | None = None
        self.domain_controllers: list[str] = []
        self.domain_admin_achieved: bool = False
        self.enterprise_admin_achieved: bool = False
        self.target_input: str = ""
        self.meta: dict[str, Any] = {}

    # ---- hosts ----
    def add_host(self, ip: str) -> Host:
        with self._lock:
            if ip not in self.hosts:
                self.hosts[ip] = Host(ip=ip)
            return self.hosts[ip]

    def get_host(self, ip: str) -> Host | None:
        return self.hosts.get(ip)

    def set_host_port(self, ip: str, port: int, service: str) -> None:
        h = self.add_host(ip)
        with self._lock:
            h.ports[port] = service

    # ---- credentials ----
    def add_credential(self, username: str, password: str | None = None,
                       nthash: str | None = None, domain: str | None = None,
                       source: str = "") -> bool:
        """Add a credential if it's new; return True if added."""
        with self._lock:
            key = f"{domain or ''}\\{username}"
            existing = self.credentials.get(key)
            if existing and (existing.password or existing.nthash):
                return False
            self.credentials[key] = Credential(
                username=username, password=password, nthash=nthash,
                domain=domain, source=source)
            return True

    def usable_credentials(self, domain: str | None = None) -> list[Credential]:
        """Credentials that have a password and/or hash, optionally filtered."""
        with self._lock:
            creds = [c for c in self.credentials.values()
                     if (c.password or c.nthash)]
            if domain:
                creds = [c for c in creds if c.domain == domain]
            return list(creds)

    def get_credential(self, username: str, domain: str | None = None) -> Credential | None:
        return self.credentials.get(f"{domain or ''}\\{username}")

    # ---- findings ----
    def add_finding(self, severity: str, title: str, detail: str = "",
                    host: str | None = None, technique: str = "",
                    evidence: str = "") -> None:
        with self._lock:
            self.findings.append(Finding(
                severity=severity, title=title, detail=detail, host=host,
                technique=technique, evidence=evidence))

    # ---- persistence ----
    def save(self, output_dir: Path) -> Path:
        """Write the full state as JSON to the output dir."""
        output_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "target": self.target_input,
            "domain": self.domain,
            "domain_sid": self.domain_sid,
            "domain_controllers": self.domain_controllers,
            "domain_admin_achieved": self.domain_admin_achieved,
            "enterprise_admin_achieved": self.enterprise_admin_achieved,
            "hosts": [h.to_dict() for h in self.hosts.values()],
            "credentials": [c.to_dict() for c in self.credentials.values()],
            "findings": [f.to_dict() for f in self.findings],
            "meta": self.meta,
        }
        path = output_dir / "results.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return path
