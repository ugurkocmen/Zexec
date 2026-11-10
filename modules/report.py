"""Report generation: Markdown + JSON summary of the engagement."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .base import BaseModule

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportModule(BaseModule):
    name = "reporting"
    description = "Generate the final report"

    def run(self, workdir: Path) -> dict:
        # Persist full JSON
        json_path = self.state.save(workdir)
        md_path = self._markdown(workdir)
        self.log.ok("report written: %s", md_path)
        return {"json": str(json_path), "markdown": str(md_path)}

    def _markdown(self, workdir: Path) -> Path:
        s = self.state
        lines: list[str] = []
        lines.append("# Zexec — Internal Network Penetration Test Report")
        lines.append("")
        lines.append(f"- **Target:** `{s.target_input}`")
        lines.append(f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append(f"- **Domain:** `{s.domain or 'unknown'}`")
        lines.append(f"- **Domain Controllers:** {', '.join(s.domain_controllers) or '—'}")
        lines.append("")
        lines.append("## Outcome")
        lines.append("")
        lines.append(f"- **Domain Admin achieved:** {'✅ YES' if s.domain_admin_achieved else '❌ No'}")
        lines.append(f"- **Enterprise Admin achieved:** {'✅ YES' if s.enterprise_admin_achieved else '❌ No'}")
        lines.append(f"- **Credentials recovered:** {len(s.usable_credentials())}")
        lines.append("")

        lines.append("## Hosts")
        lines.append("")
        lines.append("| IP | Hostname | Role | Open ports |")
        lines.append("|----|----------|------|-----------|")
        for ip, h in sorted(s.hosts.items()):
            role = "DC" if h.is_dc else "—"
            ports = ", ".join(str(p) for p in sorted(h.ports)) or "—"
            lines.append(f"| {ip} | {h.hostname or '—'} | {role} | {ports} |")
        lines.append("")

        lines.append("## Credentials")
        lines.append("")
        lines.append("| Account | Domain | Password | NT Hash | Source |")
        lines.append("|---------|--------|----------|---------|--------|")
        for c in s.credentials.values():
            if not (c.password or c.nthash):
                continue
            lines.append(
                f"| `{c.username}` | {c.domain or '—'} | "
                f"{c.password or '—'} | {c.nthash or '—'} | {c.source} |")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        findings = sorted(s.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
        lines.append("| Severity | Technique | Title | Detail | Host |")
        lines.append("|----------|-----------|-------|--------|------|")
        for f in findings:
            detail = (f.detail or "").replace("|", "\\|")[:120]
            lines.append(
                f"| {f.severity.upper()} | {f.technique or '—'} | {f.title} "
                f"| {detail} | {f.host or '—'} |")
        lines.append("")

        path = workdir / "report.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
