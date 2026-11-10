"""Active Directory identification: find DCs, domain name, SMB signing."""
from __future__ import annotations

import ipaddress

from .base import BaseModule


class ADIdentifyModule(BaseModule):
    name = "ad_identification"
    description = "Locate domain controllers and identify the AD domain"

    def run(self, creds: list | None = None) -> dict:
        self.log.info("identifying Active Directory environment")

        # Candidates: hosts exposing Kerberos(88), LDAP(389), or SMB(445)
        candidates = []
        for ip, host in self.state.hosts.items():
            if any(p in host.ports for p in (88, 389, 636, 445)):
                candidates.append(ip)
        candidates = sorted(set(candidates))

        # First-class DC signal: Kerberos or GC/LDAP ports
        dc_candidates = [
            ip for ip, h in self.state.hosts.items()
            if 88 in h.ports or 389 in h.ports or 3268 in h.ports
        ]
        dc_candidates = sorted(set(dc_candidates)) or candidates

        # Try to obtain domain name and validate DCs via SMB
        self._smb_info(dc_candidates)
        self._dns_lookup()

        if self.state.domain_controllers:
            for dc in self.state.domain_controllers:
                host = self.state.add_host(dc)
                host.is_dc = True
            self.log.ok("domain controller(s): %s", ", ".join(self.state.domain_controllers))
        elif candidates:
            # Guess DCs from Kerberos/LDAP presence
            for ip in dc_candidates:
                host = self.state.add_host(ip)
                host.is_dc = True
                self.state.domain_controllers.append(ip)
            self.log.ok("probable DC(s) (by port): %s", ", ".join(dc_candidates))

        if not self.state.domain:
            self.log.warn("could not determine domain name automatically; "
                          "use -d to specify it")
        else:
            self.log.ok("domain: %s", self.state.domain)

        # SMB signing status for relay-awareness (informational, safe)
        self._smb_signing(candidates)

        return {
            "domain": self.state.domain,
            "domain_controllers": self.state.domain_controllers,
        }

    def _smb_info(self, hosts: list[str]) -> None:
        """Use nxc SMB null session to gather domain + hostname info."""
        if not hosts:
            return
        # Scan a bounded set of candidates for speed
        sample = hosts[:5]
        res = self.runner.run(
            [self.nxc_bin(), "smb", *sample, "--no-bruteforce", "-u", "", "-p", ""],
            timeout=300,
        )
        for line in res.out_lines:
            # e.g. "SMB  10.10.10.1  445  DC01  [*] Windows ... (name:DC01) (domain:CORP.LOCAL)"
            if "domain:" in line.lower():
                domain = line.split("domain:")[-1].split(")")[0].strip()
                if domain and not self.state.domain:
                    self.state.domain = domain
            if "(name:" in line.lower():
                name = line.split("(name:")[-1].split(")")[0].strip()
                ip = line.split()[1] if len(line.split()) > 1 else None
                if ip and name:
                    host = self.state.add_host(ip)
                    host.hostname = name

    def _dns_lookup(self) -> None:
        """If we have a domain, resolve DCs via DNS SRV records."""
        domain = self.state.domain
        if not domain:
            return
        res = self.runner.run(
            ["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}"],
            timeout=60,
        )
        for line in res.out_lines:
            # lines contain the target FQDN, e.g. "svc hostname = dc01.corp.local."
            if "svc hostname" in line.lower():
                fqdn = line.split("=")[-1].strip().rstrip(".")
                if fqdn and fqdn not in self.state.domain_controllers:
                    self.state.domain_controllers.append(fqdn)

    def _smb_signing(self, hosts: list[str]) -> None:
        """Detect SMB signing (hosts where signing is disabled are relayable)."""
        if not hosts:
            return
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            tmp = fh.name
        res = self.runner.run(
            [self.nxc_bin(), "smb", *hosts[:10], "--gen-relay-list", tmp],
            timeout=300,
        )
        try:
            with open(tmp, encoding="utf-8") as fh:
                relayable = [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            relayable = []
        for ip in relayable:
            if _is_ip(ip) or ip:
                host = self.state.add_host(ip)
                host.smb_signing = False
        if relayable:
            self.log_finding(
                "medium", "SMB signing disabled",
                f"{len(relayable)} host(s) do not require SMB signing "
                "(NTLM relay surface)",
                technique="SMB Signing")
        # Mark the rest as signed (rough heuristic)
        for ip in hosts:
            if ip not in relayable:
                host = self.state.get_host(ip)
                if host:
                    host.smb_signing = True


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
