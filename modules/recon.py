"""Reconnaissance: port scanning and service identification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseModule

# Ports relevant to Active Directory / Windows / common internal services.
AD_PORTS = (
    "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,"
    "993,995,1433,1521,2049,3000,3128,3268,3269,3306,3389,5432,5900,"
    "5985,5986,8000,8080,8081,8443,8888,9200,47001"
)


class ReconModule(BaseModule):
    name = "port_scan"
    description = "Discover open ports and identify services on live hosts"

    def run(self, hosts: list[str]) -> dict:
        if not hosts:
            self.log.warn("no hosts to scan")
            return {"scanned": 0}

        self.log.info("scanning %d host(s) on common AD/Windows ports", len(hosts))
        open_ports = self._fast_port_scan(hosts)

        # Detailed service scan on hosts that have at least one interesting port
        live = [h for h, ports in open_ports.items() if ports]
        if live:
            self.log.info("service/version scan on %d host(s)", len(live))
            self._service_scan(live, open_ports)

        # Record results into state
        for ip, ports in open_ports.items():
            host = self.state.add_host(ip)
            for port in ports:
                self.state.set_host_port(ip, port, "")

        self.log.ok("port scan complete: %d host(s) with open ports", len(live))
        return {"scanned": len(hosts), "with_open_ports": len(live)}

    def _fast_port_scan(self, hosts: list[str]) -> dict[str, list[int]]:
        """Quick SYN scan returning host -> open port list."""
        import tempfile
        results: dict[str, list[int]] = {}
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(hosts))
            tmp = fh.name

        res = self.runner.run(
            ["nmap", "-Pn", "-sS", "-n", *self.scan_flags(),
             "-p", AD_PORTS, "-iL", tmp, "-oG", "-"],
            timeout=900,
        )
        import os
        try:
            os.unlink(tmp)
        except OSError:
            pass
        for line in res.out_lines:
            # Greppable format: "Host: 1.2.3.4 (x) Ports: 88/open/tcp//...//"
            if line.startswith("Host:") and "Ports:" in line:
                ip = line.split()[1]
                ports = []
                ports_part = line.split("Ports: ", 1)[1]
                for entry in ports_part.split(","):
                    fields = entry.split("/")
                    if len(fields) >= 2 and fields[1] == "open":
                        try:
                            ports.append(int(fields[0]))
                        except ValueError:
                            continue
                if ports:
                    results[ip] = ports
        return results

    def _service_scan(self, live: list[str], open_ports: dict[str, list[int]]) -> None:
        """Run -sV -sC against open ports of each host, in parallel."""
        import tempfile
        outdir = tempfile.mkdtemp(prefix="zexec_svc_")

        def scan_one(ip: str) -> tuple[str, str, int]:
            ports = ",".join(str(p) for p in open_ports[ip])
            res = self.runner.run(
                ["nmap", "-Pn", "-sV", "-sC", "-n", "-p", ports,
                 ip, "-oN", f"{outdir}/svc_{ip.replace('.', '_')}.nmap"],
                timeout=600,
            )
            return ip, res.stdout, res.returncode

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(scan_one, ip) for ip in live]
            for fut in as_completed(futures):
                ip, out, code = fut.result()
                os_guess = ""
                for line in out.splitlines():
                    if "OS details:" in line:
                        os_guess = line.split("OS details:", 1)[1].strip()
                        break
                host = self.state.add_host(ip)
                if os_guess:
                    host.os = os_guess
