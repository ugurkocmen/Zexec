# Zexec

**Zexec** is an automated internal-network and Active Directory penetration
testing tool. You give it a CIDR range or a single IP; it discovers live hosts,
identifies the AD environment, enumerates it, attacks credentials and
misconfigurations, moves laterally, and attempts to reach **Domain Admin** 
while **never** running exploits that can crash or lock systems.

## Safety model (important)

- **Default = non-destructive.** Zexec only abuses *misconfigurations* and
  *features* (AS-REP/Kerberoasting, delegation, ACL/DACL, AD CS ESC1-16,
  shadow credentials, DCSync, ticket forging). It does **not** run
  destructive CVE exploits.
- **Hard-excluded:** Zerologon (unsafe), EternalBlue, PrintNightmare,
  service DoS, or anything that modifies a DC's password or crashes services.
- **Lockout-aware spraying:** password spraying is throttled, respects the
  discovered lockout policy, and uses only a tiny safe password list.
- **`--aggressive` gate:** NTLM relay, large spray lists, LSASS dump,
  AD CS template/CA modification run only when you pass `--aggressive`.
- **`--crack` gate:** hash cracking is **OFF by default**. It only runs when
  you pass `--crack hashcat` or `--crack john`, even if both tools are
  installed. The default wordlist is Kali's `rockyou.txt`; override it with
  `--crack-wordlist`.
- **No persistence:** authorized corporate pentests never leave backdoors, so
  Zexec intentionally implements **no persistence** techniques (no golden
  tickets, skeleton keys, DSRM backdoors, etc.).
- **`--stealth` mode:** quieter scans (lower timing, packet fragmentation,
  scan delay) plus auth jitter to avoid firewall/IDS detection.

> Use only against systems you are explicitly authorized to test.

## Requirements

Kali Linux (or Debian-based) with the AD toolchain:

```bash
sudo apt update
sudo apt install -y netexec impacket-scripts python3-impacket bloodhound.py \
  smbmap evil-winrm hashcat cifs-utils krb5-user ldap-utils dnsutils \
  enum4linux-ng responder masscan gobuster seclists \
  default-mysql-client odat python3-pip python3-venv figlet
pip3 install pyyaml
```

> Zexec auto-detects tool paths and **degrades gracefully** when a tool is
> missing (skips that technique with a warning). Wordlists fall back to the
> first existing entry, so it runs on any Kali/Linux build  not just WSL.

## Usage

```bash
# CIDR  auto host discovery
sudo python3 zexec.py -t 10.10.10.0/24

# Single IP
sudo python3 zexec.py -t 10.10.10.5

# With credentials
sudo python3 zexec.py -t 10.10.10.0/24 -u user -p 'Passw0rd!' -d corp.local

# With an NTLM hash
sudo python3 zexec.py -t 10.10.10.0/24 -u user -H 1a2b3c... -d corp.local

# Aggressive mode (relay, LSASS dump, template modification)
sudo python3 zexec.py -t 10.10.10.0/24 --aggressive

# Hash cracking with hashcat (default wordlist: Kali rockyou.txt)
sudo python3 zexec.py -t 10.10.10.0/24 --crack hashcat

# Hash cracking with john + a custom wordlist
sudo python3 zexec.py -t 10.10.10.0/24 --crack john --crack-wordlist /path/list.txt

# Stealth mode (avoid firewall/IDS detection)
sudo python3 zexec.py -t 10.10.10.0/24 --stealth
```

## Attack pipeline

1. **Host discovery:** nmap `-sn` sweep of the CIDR.
2. **Port scan:** SYN scan of AD/Windows ports + service detection.
3. **Firewall evasion:** adaptive re-scan of filtered hosts (stealth-aware).
4. **AD identification:** find DCs, domain name, SMB signing status.
5. **AD enumeration:** users/groups/computers, SPNs, AS-REP accounts,
   delegation, trusts, LAPS/gMSA, password policy, AD CS (certipy).
6. **Credential attacks:** AS-REP roast, Kerberoast, safe spray, hash cracking.
7. **Credential sources:** GPP passwords (MS14-025), LAPS, gMSA.
8. **Database attacks:** Oracle, PostgreSQL, MSSQL (xp_cmdshell + linked
   servers), MySQL.
9. **Misconfiguration abuse:** AD CS ESC1 → DCSync, shadow credentials.
10. **ACL pathfinding:** BloodHound collection + exploit GenericAll/WriteDacl/
    ForceChangePassword/AddMember/DCSync over high-value targets.
11. **Delegation abuse:** RBCD (aggressive-gated).
12. **NTLM relay:** coercion + relay to LDAP/AD CS (aggressive-gated).
13. **Lateral movement:** PTH/WinRM/SMB, SAM/LSA dump on owned hosts.
14. **Domain dominance:** DCSync, child→parent trust escalation (SID history).
15. **Reporting:** Markdown + JSON.

Results are written to `./zexec_output/` (`report.md`, `results.json`,
`zexec_*.log`). A **checkpoint** (`results.json`) is saved mid-run so a crash
never loses findings.

## Layout

```
zexec/
├── zexec.py            # CLI entry point
├── config.yaml         # tunables, safety, evasion & database settings
├── core/
│   ├── config.py       # config loading
│   ├── logger.py       # logging
│   ├── runner.py       # safe subprocess execution (+ background processes)
│   ├── state.py        # hosts/creds/findings store
│   ├── target.py       # CIDR/IP parsing + host discovery
│   ├── ldap_ops.py     # LDAP writes (AddMember / ForceChangePassword)
│   └── engine.py       # pipeline orchestration + checkpoints
└── modules/
    ├── base.py         # shared helpers (evasion flags, jitter, tool lookup)
    ├── recon.py        # port scan
    ├── evasion.py      # firewall/IDS evasion + adaptive re-scan
    ├── ad_ident.py     # DC/domain identification
    ├── ad_enum.py      # AD enumeration (parallel)
    ├── cred_attack.py  # roasting/spray/cracking
    ├── cred_more.py    # GPP/LAPS/gMSA secrets
    ├── database.py     # Oracle / PostgreSQL / MSSQL / MySQL
    ├── abuse.py        # ADCS + shadow creds
    ├── pathfind.py     # BloodHound ACL analysis + abuse
    ├── delegation.py   # RBCD (aggressive)
    ├── relay.py        # NTLM relay + coercion (aggressive)
    ├── lateral.py      # lateral movement + cred harvest
    ├── domain_admin.py # DCSync + trust attacks
    └── report.py       # reporting
```
