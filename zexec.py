#!/usr/bin/env python3
"""Zexec — automated internal-network / Active Directory penetration tool.

Usage:
    sudo python3 zexec.py -t 10.10.10.0/24
    sudo python3 zexec.py -t 10.10.10.5 -u user -p 'Passw0rd!' -d corp.local
    sudo python3 zexec.py -t targets.txt --aggressive

Safety: by default Zexec performs NON-DESTRUCTIVE misconfiguration and
feature abuse only. It never runs exploits that can crash or lock systems.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a plain script: add the project root to sys.path.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import load_config
from core.engine import Engine

# ANSI colour codes (safe in WSL / Windows Terminal)
_C = {
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "dim": "\033[90m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

# "Zexec" rendered with figlet -f big
_BANNER_ART = r"""
 ______
|___  /
   / / _____  _____  ___
  / / / _ \ \/ / _ \/ __|
 / /_|  __/>  <  __/ (__
/_____\___/_/\_\___|\___|
"""

_BANNER_TAGLINE = "Automated Internal Network & Active Directory Pentest Tool"

_BANNER_SOCIALS = [
    ("LinkedIn", "linkedin.com/in/ukocmen"),
    ("Medium", "medium.com/@ugurkocmen"),
    ("Github", "github.com/ugurkocmen"),
]


def print_banner() -> None:
    """Print the Zexec banner (name, tagline and social links)."""
    print(_C["cyan"] + _BANNER_ART + _C["reset"])
    print("   " + _C["bold"] + _BANNER_TAGLINE + _C["reset"])
    print()
    for label, url in _BANNER_SOCIALS:
        print(f"   {_C['dim']}{label:<10}{_C['reset']} : "
              f"{_C['green']}{url}{_C['reset']}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zexec",
        description="Automated internal-network & Active Directory pentest tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    p.add_argument("-t", "--target", required=True,
                   help="target: CIDR (10.0.0.0/24), single IP, hostname, or a file of targets")
    p.add_argument("-u", "--username", help="domain username")
    p.add_argument("-p", "--password", help="password for the username")
    p.add_argument("-H", "--hash", help="NTLM hash (LM:NT or NT) for the username")
    p.add_argument("-d", "--domain", help="Active Directory domain (FQDN or NETBIOS)")
    p.add_argument("--aggressive", action="store_true",
                   help="enable riskier techniques (relay, large spray lists, "
                        "LSASS dump, template modification)")
    p.add_argument("--crack", metavar="TOOL", choices=["hashcat", "john", "auto"],
                   help="enable hash cracking with the given tool: "
                        "hashcat | john | auto (default wordlist: Kali rockyou.txt)")
    p.add_argument("--crack-wordlist", metavar="FILE",
                   help="custom wordlist for --crack (overrides the default)")
    p.add_argument("--stealth", action="store_true",
                   help="quieter scans + jitter to avoid firewall/IDS detection")
    p.add_argument("--listener", help="attacker IP for NTLM relay (default: auto-detect)")
    p.add_argument("-o", "--output", default="./zexec_output",
                   help="output directory (default: ./zexec_output)")
    p.add_argument("--threads", type=int, default=30, help="concurrency (default 30)")
    p.add_argument("--config", help="path to alternate config.yaml")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p


EXAMPLES = """\
examples:
  # Scan a CIDR range (auto host discovery)
  python3 zexec.py -t 10.10.10.0/24

  # Scan a single IP
  python3 zexec.py -t 10.10.10.5

  # With credentials
  python3 zexec.py -t 10.10.10.0/24 -u user -p 'Passw0rd!' -d corp.local

  # With an NTLM hash
  python3 zexec.py -t 10.10.10.0/24 -u user -H 1a2b3c4d... -d corp.local

    # Aggressive mode (relay, LSASS dump, template modification)
  python3 zexec.py -t 10.10.10.0/24 --aggressive

  # Hash cracking with hashcat (default wordlist: Kali rockyou.txt)
  python3 zexec.py -t 10.10.10.0/24 --crack hashcat

  # Hash cracking with john + a custom wordlist
  python3 zexec.py -t 10.10.10.0/24 --crack john --crack-wordlist /path/list.txt

  # NTLM relay with an explicit listener IP
  python3 zexec.py -t 10.10.10.0/24 --aggressive --listener 10.10.10.99

  # Stealth mode (quieter scans + jitter to evade firewalls/IDS)
  python3 zexec.py -t 10.10.10.0/24 --stealth

note: run as root (or with sudo) for SYN scans and raw sockets.
"""


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:]) if argv is None else list(argv)

    # Always show the banner, then help/usage when no arguments are given.
    print_banner()

    if not args_list:
        build_parser().print_help()
        return 0

    args = build_parser().parse_args(args_list)

    overrides = {
        "general.output_dir": args.output,
        "general.threads": args.threads,
        "general.aggressive": args.aggressive,
        "general.verbose": args.verbose,
        "general.listener_ip": args.listener,
    }

    if args.crack:
        overrides["credential_handling.crack_hashes"] = True
        overrides["credential_handling.cracker"] = args.crack
    if args.crack_wordlist:
        if not Path(args.crack_wordlist).exists():
            print(f"[!] warning: wordlist not found: {args.crack_wordlist}",
                  file=sys.stderr)
        overrides["credential_handling.wordlists"] = [args.crack_wordlist]

    if args.stealth:
        overrides["general.stealth"] = True
        overrides["evasion.nmap_timing"] = 1
        overrides["evasion.nmap_min_rate"] = 300
        overrides["evasion.fragment_packets"] = True
        overrides["evasion.scan_delay"] = "300ms"
        overrides["evasion.auth_jitter"] = 3.0

    try:
        config = load_config(args.config, overrides=overrides)
    except Exception as exc:
        print(f"[!] failed to load config: {exc}", file=sys.stderr)
        return 2

    engine = Engine(config)

    try:
        engine.run(
            target=args.target,
            username=args.username,
            password=args.password,
            nthash=args.hash,
            domain=args.domain,
        )
    except KeyboardInterrupt:
        engine.log.error("interrupted by user")
        # Save whatever we gathered before exiting
        try:
            engine.state.save(Path(args.output))
        except Exception:
            pass
        return 130
    except Exception as exc:
        engine.log.error("fatal: %s", exc, exc_info=args.verbose)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
