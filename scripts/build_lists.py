#!/usr/bin/env python3

"""
build_lists.py

Converts CTI domain intelligence feeds into Wazuh-compatible CDB list format.

Input example:
bad-domain.com:P1|90
evil-domain.net:P2|70

Output (cti_domains_keys):
bad-domain.com:1
evil-domain.net:1
"""

from pathlib import Path

INPUT = Path("lists/cti_domains")
OUTPUT = Path("lists/cti_domains_keys")


def build():
    if not INPUT.exists():
        print("Input list not found:", INPUT)
        return

    domains = []

    for line in INPUT.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        domain = line.split(":")[0]

        domains.append(f"{domain}:1")

        # add trailing-dot variant
        if not domain.endswith("."):
            domains.append(f"{domain}.:1")

    OUTPUT.write_text("\n".join(sorted(set(domains))) + "\n")

    print("Generated:", OUTPUT)
    print("Entries:", len(domains))


if __name__ == "__main__":
    build()