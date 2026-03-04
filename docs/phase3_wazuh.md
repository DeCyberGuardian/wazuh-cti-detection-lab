# Phase 3 — Wazuh Detection Artifacts (IOC-driven)

## Objective
Convert scored threat intelligence into Wazuh-ready detection artifacts.

## Inputs
- `output/scored_iocs.json` (IOCs + VT evidence + scoring)

## Selection Policy
Only IOCs with priority:
- P1 (high)
- P2 (medium)

This reduces alert noise and keeps detection actionable.

## Outputs
- `output/wazuh_iocs_domains.cdb` — curated domain IOCs
- `output/wazuh_iocs_ips.cdb` — curated IP IOCs
- `output/wazuh_rules_iocs.xml` — baseline Wazuh rules (to be wired to log sources in Wazuh lab phase)

## Next (Wazuh Lab Integration)
- Deploy Wazuh manager + agents (Windows + Linux)
- Validate which log fields contain domains/IPs
- Add/adjust Wazuh rules to match those fields and trigger alerts
- Create a triage mini-playbook for each alert type
