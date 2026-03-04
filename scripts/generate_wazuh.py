"""
Phase 3: Generate Wazuh detection artifacts from scored IOCs.

Outputs:
- output/wazuh_iocs_domains.cdb
- output/wazuh_iocs_ips.cdb
- output/wazuh_rules_iocs.xml

We only include P1/P2 to avoid blasting the SOC with noise.
"""
from scripts.utils import logger, read_json, write_json
from collections import defaultdict

INPUT = "output/scored_iocs.json"

OUT_DOMAINS = "output/wazuh_iocs_domains.cdb"
OUT_IPS = "output/wazuh_iocs_ips.cdb"
OUT_RULES = "output/wazuh_rules_iocs.xml"

PRIORITIES_TO_INCLUDE = {"P1", "P2"}

def to_cdb_lines(items):
    """
    Wazuh CDB list format:
      key:value
    We'll store a small value for context: priority|score
    """
    lines = []
    for key, meta in items.items():
        lines.append(f"{key}:{meta}")
    return sorted(lines)

def main():
    data = read_json(INPUT)
    logger.info(f"Loaded {len(data)} IOCs from {INPUT}")

    domains = {}
    ips = {}

    kept = 0
    for x in data:
        score = x.get("score", {})
        pr = score.get("priority")
        if pr not in PRIORITIES_TO_INCLUDE:
            continue

        ioc_type = x.get("ioc_type")
        val = x.get("ioc_value")
        risk = score.get("risk_score")

        meta = f"{pr}|{risk}"
        if ioc_type == "domain":
            domains[val] = meta
            kept += 1
        elif ioc_type == "ip":
            ips[val] = meta
            kept += 1

    logger.info(f"Kept {kept} IOC entries for Wazuh (P1/P2 only). Domains={len(domains)}, IPs={len(ips)}")

    # Write CDB lists
    with open(OUT_DOMAINS, "w", encoding="utf-8") as f:
        f.write("\n".join(to_cdb_lines(domains)) + ("\n" if domains else ""))
    with open(OUT_IPS, "w", encoding="utf-8") as f:
        f.write("\n".join(to_cdb_lines(ips)) + ("\n" if ips else ""))

    # Minimal Wazuh rules referencing lists (conceptual starter)
    # NOTE: exact list lookup integration depends on your Wazuh version and deployment model.
    # We provide a clean baseline; you will adapt to your environment during Wazuh lab phase.
    rules = f"""<group name="cti,ioc,">
  <!-- IOC Domain match (requires logs containing a domain field/string) -->
  <rule id="100100" level="12">
    <decoded_as>json</decoded_as>
    <description>CTI IOC (Domain) matched against curated list (P1/P2)</description>
    <group>cti,ioc,domain,</group>
  </rule>

  <!-- IOC IP match (requires logs containing an IP field/string) -->
  <rule id="100101" level="12">
    <decoded_as>json</decoded_as>
    <description>CTI IOC (IP) matched against curated list (P1/P2)</description>
    <group>cti,ioc,ip,</group>
  </rule>
</group>
"""
    # We write the baseline XML; in the Wazuh lab phase we'll wire exact match conditions.
    with open(OUT_RULES, "w", encoding="utf-8") as f:
        f.write(rules)

    logger.info(f"Wrote: {OUT_DOMAINS}, {OUT_IPS}, {OUT_RULES}")

if __name__ == "__main__":
    main()
