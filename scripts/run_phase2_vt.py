from scripts.utils import logger, read_json, write_json
from scripts.enrich_vt import enrich_iocs

INPUT = "output/normalized_iocs.json"
OUTPUT = "output/enriched_iocs.json"

def main():
    iocs = read_json(INPUT)
    logger.info(f"Loaded {len(iocs)} IOCs from {INPUT}")

    # Start conservative: 25 lookups max, slow pace to avoid 429
    enriched = enrich_iocs(iocs, sleep_seconds=16, max_items=25)

    write_json(OUTPUT, enriched)
    logger.info(f"Wrote enriched output to {OUTPUT}")

if __name__ == "__main__":
    main()
