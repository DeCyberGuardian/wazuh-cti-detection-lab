from scripts.utils import logger, read_json, write_json
from scripts.scoring import compute_risk

INPUT = "output/enriched_iocs.json"
OUTPUT = "output/scored_iocs.json"

def main():
    data = read_json(INPUT)
    logger.info(f"Loaded {len(data)} IOCs from {INPUT}")

    out = []
    for ioc in data:
        scored = compute_risk(ioc)
        ioc["score"] = scored
        out.append(ioc)

    write_json(OUTPUT, out)
    logger.info(f"Wrote scored output to {OUTPUT}")

    # quick summary
    p1 = sum(1 for x in out if x.get("score", {}).get("priority") == "P1")
    p2 = sum(1 for x in out if x.get("score", {}).get("priority") == "P2")
    p3 = sum(1 for x in out if x.get("score", {}).get("priority") == "P3")
    logger.info(f"Priority counts: P1={p1}, P2={p2}, P3={p3}")

if __name__ == "__main__":
    main()
