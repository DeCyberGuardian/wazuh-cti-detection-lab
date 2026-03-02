"""
Orchestrator for Phase 1 ingestion.
Run with:
    python scripts/main.py --mode dry      # uses no API keys, small fetch or mocks
    python scripts/main.py --mode live     # uses real APIs (OTX required)
"""
import argparse
import os
from scripts.utils import logger, write_json, env
from scripts.ingest_abusech import fetch_abusech
from scripts.ingest_otx import fetch_otx_pulses
from scripts.normalize import merge_ioc_lists

OUTPUT = "output/normalized_iocs.json"

def dry_run():
    logger.info("Starting dry-run: fetch small sample from abuse.ch and return")
    abuse = fetch_abusech(limit=5)
    # OTX may be skipped in dry-run if no API key set
    return merge_ioc_lists([abuse])

def live_run():
    logger.info("Starting live run: Abuse.ch + OTX")
    abuse = fetch_abusech(limit=200)
    otx = []
    otx_key = env("OTX_API_KEY")
    if otx_key:
        otx = fetch_otx_pulses(limit=50)
    else:
        logger.warning("OTX API key not set; skipping OTX ingestion")
    merged = merge_ioc_lists([abuse, otx])
    return merged


def summarize(iocs):
    counts = {}
    for x in iocs:
        t = x.get("ioc_type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    # print top types
    from scripts.utils import logger
    logger.info("IOC type distribution: " + ", ".join([f"{k}={v}" for k,v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["dry","live"], default="dry")
    args = parser.parse_args()
    if args.mode == "dry":
        iocs = dry_run()
    else:
        iocs = live_run()
    summarize(iocs)
    write_json(OUTPUT, iocs)
    logger.info(f"Saved {len(iocs)} normalized IOCs to {OUTPUT}")

if __name__ == "__main__":
    main()
