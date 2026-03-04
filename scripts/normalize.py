"""
Normalization & deduplication

Takes lists of normalized IOC dicts from multiple sources and:
- Deduplicates by (ioc_value, ioc_type)
- Merges best metadata (keeps earliest first_seen)
- Enforces canonical IOC types for downstream enrichment/detection
- Returns a deterministic (sorted) list
"""
from scripts.schema import IOCModel
from scripts.utils import logger

ALLOWED_TYPES = {"ip", "domain", "url", "hash"}
CONF_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}

def merge_ioc_lists(lists):
    logger.info("Merging and deduplicating IOC lists")

    seen = {}  # (ioc_value, ioc_type) -> IOC dict

    for lst in lists:
        for entry in lst:
            key = (entry.get("ioc_value"), entry.get("ioc_type"))
            if not key[0] or not key[1]:
                # Skip malformed entries early
                continue

            if key in seen:
                existing = seen[key]

                # Prefer earliest first_seen if available
                e_first = existing.get("first_seen")
                n_first = entry.get("first_seen")
                if n_first and (not e_first or str(n_first) < str(e_first)):
                    existing["first_seen"] = n_first

                # Prefer higher confidence
                if CONF_ORDER.get(entry.get("confidence", "unknown"), 0) > CONF_ORDER.get(existing.get("confidence", "unknown"), 0):
                    existing["confidence"] = entry.get("confidence", existing.get("confidence", "unknown"))

                # Preserve traceability: merge raw_source (keep compact)
                existing_raw = existing.get("raw_source", {}) or {}
                new_raw = entry.get("raw_source", {}) or {}
                if new_raw:
                    existing["raw_source"] = {"merged": [existing_raw, new_raw]}

                seen[key] = existing
            else:
                seen[key] = entry

    # Validate via Pydantic and keep only schema-valid entries
    clean = []
    for key, val in seen.items():
        try:
            model = IOCModel(**val)
            clean.append(model.as_dict())
        except Exception as e:
            logger.warning(f"IOC failed schema validation during merge: {e} - skipping {key}")

    logger.info(f"Merged set contains {len(clean)} unique IOCs (pre-filter)")

    # Enforce canonical types for downstream enrichment/detection
    dropped = 0
    filtered = []
    for x in clean:
        if x.get("ioc_type") in ALLOWED_TYPES:
            filtered.append(x)
        else:
            dropped += 1

    if dropped:
        logger.info(f"Dropped {dropped} IOCs due to unsupported types (kept only {sorted(ALLOWED_TYPES)})")

    # Deterministic ordering (stable output)
    clean_sorted = sorted(filtered, key=lambda x: (x["ioc_type"], x["ioc_value"]))

    logger.info(f"Final IOC count after type filtering: {len(clean_sorted)}")
    return clean_sorted
