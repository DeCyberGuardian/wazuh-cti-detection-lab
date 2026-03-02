"""
Normalization & deduplication
Takes lists of normalized IOC dicts from multiple sources and:
- Deduplicates by (ioc_value, ioc_type)
- Merges best metadata (keeps earliest first_seen)
- Returns a deterministic list
"""
from scripts.schema import IOCModel
from scripts.utils import logger
from collections import defaultdict

ALLOWED_TYPES = {'ip','domain','url','hash'}

def merge_ioc_lists(lists):
    logger.info("Merging and deduplicating IOC lists")
    seen = {}  # key -> IOC dict
    for lst in lists:
        for entry in lst:
            key = (entry.get("ioc_value"), entry.get("ioc_type"))
            if key in seen:
                # prefer earliest first_seen if available
                existing = seen[key]
                e_first = existing.get("first_seen")
                n_first = entry.get("first_seen")
                if n_first and (not e_first or n_first < e_first):
                    existing["first_seen"] = n_first
                # widen confidence if new one is higher
                conf_order = {"unknown":0, "low":1, "medium":2, "high":3}
                if conf_order.get(entry.get("confidence","unknown"),0) > conf_order.get(existing.get("confidence","unknown"),0):
                    existing["confidence"] = entry.get("confidence")
                # append raw_source for traceability (keeps small)
                existing_raw = existing.get("raw_source", {})
                new_raw = entry.get("raw_source", {})
                if new_raw:
                    existing["raw_source"] = {"merged": [existing_raw, new_raw]}
                seen[key] = existing
            else:
                seen[key] = entry
    # Validate via pydantic and return clean list
    clean = []
    for k, v in seen.items():
        try:
            model = IOCModel(**v)
            clean.append(model.as_dict())
        except Exception as e:
            logger.warning(f"IOC failed schema validation during merge: {e} - skipping {k}")
    logger.info(f"Merged set contains {len(clean)} unique IOCs")
    # sort for determinism
    
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
    clean = filtered

clean_sorted = sorted(clean, key=lambda x: (x["ioc_type"], x["ioc_value"]))
    return clean_sorted
