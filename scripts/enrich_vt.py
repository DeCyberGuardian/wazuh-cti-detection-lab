"""
Phase 2: VirusTotal Enrichment (Rate-limited + Cached)

We enrich only:
- domain
- ip
- hash

Why not url yet?
- URL endpoints can burn quota quickly; we can add later if needed.

Outputs:
- Adds a "vt" field per IOC when enrichment succeeds
- Stores compact evidence, not full VT payload
- Caches results to avoid repeated API calls
"""
import time
import requests
from scripts.utils import logger, env, read_json, write_json

VT_API_KEY = env("VT_API_KEY")
BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

CACHE_PATH = "output/vt_cache.json"

def load_cache():
    try:
        return read_json(CACHE_PATH)
    except Exception:
        return {}

def save_cache(cache):
    write_json(CACHE_PATH, cache)

def vt_get(path, timeout=30):
    url = f"{BASE}{path}"
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    logger.info(f"VT GET {path} -> {r.status_code}")

    if r.status_code == 429:
        raise RuntimeError("VT rate limit hit (429). Increase sleep_seconds or reduce max_items.")

    # 404 can happen if VT has never seen the indicator; that’s not an error for us.
    if r.status_code == 404:
        return {"_not_found": True}

    r.raise_for_status()
    return r.json()

def enrich_domain(domain):
    return vt_get(f"/domains/{domain}")

def enrich_ip(ip):
    return vt_get(f"/ip_addresses/{ip}")

def enrich_hash(h):
    return vt_get(f"/files/{h}")

def extract_vt_summary(vt_json):
    """
    Compact evidence object:
    - last_analysis_stats (malicious/suspicious/harmless/undetected)
    - reputation (if present)
    - last_analysis_date (epoch)
    """
    if vt_json.get("_not_found"):
        return {"found": False}

    data = vt_json.get("data", {})
    attrs = data.get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    rep = attrs.get("reputation", None)
    last = attrs.get("last_analysis_date", None)

    return {
        "found": True,
        "reputation": rep,
        "last_analysis_stats": stats,
        "last_analysis_date": last,
    }

def enrich_iocs(iocs, sleep_seconds=16, max_items=25):
    """
    sleep_seconds: controls VT request pace to avoid rate limits.
    max_items: safety cap for early runs.
    """
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY not set in .env")

    cache = load_cache()
    out = []
    processed = 0

    for ioc in iocs:
        ioc_value = ioc["ioc_value"]
        ioc_type = ioc["ioc_type"]

        # Only enrich these types in Phase 2
        if ioc_type not in {"domain", "ip", "hash"}:
            out.append(ioc)
            continue

        cache_key = f"{ioc_type}:{ioc_value}"

        if cache_key in cache:
            ioc["vt"] = cache[cache_key]
            out.append(ioc)
            continue

        if processed >= max_items:
            out.append(ioc)
            continue

        try:
            if ioc_type == "domain":
                vt_json = enrich_domain(ioc_value)
            elif ioc_type == "ip":
                vt_json = enrich_ip(ioc_value)
            else:
                vt_json = enrich_hash(ioc_value)

            evidence = extract_vt_summary(vt_json)
            cache[cache_key] = evidence
            ioc["vt"] = evidence
            out.append(ioc)

            processed += 1
            save_cache(cache)

            # Respect rate limits
            time.sleep(sleep_seconds)

        except Exception as e:
            logger.warning(f"VT enrich failed for {cache_key}: {e}")
            out.append(ioc)

    logger.info(f"VT enrichment processed {processed} new IOCs (cached results may add more).")
    return out
