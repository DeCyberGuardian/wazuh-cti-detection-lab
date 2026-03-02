"""
AlienVault OTX ingestion with endpoint fallback.

Why:
- Your /api/v1/pulses endpoint returned 404.
- OTX endpoints can differ (pulses, pulses/subscribed, pulses/user, etc.).
- We implement a robust fallback chain and normalize indicators if present.

Strategy:
1) Try a list of candidate pulse endpoints.
2) When one works, extract indicators if included.
3) If pulse listing doesn't include indicators, we fetch pulse details (optional step).
"""

import requests
from scripts.schema import IOCModel, iso_date_safe
from scripts.utils import logger, env

BASE = "https://otx.alienvault.com/api/v1"
OTX_API_KEY = env("OTX_API_KEY")

HEADERS = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}

# Candidate endpoints to try (OTX API can vary by account/state)

def map_otx_type(raw_type: str) -> str:
    """Map OTX indicator types into our canonical schema: ip/domain/url/hash."""
    if not raw_type:
        return "unknown"
    t = raw_type.strip().lower()

    # IPs
    if t in {"ipv4", "ipv6", "ip"}:
        return "ip"

    # Domains/hostnames
    if t in {"domain", "hostname", "fqdn"}:
        return "domain"

    # URLs
    if t in {"url", "uri"}:
        return "url"

    # Hashes
    if "sha256" in t or "sha-256" in t:
        return "hash"
    if "sha1" in t or "sha-1" in t:
        return "hash"
    if t == "md5":
        return "hash"
    if "filehash" in t or "hash" == t:
        return "hash"

    return t

CANDIDATE_PULSE_ENDPOINTS = [
    f"{BASE}/pulses/subscribed",   # commonly available
    f"{BASE}/pulses/mine",         # sometimes available
    f"{BASE}/pulses/user",         # sometimes available
    f"{BASE}/pulses",              # your original
]

def _get_json(url, params=None, timeout=30):
    r = requests.get(url, headers=HEADERS, params=params or {}, timeout=timeout)
    logger.info(f"OTX GET {url} -> {r.status_code}")
    r.raise_for_status()
    return r.json()

def _confidence_from_pulse(pulse_obj):
    """
    Basic confidence scoring using pulse metadata when available.
    - If pulse has high subscriber_count or votes, confidence increases.
    This is a heuristic; we refine later.
    """
    subs = pulse_obj.get("subscriber_count") or 0
    votes = pulse_obj.get("votes_count") or 0
    if subs >= 50 or votes >= 20:
        return "high"
    if subs >= 10 or votes >= 5:
        return "medium"
    return "low"

def fetch_otx_pulses(limit=20):
    """
    Returns a list of normalized IOC dicts extracted from OTX pulses.
    If listing endpoint doesn't provide indicators, returns empty (we'll upgrade later).
    """
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set; skipping OTX ingestion")
        return []

    data = None
    used_endpoint = None

    # Try endpoints until one works
    for ep in CANDIDATE_PULSE_ENDPOINTS:
        try:
            data = _get_json(ep, params={"limit": limit})
            used_endpoint = ep
            break
        except requests.HTTPError as e:
            # If 404/403 etc, try next endpoint
            continue
        except Exception as e:
            logger.error(f"OTX unexpected error on {ep}: {e}")
            continue

    if not data:
        logger.error("All OTX pulse endpoints failed. OTX ingestion skipped.")
        return []

    # Different endpoints may return different top-level keys
    pulses = data.get("results") or data.get("pulses") or data.get("data") or []
    logger.info(f"OTX: using {used_endpoint}, pulses found: {len(pulses)}")

    results = []
    for p in pulses:
        pulse_name = p.get("name") or p.get("title") or "otx_pulse"
        created = iso_date_safe(p.get("created") or p.get("modified") or p.get("date_created"))
        conf = _confidence_from_pulse(p)

        # Many pulse list endpoints don't include indicators; they may include indicator_count only.
        indicators = p.get("indicators") or []

        # If no indicators present, skip for now (we'll add pulse-detail fetching next if needed)
        if not indicators:
            continue

        for ind in indicators:
            try:
                ioc = ind.get("indicator") or ind.get("address") or ind.get("value")
                itype = map_otx_type(ind.get("type") or "unknown")
                if not ioc:
                    continue

                model = IOCModel(
                    ioc_value=str(ioc),
                    ioc_type=itype,
                    source=f"otx:{pulse_name}",
                    first_seen=created,
                    confidence=conf,
                    raw_source=ind
                )
                results.append(model.as_dict())
            except Exception as e:
                logger.warning(f"Failed to normalize OTX indicator: {e}")

    logger.info(f"OTX normalized indicators: {len(results)}")
    return results

if __name__ == "__main__":
    print(fetch_otx_pulses(5))
