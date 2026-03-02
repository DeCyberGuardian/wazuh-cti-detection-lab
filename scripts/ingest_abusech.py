"""
Abuse.ch - URLhaus ingestion (PUBLIC plaintext feed)

Why:
- The /v1/urls/recent/ endpoint is returning 401 for you.
- This plaintext feed is public and stable for pulling URL IOCs.

Source:
https://urlhaus.abuse.ch/downloads/text/
"""
import requests
from scripts.schema import IOCModel
from scripts.utils import logger

URL = "https://urlhaus.abuse.ch/downloads/text/"

def fetch_abusech(limit=100):
    logger.info("Fetching Abuse.ch (URLhaus) plaintext URL list")
    try:
        r = requests.get(URL, timeout=30)
        r.raise_for_status()
        lines = r.text.splitlines()
    except Exception as e:
        logger.error(f"URLhaus plaintext fetch failed: {e}")
        return []

    out = []
    count = 0

    for line in lines:
        line = line.strip()

        # Skip comments and blanks
        if not line or line.startswith("#"):
            continue

        # Each non-comment line is a URL IOC
        try:
            model = IOCModel(
                ioc_value=line,
                ioc_type="url",
                source="abuse.ch_urlhaus_text",
                first_seen=None,          # plaintext list doesn't provide first-seen per URL
                confidence="high",        # URLhaus feed is curated; we treat it as high-confidence source
                raw_source={"feed": "urlhaus_text"}
            )
            out.append(model.as_dict())
            count += 1
            if count >= limit:
                break
        except Exception as e:
            logger.warning(f"Validation failed for URLhaus line: {e}")

    logger.info(f"URLhaus plaintext returned {len(out)} normalized IOCs")
    return out

if __name__ == "__main__":
    print(fetch_abusech(10))
