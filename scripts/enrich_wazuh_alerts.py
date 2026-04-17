import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Iterator, Optional

from dotenv import load_dotenv
from ai_enrichment import enrich_alert

load_dotenv()

ALERTS_FILE = os.getenv("WAZUH_ALERTS_FILE", "./sample_data/alerts.json")
OUTPUT_FILE = os.getenv("AI_ENRICHMENT_OUTPUT", "output/enriched_dns_alerts.jsonl")
MODE = os.getenv("ENRICHMENT_MODE", "oneshot").strip().lower()
TARGET_RULE_IDS = {"100200", "100205", "100206", "100207"}


def ensure_output_dir(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def should_enrich(alert: Dict[str, Any]) -> bool:
    rule_id = str(alert.get("rule", {}).get("id", ""))
    return rule_id in TARGET_RULE_IDS


def append_jsonl(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def read_json_file_once(path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Alerts file not found: {path}\n"
            "For local Mac testing, set WAZUH_ALERTS_FILE=./sample_data/alerts.json"
        )

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()

    if not content:
        return

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        for line in content.splitlines():
            alert = parse_line(line)
            if alert:
                yield alert
        return

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
    elif isinstance(data, dict):
        yield data


def follow_file(path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Alerts file not found: {path}\n"
            "For live mode on Wazuh, set WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json"
        )

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            alert = parse_line(line)
            if alert:
                yield alert


def build_result(alert: Dict[str, Any], enrichment: Dict[str, Any]) -> Dict[str, Any]:
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {}) or {}

    return {
        "timestamp": alert.get("timestamp"),
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
        "agent": alert.get("agent", {}).get("name"),
        "domain": eventdata.get("queryName") or eventdata.get("QueryName"),
        "process": eventdata.get("image") or eventdata.get("Image"),
        "provider_status": enrichment.get("provider_status"),
        "fallback_reason": enrichment.get("fallback_reason"),
        "enrichment": enrichment,
    }


def main() -> None:
    ensure_output_dir(OUTPUT_FILE)

    print(f"[+] Mode: {MODE}")
    print(f"[+] Reading: {ALERTS_FILE}")
    print(f"[+] Writing enrichments to: {OUTPUT_FILE}")

    if MODE == "live":
        source = follow_file(ALERTS_FILE)
    else:
        source = read_json_file_once(ALERTS_FILE)

    processed = 0
    matched = 0

    try:
        for alert in source:
            processed += 1

            if not should_enrich(alert):
                continue

            matched += 1

            try:
                enrichment = enrich_alert(alert)
                result = build_result(alert, enrichment)
                append_jsonl(OUTPUT_FILE, result)

                domain = result.get("domain") or "unknown"
                status = result.get("provider_status") or "unknown"
                print(f"[AI] Enriched domain: {domain} ({status})")

            except Exception as e:
                error_result = {
                    "timestamp": alert.get("timestamp"),
                    "rule_id": alert.get("rule", {}).get("id"),
                    "error": str(e),
                    "provider_status": "failed",
                }
                append_jsonl(OUTPUT_FILE, error_result)
                print(f"[!] Enrichment failed: {e}")

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

    print(f"[+] Processed alerts: {processed}")
    print(f"[+] Matched target alerts: {matched}")


if __name__ == "__main__":
    main()