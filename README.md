# CTI Detection Pipeline — Wazuh + Sysmon + Intelligence-Driven Detection

## Overview

This project demonstrates a Cyber Threat Intelligence (CTI)-driven detection pipeline using:

- Wazuh (SIEM)
- Sysmon (endpoint telemetry)
- Custom detection rules
- AI-assisted enrichment (with resilient fallback)

The objective is to show how intelligence can directly drive:

- Detection engineering
- SIEM rule development
- SOC alert workflows
- Threat-informed defense

---

## Architecture

Threat Intelligence Sources  
↓  
IOC Ingestion & Normalization  
↓  
CTI Processing (Deduplication, Scoring)  
↓  
Detection Engineering (Wazuh Rules)  
↓  
Sysmon Endpoint Telemetry  
↓  
Wazuh Alerts  
↓  
AI Enrichment (Cloud + Fallback)

---

## Phase 1 — IOC Ingestion

### Sources
- Abuse.ch (URLhaus / MalwareBazaar)
- AlienVault OTX

### Output


Phase 2 — Detection Engineering (Wazuh + Sysmon)
Lab Stack
Wazuh 4.x
Sysmon (Event ID 22 for DNS)
Custom rules
VMware lab

Detection Use Cases
1. IOC-Based DNS Detection
Rule: 100200-dns-ioc.xml
Detects DNS queries matching CTI domains
MITRE: T1071.004

2. Marker Domain Detection (Validation)
Rule: 100205-dns-marker.xml
Used for deterministic testing

3. DNS Beaconing Detection
Rule: 100206-dns-beaconing.xml
Detects repeated DNS patterns (C2 behavior)

4. DGA Detection
Rule: 100207-dns-tga.xml
Detects algorithmically generated domains
MITRE: T1568.002

## Wazuh Integration
    sudo cp wazuh/rules/*.xml /var/ossec/etc/rules/
    sudo cp wazuh/lists/* /var/ossec/etc/lists/

    sudo /var/ossec/bin/wazuh-analysisd -t
    sudo systemctl restart wazuh-manager

# Testing
Simulate DNS:

    ping afriwealth-lab-test-7777.com

Check alerts:

    grep '"id":"100200"' /var/ossec/logs/alerts/alerts.json

## Phase 3 — AI Enrichment
Purpose
Enhance alerts with:

- Contextual assessment
- Confidence scoring
- Analyst actions


## Enrichment Modes
1. Oneshot (Local Testing)

    export ENRICHMENT_MODE=oneshot
    export WAZUH_ALERTS_FILE=./sample_data/alerts.json

    python scripts/enrich_wazuh_alerts.py

2. Live Mode (Wazuh Manager)
    export ENRICHMENT_MODE=live
    export WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json

    python3 scripts/enrich_wazuh_alerts.py

## Fallback Behavior (Critical Design)
If OpenAI is unavailable (e.g. quota exceeded):

- The pipeline does NOT fail
- Enrichment continues using local logic
- Output includes:

    "provider_status": "fallback",
    "fallback_reason": "insufficient_quota"

## Output Format

Each enriched alert is written to:

    output/enriched_dns_alerts.jsonl

Example:

{
  "timestamp": "...",
  "rule_id": "100200",
  "domain": "example.com",
  "provider_status": "fallback",
  "enrichment": {
    "assessment": "...",
    "confidence": "low"
  }
}

# Workflow
Development Flow

Mac (VS Code)
→ Test locally (oneshot)
→ Push to GitHub
→ Pull on Wazuh manager
→ Run live mode

## Key Lessons
- Detection requires correct telemetry + rule alignment
- Sysmon Event ID 22 must map to:

    sysmon_event_22

- Wazuh rule duplication causes silent failures
- CTI normalization improves detection reliability
- AI must enhance, not break, the pipeline

## Project Outcome

This project demonstrates a CTI-first approach:

Intelligence drives detection — not tools alone.

## Author

DeCyberGuardian👨🏾‍💻
Cyber Threat Intelligence & Detection Engineering