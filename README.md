# CTI Detection Pipeline

## Goal
Build an Intelligence-driven pipeline that:
1) Ingests threat intelligence IOCs from multiple sources  
2) Normalizes + deduplicates them into a consistent schema  
3) (Later phases) Enriches, maps to MITRE ATT&CK, and generates detection content for SOC tools

## Phase 1 (Current): IOC Ingestion + Normalization
**Deliverable:** `output/normalized_iocs.json`

### Sources
- Abuse.ch (URLhaus/MalwareBazaar feed)
- AlienVault OTX (API)

### Output Schema (Normalized)
Each IOC becomes:
- `ioc_value` (string)
- `ioc_type` (ip/domain/url/hash)
- `source` (string)
- `first_seen` (string / ISO-like when available)
- `confidence` (high/medium/low)
- `raw_source` (object; original record for traceability)

## How to Run (Phase 1)
1) `cp .env.example .env` and add your API keys
2) `source venv/bin/activate`
3) `python scripts/main.py`

