# Phase 1 — IOC Ingestion & Normalization

## Objective
Collect IOCs from multiple threat intelligence sources and convert them into a clean, deduplicated dataset with a consistent schema for downstream enrichment and detection engineering.

## Sources
- Abuse.ch URLhaus plaintext feed (malicious URLs)
- AlienVault OTX subscribed pulses (community threat indicators)

## Normalized Schema
Each IOC record includes:
- ioc_value
- ioc_type (canonical: ip/domain/url/hash)
- source
- first_seen
- confidence
- raw_source (for traceability)

## Deduplication Strategy
Records are deduplicated using the tuple:
(ioc_value, ioc_type)

When duplicates exist:
- Prefer earlier first_seen if available
- Prefer higher confidence using ordering:
unknown < low < medium < high

## Output Artifact
`output/normalized_iocs.json`

## Known Limitations
- Some OTX pulse list endpoints may not include indicators in all contexts. We use the subscribed pulses endpoint and implement fallback logic.
- URLhaus plaintext feed does not provide per-IOC first_seen.


## Phase 1 Results Snapshot (Example)
- URLhaus plaintext ingested: 200 URLs (run-config)
- OTX pulses processed: 50 pulses (subscribed)
- OTX indicators extracted: ~6.9k (varies per run)
- Final unique IOCs after deduplication: ~7.1k (varies per run)

## Notes on Variability
Counts vary slightly across runs because feeds update continuously.
