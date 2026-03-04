# Lab Setup (Current State)

## Components
- Wazuh 4.12 OVA (VMware Fusion on macOS)
- Windows 11 endpoint with Sysmon installed
- Wazuh agent installed on Windows and connected (active)

## Data Flow Verified
Windows Sysmon → Wazuh agent → Wazuh manager → archives.json

Sysmon DNS telemetry:
- Sysmon Event ID 22 (DNS query) observed and decoded.
- Field used for domain matching:
  - `data.win.eventdata.queryName`

## Wazuh Paths
- Rules: `/var/ossec/etc/rules/local_rules.xml`
- Lists: `/var/ossec/etc/lists/`
- Alerts: `/var/ossec/logs/alerts/alerts.json`
- Archives: `/var/ossec/logs/archives/archives.json`

## Notes
- Lists are loaded via `<ruleset>` in `/var/ossec/etc/ossec.conf`
- CDB-backed lists are required for `<list ... lookup="match_key">`