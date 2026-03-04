#!/bin/bash

# Sync CTI lists and rules to Wazuh server

WAZUH_SERVER="172.20.10.2"
WAZUH_USER="wazuh-user"

echo "[+] Building CTI key list"
python3 scripts/build_lists.py

echo "[+] Syncing lists"

scp lists/cti_domains ${WAZUH_USER}@${WAZUH_SERVER}:/tmp/
scp lists/cti_domains_keys ${WAZUH_USER}@${WAZUH_SERVER}:/tmp/

echo "[+] Syncing rules"

scp rules/local_rules.xml ${WAZUH_USER}@${WAZUH_SERVER}:/tmp/

echo "[+] Applying changes on Wazuh server"

ssh ${WAZUH_USER}@${WAZUH_SERVER} "

sudo mv /tmp/cti_domains /var/ossec/etc/lists/
sudo mv /tmp/cti_domains_keys /var/ossec/etc/lists/

sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/

sudo chown wazuh:wazuh /var/ossec/etc/lists/cti_domains*
sudo chmod 640 /var/ossec/etc/lists/cti_domains*

sudo /var/ossec/bin/wazuh-analysisd -t

sudo systemctl restart wazuh-manager

echo 'Wazuh updated successfully'
"