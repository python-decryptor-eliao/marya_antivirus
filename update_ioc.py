import requests
import json
import re

IOC_SOURCES = {
    "AlienVault": "https://otx.alienvault.com/api/v1/pulses/subscribed",
    "Abuse.ch": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "ThreatFox": "https://threatfox.abuse.ch/export/json/recent/",
}

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

def detect_ioc_type(ioc):
    if IP_REGEX.fullmatch(ioc):
        return "ip"
    elif DOMAIN_REGEX.fullmatch(ioc):
        return "domain"
    elif HASH_REGEX.fullmatch(ioc):
        return "hash"
    else:
        return "unknown"

def download_iocs():
    ioc_list = []

    for source, url in IOC_SOURCES.items():
        try:
            print(f"📥 Downloading IOC's from {source}...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                lines = response.text.split("\n")
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ioc_type = detect_ioc_type(line)
                        ioc_list.append({
                            "ioc_value": line,
                            "type": ioc_type,
                            "source": source
                        })
            else:
                print(f"⚠️ Downloading error to {source} : {response.status_code}")
        except Exception as e:
            print(f"❌ Impossible to get IOC's from {source} : {e}")

    with open("ioc_list.json", "w", encoding="utf-8") as f:
        json.dump(ioc_list, f, indent=4)

    print("✅ IOCs updated in ioc_list.json")

download_iocs()
