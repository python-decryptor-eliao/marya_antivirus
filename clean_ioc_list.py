import json
import re

INPUT_FILE = "ioc_list.json"
OUTPUT_FILE = "clean_ioc_list.json"

IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s\"]+"

try:
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_data = json.load(f) 

    cleaned_iocs = []

    for entry in raw_data:
        if isinstance(entry, dict) and "ioc_value" in entry:
            ioc_value = entry["ioc_value"].strip()

            if ioc_value in ["{", "}", "]:", "[", "]", "null", ""]:
                continue

            url_match = re.search(URL_REGEX, ioc_value)
            ip_match = re.search(IP_REGEX, ioc_value)
            domain_match = re.search(DOMAIN_REGEX, ioc_value)

            if url_match:
                cleaned_iocs.append({"ioc_value": url_match.group(), "type": "url", "source": entry.get("source", "Unknown")})
            elif ip_match:
                cleaned_iocs.append({"ioc_value": ip_match.group(), "type": "ip", "source": entry.get("source", "Unknown")})
            elif domain_match:
                cleaned_iocs.append({"ioc_value": domain_match.group(), "type": "domain", "source": entry.get("source", "Unknown")})

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned_iocs, f, indent=4)

    print(f"✅ {len(cleaned_iocs)} valides IOCs saved '{OUTPUT_FILE}'.")

except json.JSONDecodeError as e:
    print(f"❌ Error JSON : {e}")
except Exception as e:
    print(f"❌ Erreor : {e}")
