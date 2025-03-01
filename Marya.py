import os
import json
import hashlib
import requests
import yara
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import ttkbootstrap as tb

IOC_FILE = "clean_ioc_list.json"
YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "YARA_RULES_DIR")

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def load_iocs():
    try:
        with open(IOC_FILE, "r", encoding="utf-8") as f:
            iocs = json.load(f)

        iocs_ips = {ioc["ioc_value"] for ioc in iocs if ioc["type"] == "ip"}
        iocs_domains = {ioc["ioc_value"] for ioc in iocs if ioc["type"] == "domain"}
        iocs_urls = {ioc["ioc_value"] for ioc in iocs if ioc["type"] == "url"}

        print(f"✅ {len(iocs_ips)} IPs, {len(iocs_domains)} Domaines, {len(iocs_urls)} URLs chargés.")

        return iocs_ips, iocs_domains, iocs_urls

    except Exception as e:
        print(f"❌ IOCs load error : {e}")
        return set(), set(), set()


IOCs_IP, IOCs_DOMAINS, IOCs_URLS = load_iocs()


def load_yara_rules():
    print(f"📁 YARA rules load from : {YARA_RULES_DIR}")

    if not os.path.exists(YARA_RULES_DIR):
        print(f"❌ YARA rules folder does not exist : {YARA_RULES_DIR}")
        return None

    rule_files = {
        f: os.path.join(YARA_RULES_DIR, f)
        for f in os.listdir(YARA_RULES_DIR)
        if f.endswith(".yar")
    }

    if not rule_files:
        print("❌ No YARA rules find !")
        return None

    try:
        compiled_rules = yara.compile(filepaths=rule_files)
        print(f"✅ YARA rules loaded : {list(rule_files.keys())}")
        return compiled_rules
    except yara.SyntaxError as e:
        print(f"❌ Syntax error in YARA rules : {e}")
        return None


rules = load_yara_rules()


def yara_scan(file_path):
    if not rules:
        return "⚠️ No YARA rules loaded."
    try:
        matches = rules.match(file_path)
        return f"🚨 CYARA matches found : {matches}" if matches else "✅ No YARA matches"
    except Exception as e:
        return f"❌ YARA parsing error : {e}"


def hash_file(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"❌ Hash calculation error : {e}")
        return None


def check_virus_total(file_path):
    file_hash = hash_file(file_path)
    if not file_hash:
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        elif response.status_code == 404:
            return "⚠️ Unknown file on VirusTotal."
        else:
            return f"⚠️ VirusTotal error ({response.status_code}): {response.text}"
    except requests.RequestException as e:
        return f"⚠️ VirusTotal connection error : {e}"


def check_iocs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        matches = {
            "ips": [ip for ip in IOCs_IP if ip in content],
            "domains": [domain for domain in IOCs_DOMAINS if domain in content],
            "urls": [url for url in IOCs_URLS if url in content]
        }

        return matches
    except Exception as e:
        return f"❌ Error reading file : {e}"


def analyze_file():
    file_path = filedialog.askopenfilename(title="Select a file to scan")

    if not file_path:
        return

    analyze(file_path)


def analyze_folder():
    folder_path = filedialog.askdirectory(title="Select a folder to scan")

    if not folder_path:
        return

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            analyze(file_path)


def analyze(file_path):
    result_vt = check_virus_total(file_path) or "⚠️ Unable to verify on VirusTotal."
    result_yara = yara_scan(file_path) or "⚠️ No YARA rules loaded."
    result_iocs = check_iocs(file_path)

    ioc_summary = (
        f"📌 IPs: {', '.join(result_iocs['ips']) if result_iocs['ips'] else 'Aucune'}\n"
        f"🌐 Domaines: {', '.join(result_iocs['domains']) if result_iocs['domains'] else 'Aucun'}\n"
        f"🔗 URLs: {', '.join(result_iocs['urls']) if result_iocs['urls'] else 'Aucune'}\n"
    )

    results_text = f"📄 File: {file_path}\n\n🔍 VirusTotal: {result_vt}\n🛡️ YARA: {result_yara}\n\n🔎 IOC Matches:\n{ioc_summary}"

    result_box.config(state=tk.NORMAL)
    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, results_text)
    result_box.config(state=tk.DISABLED)


root = tb.Window(themename="darkly")
root.title("Files Scan (IOC, YARA & VirusTotal)")
root.geometry("700x500")

frame = tb.Frame(root)
frame.pack(pady=20)

btn_file = tb.Button(frame, text="File scan", command=analyze_file, bootstyle="primary")
btn_file.pack(side="left", padx=10)

btn_folder = tb.Button(frame, text="Folder Scan", command=analyze_folder, bootstyle="secondary")
btn_folder.pack(side="left", padx=10)

result_box = scrolledtext.ScrolledText(root, height=15, width=80, state=tk.DISABLED)
result_box.pack(pady=20)

root.mainloop()
