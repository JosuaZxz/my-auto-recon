import os
import json
import requests
import re
import time
import hashlib
from datetime import datetime

# --- [ 1. CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def extract_ua(request_data):
    match = re.search(r"User-Agent: (.*)", request_data, re.IGNORECASE)
    return match.group(1).strip() if match else "Mozilla/5.0 (Stealth Sniper)"

def get_contextual_snippet(res_raw, data):
    if not res_raw: return "No Response Data"
    keys = []
    if "matcher-name" in data: keys.append(data["matcher-name"])
    if "extracted-results" in data: keys.extend(data["extracted-results"])
    keys.extend(["sql syntax", "mysql", "alert(", "<script", "root:x:"])

    target_index = -1
    for kw in keys:
        idx = res_raw.lower().find(str(kw).lower())
        if idx != -1:
            target_index = idx
            break
    
    if target_index == -1: return res_raw[:1000]
    
    start = max(0, target_index - 500)
    end = min(len(res_raw), target_index + 500)
    return f"[...Snipped Context...]\n{res_raw[start:end]}\n[...Snipped Context...]"

def validate_findings():
    print(f"🔍 [MASTER TRIAGE] Engaging: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    # FIX ENCODING: Baca SEEN_DB dengan utf-8 agar tahan banting
    seen_hashes = set()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r", encoding='utf-8', errors='ignore') as f:
            seen_hashes = set(f.read().splitlines())

    all_findings = []
    # FIX ENCODING: Baca hasil Nuclei dengan ignore errors
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                req = d.get("request", "")
                res = d.get("response", "")
                proof = get_contextual_snippet(res, d)
                if "interaction" in d:
                    proof = f"OAST Interaction Detected:\n{json.dumps(d['interaction'], indent=2)}"

                all_findings.append({
                    "template_id": d.get("template-id", "unknown"),
                    "host": d.get("host", "unknown"),
                    "url": d.get("matched-at", d.get("host", "")),
                    "severity": d.get("info", {}).get("severity", "medium").upper(),
                    "title": d.get("info", {}).get("name", "Unknown Bug"),
                    "ua": extract_ua(req),
                    "req_evidence": req[:1500],
                    "res_evidence": proof
                })
            except: continue

    all_findings.sort(key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2}.get(x["severity"], 0), reverse=True)

    for item in all_findings[:15]:
        dedupe_key = f"{item['template_id']}_{item['host']}"
        url_hash = hashlib.md5(dedupe_key.encode()).hexdigest()
        
        if url_hash in seen_hashes: continue

        print(f"[*] Analyzing: {item['title']} on {item['host']}")

        prompt = f"""You are an Elite Bug Bounty Triager. Analyze:
{json.dumps(item)}

REQUIRED OUTPUT (STRICT JSON):
{{
  "title": "Technical Bug Title",
  "status": "valid",
  "full_markdown": "Complete report...",
  "confidence": 0.9
}}
If evidence is weak/404, set "status": "skip"."""

        try:
            time.sleep(3)
            res = requests.post("https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {AI_KEY}"},
                json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1})
            
            ai_data = res.json()['choices'][0]['message']['content'].strip()
            clean_json = re.search(r'\{.*\}', ai_data, re.DOTALL)
            if not clean_json: continue
            
            rep = json.loads(clean_json.group(0), strict=False)
            if rep.get("status") == "skip": continue

            # FIX ENCODING: Simpan hash
            with open(SEEN_DB, "a", encoding='utf-8') as f: f.write(f"{url_hash}\n")
            seen_hashes.add(url_hash)
            
            folder = "high" if item['severity'] in ["CRITICAL", "HIGH"] else "low"
            safe_name = re.sub(r'\W+', '_', rep['title'])[:50]
            report_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{safe_name}.md"
            
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            # FIX ENCODING: Simpan report dengan utf-8
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(f"# {rep['title']} in {PROGRAM_NAME}\n\n🆔 **Draft ID:** `TEST-DRAFT-ID-2026`\n\n")
                f.write(rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".```", "```"))
            
            print(f"[+] Report Created: {rep['title']}")

        except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
