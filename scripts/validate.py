import os
import json
import requests
import subprocess
import re
import time
from datetime import datetime

# --- [1. KONFIGURASI GITHUB SECRETS] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls" # Database lokal sederhana

def get_verification_context(data):
    """Mengecek bukti teknis (IP & DNS) secara real-time"""
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    context = {
        "template_id": data.get("template-id", "Unknown"),
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "url": data.get("matched-at", host)
    }
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME found"
        except: context["dns_error"] = "Lookup failed"
    return context

def create_h1_draft(title, description, impact, severity, url):
    """Kirim Draf ke HackerOne dengan Delay dan Cek Duplikat"""
    # 1. Cek apakah URL ini sudah pernah dilaporkan sebelumnya
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url in f.read():
                print(f"[-] Duplicate skipped: {url}")
                return "ALREADY_REPORTED"

    # 2. Bypass khusus mode tes
    if PROGRAM_NAME == "00_test": return "TEST-DRAFT-PRO-2026"

    # 3. Jalur API HackerOne
    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    
    payload = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": target_handle,
                "title": title,
                "description": description,
                "impact": impact,
                "severity_rating": h1_sev
            }
        }
    }
    
    try:
        # Tambahkan jeda 2 detik biar gak kena Rate Limit HackerOne
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            # Simpan URL ke database agar tidak dilaporkan lagi selamanya
            with open(SEEN_DB, "a") as f: f.write(f"{url}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    # FILTER: Hanya kirim yang Medium ke atas ke AI (Hemat Kuota & Fokus)
    findings_list = []
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                severity = d.get("info", {}).get("severity", "info").lower()
                if severity in ["medium", "high", "critical"]:
                    d["context"] = get_verification_context(d)
                    findings_list.append(d)
                if len(findings_list) >= 15: break
            except: continue

    if not findings_list:
        print("✅ No high-quality findings to analyze.")
        return

    # --- [TEMPLATE LAPORAN PRO] ---
    report_template = """## Vulnerability Details
**Severity:** {severity} | **Asset:** {url}
## Summary
{summary}
## Impact
{impact_analysis}
## Technical Details
{tech_details}
## Steps To Reproduce
1. Access {url}
2. Observe result
## Environment
- IP: {ip} | Time: {time}"""

    prompt = f"Role: Senior Triage Lead. Program: {PROGRAM_NAME}. Data: {json.dumps(findings_list)}. Task: Write separate reports using template: {report_template}. Format: JSON ARRAY of objects [{{title, description, impact, severity, url}}]. No talk, just JSON. If nothing valid: NO_VALID_BUG"

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        res = requests.post(url, headers=headers, json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1})
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                # Eksekusi kirim H1 & Cek duplikat
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'], rep.get('url', ''))
                
                if d_id in [None, "ALREADY_REPORTED"]: continue
                
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if sev in ["CRITICAL", "HIGH"] else "P3-P4"
                folder = "high" if p_label == "P1-P2" else "low"
                
                # Simpan file .md (FIXED Syntax)
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                with open(f"data/{PROGRAM_NAME}/alerts/{folder}/{p_label}_{safe_title}_{idx}.md", 'w') as f:
                    f.write(f"# {rep['title']}\n\nDraft ID: {d_id}\n\n{rep['description']}\n\n## Impact\n{rep['impact']}")

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
