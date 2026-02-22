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
SEEN_DB = ".seen_urls"

def get_verification_context(data):
    """Mengumpulkan bukti teknis IP, DNS, dan Waktu"""
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    context = {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": data.get("info", {}).get("name", "Unknown"),
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "url": data.get("matched-at", host)
    }
    
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME record"
        except: context["dns_cname"] = "Failed"
    return context

def create_h1_draft(title, description, impact, severity, url):
    """Kirim laporan ke HackerOne Draft dengan Cek Duplikat"""
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url in f.read(): return "ALREADY_REPORTED"

    if PROGRAM_NAME == "00_test": return "TEST-DRAFT-ID-2026"

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
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f: f.write(f"{url}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings_list = []
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                sev = d.get("info", {}).get("severity", "info").lower()
                if sev in ["medium", "high", "critical"]:
                    findings_list.append(get_verification_context(d))
                if len(findings_list) >= 15: break
            except: continue

    if not findings_list: return

    # --- [TEMPLATE LAPORAN PROFESIONAL ASLI DARI BOS JOSUA] ---
    report_template = """
## Vulnerability Details
**Title:** {title}
**Severity:** {severity}
**Category:** {category}
**Affected Asset:** {url}

## Summary
{summary}

## Impact
### Business Impact:
{business_impact}

### Technical Impact:
{technical_impact}

### Affected Users/Data:
{affected_data}

## Technical Details
{technical_explanation}

## Steps To Reproduce
1. {step_1}
2. {step_2}
3. {step_3}

## Proof of Concept
Vulnerability detected via Nuclei automation.
- **Template ID:** {template_id}
- **Status Code:** {status}
- **Resolved IP:** {ip}

## Discovery Process
Automated discovery using customized ProjectDiscovery Nuclei sniper drones during authorized security testing.

## Testing Environment
- **IP Address(es):** {ip}
- **User Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64) SniperRecon/2026
- **Testing Timezone:** UTC
- **Testing Period:** {time}

## Remediation
{remediation_plan}
    """

    prompt = f"""
    ROLE: Senior Triage Specialist at HackerOne.
    PROGRAM: {PROGRAM_NAME}. DATA: {json.dumps(findings_list)}
    
    TASK: Write a separate, professional HackerOne report for each valid bug.
    USE THIS EXACT TEMPLATE:
    {report_template}

    INSTRUCTIONS:
    - Fill every section with technical detail.
    - Impact field in the JSON output should ONLY contain the full '## Impact' section text.
    - Description field should contain all other sections.
    - Output ONLY a JSON ARRAY: [{{title, description, impact, severity, url}}]
    - If nothing valid: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        res = requests.post(url, headers={"Authorization": f"Bearer {AI_KEY}"}, json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1})
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'], rep.get('url', ''))
                if d_id in [None, "ALREADY_REPORTED"]: continue
                
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if any(x in sev for x in ["CRITICAL", "HIGH", "P1", "P2"]) else "P3-P4"
                folder = "high" if p_label == "P1-P2" else "low"
                
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                with open(f"data/{PROGRAM_NAME}/alerts/{folder}/{p_label}_{safe_title}_{idx}.md", 'w') as f:
                    f.write(f"# {rep['title']}\n\nDraft ID: `{d_id}`\n\n{rep['description']}\n\n## Impact\n{rep['impact']}")

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
