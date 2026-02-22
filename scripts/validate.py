import os
import json
import requests
import subprocess
import re
from datetime import datetime

# --- [1. KONFIGURASI RAHASIA GITHUB SECRETS] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """
    Mengambil data teknis mendalam dari Nuclei untuk AI.
    Ini fitur yang bikin AI punya 'mata' buat liat detail bug.
    """
    host = data.get("host", "")
    info = data.get("info", {})
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown"),
        "template_desc": info.get("description", "No description"),
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", host),
        "extracted_results": data.get("extracted-results", []),
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time
    }

def create_h1_draft(title, description, impact, severity):
    """Mengirim laporan valid langsung ke Draft HackerOne"""
    # Bypass khusus mode tes (Abaikan jika bukan berburu asli)
    if PROGRAM_NAME == "00_test": return "TEST-DRAFT-PRO-2026"

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    h1_sev = "low"
    if severity.lower() in ["critical", "high"]: h1_sev = "high"
    elif severity.lower() == "medium": h1_sev = "medium"
    
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
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    """Proses utama: Triage AI menggunakan Template Profesional Bos Josua"""
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings_list = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                # Ambil konteks teknis lengkap
                findings_list.append(get_verification_context(d))

    # Siapkan folder untuk file laporan di memori sementara GitHub
    os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
    os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

    # --- [TEMPLATELAPORAN PROFESIONAL BOS JOSUA] ---
    report_template = """
## Vulnerability Details
**Title:** {title}
**Severity:** {severity_label}
**Category:** {category}
**Affected Asset:** {url}

## Summary
{summary}

## Impact
{impact_analysis}

## Technical Details
{tech_details}

## Steps To Reproduce
1. Access the target at {url}
2. {step_2}
3. {step_3}

## Proof of Concept
The automated scan identified this issue using Nuclei template `{template_id}`.
Resolved IP: {ip}
Status Code: {status}

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

    # --- PROMPT AI GRANDMASTER ---
    prompt = f"""
    ROLE: Senior Triage Specialist at HackerOne.
    PROGRAM: {PROGRAM_NAME}
    DATA: {json.dumps(findings_list)}

    TASK:
    Write a separate, high-quality technical report for each valid bug using the provided template. 
    Be very specific about the 'Impact' section (split into Business and Technical impact).
    
    TEMPLATE TO FILL:
    {report_template}

    INSTRUCTIONS:
    1. Fill every placeholder in the template with professional detail.
    2. Focus heavily on 'Impact' (Detailed Business and Technical risks).
    3. Categorize as 'Critical', 'High', 'Medium', or 'Low'.
    
    FORMAT: Return ONLY a raw JSON ARRAY of objects:
    [ {{"title": "...", "description": "FULL_MARKDOWN_REPORT", "impact": "IMPACT_SECTION_ONLY", "severity": "..."}} ]
    If nothing valid: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        response = requests.post(url, headers=headers, json=data)
        ai_out = response.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            for idx, rep in enumerate(reports):
                # 1. Kirim Draf ke HackerOne
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
                
                # 2. Tentukan Jalur P-Level
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if sev in ["CRITICAL", "HIGH"] else "P3-P4"
                folder = "high" if p_label == "P1-P2" else "low"
                
                # 3. Buat File Markdown untuk dikirim ke Telegram
                safe_name = re.sub(r'\W+', '_', rep['title'])[:50]
                file_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{p_label}_{safe_name}_{idx}.md"
                
                md_content = f"# {rep['title']}\n\n"
                md_content += f"**Draft ID:** `{d_id or 'Manual_Check_Required'}`\n"
                md_content += f"**Program:** {PROGRAM_NAME.upper()}\n"
                md_content += f"**Label:** {p_label}\n\n"
                md_content += f"{rep['description']}\n\n"
                md_content += f"## Impact Analysis\n{rep['impact']}"

                with open(file_path, 'w') as f:
                    f.write(md_content)

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
