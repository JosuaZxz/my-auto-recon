import os
import json
import requests
import google.generativeai as genai

# Ambil rahasia dari GitHub
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

def create_h1_draft(title, description, impact):
    """Mengirim laporan langsung ke Draft HackerOne"""
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    headers = {"Accept": "application/json"}
    data = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": PROGRAM_NAME, 
                "title": title,
                "description": description,
                "impact": impact
            }
        }
    }
    try:
        response = requests.post(url, auth=auth, headers=headers, json=data)
        return response.json()['data']['id'] if response.status_code == 201 else None
    except:
        return None

def validate_findings():
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 10: findings.append(json.loads(line))

    # Prompt AI yang lebih detail
    prompt = f"""
    You are a professional Bug Bounty Hunter. Create a detailed report for {PROGRAM_NAME}.
    Data: {json.dumps(findings)}
    Output ONLY a JSON with keys: "title", "description", "impact". English only.
    """

    try:
        response = model.generate_content(prompt)
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_json)
        
        # 1. Kirim ke HackerOne API
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        # 2. Simpan Backup Laporan dalam bentuk Markdown (.md) di GitHub
        report_md = f"# H1 Report Draft: {report_data['title']}\n\n## Description\n{report_data['description']}\n\n## Impact\n{report_data['impact']}"
        with open(f'data/{PROGRAM_NAME}/H1_DRAFT_FULL.md', 'w') as f:
            f.write(report_md)

        # 3. Siapkan Notifikasi Telegram
        if draft_id:
            status_msg = f"✅ SUCCESS: Draft created on HackerOne!\nID: {draft_id}\nProgram: {PROGRAM_NAME}\nTitle: {report_data['title']}"
        else:
            status_msg = f"⚠️ AI found a bug but H1 Draft failed. Check GitHub!\nProgram: {PROGRAM_NAME}\nTitle: {report_data['title']}"
            
        with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
            f.write(status_msg)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
