import os
import json
import requests
import google.generativeai as genai

# Ambil rahasia dari GitHub Secrets
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# Inisialisasi Gemini AI
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

def create_h1_draft(title, description, impact):
    """Fungsi untuk mengirim draf ke HackerOne"""
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
        if response.status_code == 201:
            return response.json()['data']['id']
        else:
            print(f"HackerOne API Error: {response.text}")
    except Exception as e:
        print(f"H1 Request Error: {e}")
    return None

def validate_findings():
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 10: # Ambil 10 temuan teratas
                findings.append(json.loads(line))

    # Perintah AI untuk membuat JSON laporan
    prompt = f"""
    You are a professional Bug Bounty Hunter. 
    Analyze these Nuclei results for program '{PROGRAM_NAME}': {json.dumps(findings)}
    
    Task:
    1. Ignore False Positives.
    2. If valid, create a report in English.
    3. Output MUST be ONLY a JSON with keys: "title", "description", "impact".
    4. In "description", include the URL and how to reproduce it.
    """

    try:
        response = model.generate_content(prompt)
        # Membersihkan teks dari format markdown ```json ... ```
        clean_text = response.text.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_text)
        
        # 1. Kirim Draft ke HackerOne
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        # 2. Siapkan file untuk Notifikasi Telegram
        if draft_id:
            msg = f"✅ DRAFT CREATED ON HACKERONE!\n\nProgram: {PROGRAM_NAME}\nDraft ID: {draft_id}\nTitle: {report_data['title']}"
            # Kita anggap ini HIGH severity karena masuk ke HackerOne
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(msg)
        else:
            # Jika gagal kirim ke H1, tetap simpan laporan ke Telegram agar kamu tahu
            with open(f'data/{PROGRAM_NAME}/low_findings.txt', 'w') as f:
                f.write(f"AI Found something but H1 Draft Failed:\n\n{report_data['title']}")
                
    except Exception as e:
        print(f"AI/Process Error: {e}")

if __name__ == "__main__":
    validate_findings()
