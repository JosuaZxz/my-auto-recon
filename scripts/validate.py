import os
import json
import requests
import google.generativeai as genai

# --- KONFIGURASI RAHASIA ---
# Mengambil kunci dari GitHub Secrets
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# Setup Gemini AI
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

def create_h1_draft(title, description, impact):
    """
    Mengirim laporan draft langsung ke HackerOne.
    Laporan ini akan muncul di menu 'Report Intents' dashboard kamu.
    """
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    
    # Autentikasi menggunakan Username (Identifier) dan API Key (Token)
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
            # Jika gagal, print errornya di log (hanya kamu yang bisa lihat di Actions)
            print(f"❌ H1 API Error: {response.text}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")
    return None

def validate_findings():
    # Cek apakah ada hasil scan Nuclei
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        print("No Nuclei findings to analyze.")
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            # Kita ambil 15 temuan teratas agar AI punya banyak konteks
            if i < 15: 
                findings.append(json.loads(line))

    print(f"🔍 Analyzing {len(findings)} findings with Gemini AI...")

    # --- BAGIAN INI YANG BIKIN LAPORAN JADI PROFESIONAL ---
    prompt = f"""
    ROLE: You are a Senior Bug Bounty Hunter and Security Engineer.
    TASK: Analyze the following Nuclei scan results for the program '{PROGRAM_NAME}'.
    
    DATA: {json.dumps(findings)}

    INSTRUCTIONS:
    1. FILTER: Ignore False Positives or Info-level findings (like missing headers). Focus on P1/P2/P3 vulnerabilities.
    2. WRITE: Create a PROFESSIONAL BUG BOUNTY REPORT in English.
    3. FORMAT: The output must be a VALID JSON object with exactly these keys:
       - "title": A clear, professional title (e.g., "Reflected XSS on search endpoint").
       - "description": A detailed technical explanation including the vulnerable URL and Steps to Reproduce (1. Go to URL, 2. Inject payload...).
       - "impact": A strong impact statement explaining the business risk (e.g., "Attacker can steal session cookies...").
    
    IMPORTANT: Do not output Markdown code blocks. Just the raw JSON string.
    """

    try:
        # Minta Gemini berpikir
        response = model.generate_content(prompt)
        
        # Bersihkan hasil (kadang AI nambahin ```json di awal)
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_json)
        
        # Kirim ke HackerOne
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        if draft_id:
            # Jika Sukses, siapkan pesan untuk Telegram
            msg = f"✅ **SUCCESS: Draft Created on HackerOne!**\n\n🎯 Program: {PROGRAM_NAME}\n🆔 Draft ID: `{draft_id}`\n📝 Title: {report_data['title']}\n\n_Check your HackerOne Dashboard to submit!_"
            
            # Simpan ke file agar recon.yml bisa mengirimnya ke Telegram
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(msg)
                
        else:
            # Jika AI nemu bug tapi Gagal Kirim ke H1 (misal API Error)
            print("AI generated a report, but H1 API failed.")
            
    except Exception as e:
        print(f"❌ AI Processing Error: {e}")

if __name__ == "__main__":
    validate_findings()
