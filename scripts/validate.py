import os
import json
import requests
import subprocess
import re

# --- [BAGIAN 1: KONFIGURASI RAHASIA] ---
# Mengambil kunci dari GitHub Secrets untuk keamanan maksimal
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """
    Fungsi cerdas untuk mengecek bukti teknis (IP & DNS) secara real-time.
    Ini fitur yang bikin laporan kamu terlihat sangat profesional di mata Triage.
    """
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    
    context = {
        "ip_address": data.get("ip", "Unknown"),
        "status_code": data.get("info", {}).get("status-code", "Unknown"),
        "template_id": data.get("template-id", "Unknown"),
        "matched_at": data.get("matched-at", "Unknown")
    }
    
    # Verifikasi CNAME jika ada indikasi Subdomain Takeover (STO)
    if "takeover" in data.get("template-id", "").lower():
        try:
            # Menjalankan perintah 'dig' langsung di server Linux GitHub
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME record found"
        except:
            context["dns_cname"] = "DNS lookup failed"
            
    return context

def create_h1_draft(title, description, impact):
    """
    Mengirim laporan valid langsung ke Draft HackerOne.
    Laporan ini hanya berupa DRAFT (Report Intent), tidak langsung disubmit.
    """
    # --- [FITUR BYPASS KHUSUS UNTUK TESTING] ---
    if PROGRAM_NAME == "00_test":
        print("🛠️ DEBUG: Test Mode detected. Bypassing HackerOne API check...")
        return "DRAFT-TEST-SUCCESS-99999"

    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    payload = {
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
        response = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        if response.status_code == 201:
            return response.json()['data']['id']
        else:
            print(f"❌ H1 API Error: {response.text}")
    except Exception as e:
        print(f"❌ H1 Connection Error: {e}")
    return None

def validate_findings():
    """
    Proses Utama: 
    1. Membaca hasil Nuclei.
    2. Melakukan verifikasi teknis (IP/DNS).
    3. Menggunakan AI Groq (Llama 3.3) untuk Triage & Penulisan Laporan Elit.
    """
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    
    # --- [LOGIKA KHUSUS TES: PASTI BUNYI] ---
    if PROGRAM_NAME == "00_test":
        print("🛠️ TEST MODE: Forcing notification flow...")
        d_id = create_h1_draft("Fake Critical Bug", "This is a POC for testing.", "High Risk")
        msg = f"🚨 **TEST NOTIFICATION SUCCESS**\n\n🎯 Target: 00_TEST\n🆔 ID: `{d_id}`\n📝 Status: Jalur AI & Telegram AKTIF!"
        with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
            f.write(msg)
        return

    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        print("✅ Analysis Complete: No findings to process.")
        return

    findings_list = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                raw_data = json.loads(line)
                # Tambahkan bukti teknis DNS/IP sebelum dikirim ke AI
                raw_data["verification_context"] = get_verification_context(raw_data)
                findings_list.append(raw_data)

    # --- [PROMPT AI GRANDMASTER: GABUNGAN SEMUA SARAN] ---
    prompt = f"""
    ROLE: You are the Senior Security Researcher at HackerOne (Triage Specialist).
    PROGRAM: {PROGRAM_NAME}
    SCAN_DATA: {json.dumps(findings_list)}

    TASK:
    1. ANALYZE: Filter out false positives. Ignore 403/401 on sensitive files unless it's a clear bypass.
    2. CONSOLIDATE (ANTI-SPAM): If multiple subdomains have the SAME bug, combine them into ONE single report.
    3. LABEL: If the bug is High/Critical (SQLi, RCE, Takeover, Secret Leak), start title with [URGENT].
    4. POC: Provide clear technical steps (1, 2, 3) to reproduce. Use professional English.
    5. INFO: Include Resolved IP and DNS CNAME in the technical description.

    FORMAT: Return ONLY a raw JSON object with keys: "title", "description", "impact". 
    Do not add conversational text. If no valid bug is found, return: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        
        response = requests.post(url, headers=headers, json=data)
        ai_output = response.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_output:
            print("✅ AI Analysis: Target is safe. No exploitable vulnerabilities found.")
            return

        # Parsing JSON dengan aman menggunakan Regex & strict=False
        json_match = re.search(r'\{.*\}', ai_output, re.DOTALL)
        if json_match:
            report_data = json.loads(json_match.group(0), strict=False)
            draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
            
            if draft_id:
                # Siapkan pesan untuk notifikasi Telegram
                msg = f"💎 **VALID BUG DISCOVERED!**\n\n🎯 Target: {PROGRAM_NAME.upper()}\n🆔 Draft ID: `{draft_id}`\n📝 Title: {report_data['title']}\n\n🔥 _Check your HackerOne dashboard!_"
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                    f.write(msg)
                print("🚀 Success: Notification data generated.")
                
    except Exception as e:
        print(f"❌ AI Processing Error: {e}")

# --- [BAGIAN 4: RUN SCRIPT] ---
if __name__ == "__main__":
    validate_findings()
