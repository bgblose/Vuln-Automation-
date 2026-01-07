# <p align="center">⚡ OmniScanner Pro V6.8 ⚡</p>
<p align="center">
  <img src="https://img.shields.io/badge/Version-6.8--Kingzhat--Edition-red?style=for-the-badge&logo=python" alt="Version">
  <img src="https://img.shields.io/badge/Security-Audit-blue?style=for-the-badge&logo=target" alt="Security">
  <img src="https://img.shields.io/badge/HackerOne-Eligible-green?style=for-the-badge&logo=hackerone" alt="HackerOne">
</p>

<pre align="center">
  _  _  _             _              _
 | |/ /(_) _ __  __ _|_|__ ___  __ _| |_
 | ' < | || '  \/ _` ||_ /|_  |/ _` |  _|
 |_|\_\|_||_|_|_\__, |/__| /_/ \__,_|\__|
                 |___/   [  - KINGZHAT ]
</pre>

<p align="center">
  <strong>Advanced Infrastructure Audit & Vulnerability Assessment Framework</strong><br>
  <i>"Precision in Reconnaissance, Lethality in Exploitation."</i>
</p>

---

## 🌌 Overview
**OmniScanner Pro** adalah *all-in-one security suite* generasi terbaru. Dibangun di atas **AGUS Core Engine**, framework ini dirancang untuk membedah lapisan keamanan web paling ketat, mendeteksi miskonfigurasi infrastruktur cloud, hingga otomatisasi pemanenan kredensial (*Looting*).

### 🛡️ WAF & OS Intelligence
* **Adaptive Bypass**: Mesin cerdas untuk mengidentifikasi dan menembus proteksi **Cloudflare, Incapsula,** dan **F5 BIG-IP**.
* **Hypervisor Detection**: Modul audit khusus untuk mendeteksi *outdated QEMU binaries* guna memetakan potensi **VM Escape**.

### 💀 AGUS Exploitation Engine
* **Laravel/PHP Specialist**: Deteksi kebocoran `.env` dan eksploitasi `APP_KEY` melalui rantai Deserialization.
* **RCE Weaponizer**: Pemindai otomatis titik eksekusi perintah sistem (**OS Command Injection**).
* **Deep TXT Scanner**: Algoritma **Kingzhat** untuk memanen file teks sensitif yang berisi kredensial atau *target list* internal.

### 📡 Real-time Command & Control
* **Telegram C2 Integration**: Notifikasi temuan **Critical** dikirim secara instan ke bot C2 Anda.
* **Automated Looting**: Seluruh hasil panen (kredensial/config) diorganisir dalam folder terenkripsi secara otomatis.

---

## 🛠️ Deployment

### ⚡ Quick Setup
```bash
# Clone the arsenal
git clone ...

# Enter the chamber
cd OmniScanner-Pro

# Install dependencies
pip install -r requirements.txt
```


🎯 Usage Examples
Task	Command
Standard Audit	python3 omniscan.py -t https://target.com --verbose
High-Speed Recon	python3 omniscan.py -t https://target.com --threads 50
Silent Monitoring	python3 omniscan.py -t https://target.com --tg-chatid ID

📊 Severity Classification Matrix
Level	Impact	Common Findings	CVSS v3.1
🔴 CRITICAL	Full Compromise	RCE, SQLi, Auth Bypass, Deserialization	9.0 - 10.0
🟠 HIGH	Data Breach	Path Traversal, LFI, Command Injection	7.0 - 8.9
🟡 MEDIUM	Internal Leak	XXE, Directory Listing, Sensitive Files	4.0 - 6.9
🔵 LOW	Information Leak	Verbose Errors, Missing Security Headers	0.1 - 3.9
☣️ Attack Chain Logic

    RECON: Agregasi subdomain via Subfinder (60+ target).

    SCAN: Deteksi .env terbuka via Nuclei & AGUS Engine.

    EXPLOIT: Ekstraksi otomatis DB_PASSWORD & APP_KEY.

    ESCAPE: Identifikasi kerentanan Virtualisasi (QEMU) untuk kontrol Host.

📜 Legal & Disclaimer

    Alat ini disediakan semata-mata untuk tujuan audit keamanan profesional. Penggunaan tanpa izin tertulis dari pemilik aset adalah ilegal. Pengembang (Kingzhat) tidak bertanggung jawab atas segala kerusakan atau konsekuensi hukum yang timbul.

<p align="center"> <i>"The quieter you become, the more you are able to hear."</i>

<strong>Copyright © 2026 Kingzhat. Codename: Afterbreakup.</strong> </p>

☣️ Attack Chain Logic

    RECON: Agregasi subdomain via Subfinder (60+ target).

    SCAN: Deteksi .env terbuka via Nuclei & AGUS Engine.

    EXPLOIT: Ekstraksi otomatis DB_PASSWORD & APP_KEY.

    ESCAPE: Identifikasi kerentanan Virtualisasi (QEMU) untuk kontrol Host.
