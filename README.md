OSC - Open Source Code Scanner
Author: iyanji
Language: Python 3
License: MIT (Opsional, sesuaikan dengan GitHub)

🔹 Deskripsi
OSC (Open Source Code Scanner) adalah sebuah tool Python yang dirancang untuk membantu menemukan data sensitif yang terekspos pada website atau aplikasi web. Tool ini dapat mendeteksi:
API Keys & Tokens
Passwords dan kredensial database
File konfigurasi dan file sensitif
Alamat email dan IP internal
Data finansial (Stripe, PayPal, Braintree)
File backup, log, dan environment
Multi-threaded scanning untuk performa cepat
Laporan JSON komprehensif
Tool ini ditujukan hanya untuk website yang kamu miliki atau memiliki izin eksplisit untuk di-scan. Penggunaan tanpa izin dapat melanggar hukum.

🔹 Fitur Utama
Mendukung scan authenticated session menggunakan cookie.
Multi-threaded scanning (default 10 threads).
Timeout request dapat diatur.
Deteksi pola regex untuk API Key, Token, Password, Database, Email, Internal IP, dan file sensitif.
Deteksi file sensitif yang terekspos secara langsung.
Mencari URL tambahan melalui sitemap, robots.txt, dan common paths.
Menampilkan hasil secara real-time dengan warna.
Membuat laporan JSON lengkap dengan ringkasan risiko.

🔹 Instalasi
Clone repository ini:
git clone https://github.com/iyanji/osc.git
cd osc

USAGE:
    python3 osc.py [OPTIONS] TARGET_URL

OPTIONS:
    -s, --session SESSION    Session cookie for authenticated scanning
    -t, --threads THREADS    Number of threads (default: 10)
    --timeout TIMEOUT        Request timeout in seconds (default: 10)
    -o, --output FILE        Output file for JSON report
    -h, --help               Show this help message

EXAMPLES:
    Basic scan:
    python3 osc.py https://example.com

    Scan with session cookie:
    python3 osc.py -s "session_cookie_value" https://example.com

    Custom threads and timeout:
    python3 osc.py -t 5 --timeout 15 https://example.com

    Save report to file:
    python3 osc.py -o scan_report.json https://example.com

FEATURES:
    • API Keys & Tokens detection
    • Database credentials scanning
    • Sensitive file discovery
    • Configuration files detection
    • Email addresses and internal IPs
    • Financial data scanning
    • Multi-threaded scanning
    • JSON report generation

