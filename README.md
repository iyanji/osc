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
