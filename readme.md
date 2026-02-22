🚀 CARA INSTALASI
bash
# Clone repository
git clone https://github.com/username/CTF-Tools.git
cd CTF-Tools

# Install semua dependencies
pip install -r requirements.txt

# Atau install per kategori
pip install requests beautifulsoup4 colorama  # Web
pip install pillow qrcode reportlab flask      # Forensic
pip install pycryptodome                        # Crypto
pip install pyelftools pefile capstone         # Reverse
pip install python-whois dnspython phonenumbers # OSINT
🎯 CARA PENGGUNAAN
Web Exploitation:
bash
python 1_web_exploitation/sqli_scanner.py -u "http://target.com/page.php?id=1"
python 1_web_exploitation/xss_scanner.py -u "http://target.com/search.php"
Forensic:
bash
# Generate PDF dengan tracking
python 2_forensic/pdf_tracker_forensic.py generate -o doc.pdf -c "KONTEN" -u user@mail.com

# Jalankan server
python 2_forensic/pdf_tracker_forensic.py server -p 5000

# Recovery file
python 2_forensic/pdf_tracker_forensic.py carve -f image.raw -o recovered/
Cryptography:
bash
python 3_cryptography/crypto_tools.py analyze -t "SGVsbG8gV29ybGQ="
python 3_cryptography/crypto_tools.py caesar -t "Hello" -s 3
python 3_cryptography/crypto_tools.py crack -t "5f4dcc3b5aa765d61d8327deb882cf99"
Reverse Engineering:
bash
python 4_reverse_engineering/re_tools.py strings -f binary.exe
python 4_reverse_engineering/re_tools.py elf -f binary.elf
python 4_reverse_engineering/re_tools.py pe -f program.exe
Binary Exploitation:
bash
python 5_binary_exploitation/binexp_tools.py pattern -l 1000
python 5_binary_exploitation/binexp_tools.py connect -t 10.0.0.1 -p 1337
python 5_binary_exploitation/binexp_tools.py fuzz -t 10.0.0.1 -p 1337
OSINT:
bash
python 6_osint/osint_tools.py ip -t 8.8.8.8
python 6_osint/osint_tools.py dns -t google.com
python 6_osint/osint_tools.py whois -t google.com
python 6_osint/osint_tools.py phone -t "+628123456789"
📚 FITUR LENGKAP
Kategori	Tools	Fitur
Web	SQLi Scanner	Deteksi SQL Injection, Boolean/Time-based
XSS Scanner	Deteksi Cross-Site Scripting
Forensic	PDF Tracker	Lacak akses PDF, Tracking server
File Carver	Recovery file terhapus
Crypto	Encoder/Decoder	Base64, Hex, ROT13, ROT47
Cipher	Caesar, Vigenere, XOR, AES
Hash cracker	MD5, SHA1, SHA256
Reverse	Strings extractor	Ekstrak string dari binary
ELF/PE Analyzer	Analisis file executable
ROP gadgets	Cari ROP gadgets
Binary	Pwn tools	Connect, send, receive
Pattern generator	Untuk buffer overflow
Shellcode	execve, reverse shell
OSINT	IP/DNS lookup	Informasi IP dan DNS
WHOIS	Informasi domain
Phone lookup	Informasi nomor telepon
⚠️ CATATAN PENTING
Gunakan untuk belajar CTF secara legal

Jangan gunakan untuk menyerang sistem tanpa izin

Beberapa tools butuh API key (Shodan)

Untuk forensic, butuh server sendiri

Selalu patuhi hukum dan etika

Selamat belajar CTF! 🚩🔥