#!/usr/bin/env python3
"""
PDF FORENSIC TRACKER - Tools untuk melacak akses PDF
CTF Forensic Category
"""

import os
import sys
import json
import hashlib
import time
import socket
import requests
from datetime import datetime
from PIL import Image
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import argparse
import base64
from flask import Flask, request, jsonify
import threading

class PDFTracker:
    """Buat PDF dengan kemampuan tracking"""
    
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        
    def generate_tracking_id(self, user_email):
        """Generate ID unik"""
        data = f"{user_email}{time.time()}{socket.gethostname()}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def create_pdf(self, output_file, content, user_email, user_name=""):
        """Buat PDF dengan tracking tersembunyi"""
        
        tracking_id = self.generate_tracking_id(user_email)
        tracking_url = f"{self.server_url}/track?id={tracking_id}&user={user_email}"
        
        # Buat PDF
        c = canvas.Canvas(output_file, pagesize=A4)
        width, height = A4
        
        # Konten biasa (tidak ada peringatan)
        y = height - 50
        lines = content.split('\n')
        for line in lines:
            if y < 50:
                c.showPage()
                y = height - 50
            c.drawString(50, y, line)
            y -= 20
        
        # Sisipkan tracking pixel TERSEMBUNYI (1x1 transparan)
        # Di pojok kanan bawah, tidak terlihat
        c.saveState()
        c.setFillColorRGB(1, 1, 1, 0)  # Transparan
        c.rect(width-10, 10, 1, 1, fill=1)  # Pixel 1x1
        c.linkURL(tracking_url, (width-10, 10, width-9, 11), relative=1)
        c.restoreState()
        
        c.save()
        
        print(f"\n✅ PDF dibuat: {output_file}")
        print(f"🆔 Tracking ID: {tracking_id}")
        print(f"📡 Server: {self.server_url}")
        
        return tracking_id

class TrackingServer:
    """Server untuk menerima data tracking"""
    
    def __init__(self, port=5000):
        self.port = port
        self.app = Flask(__name__)
        self.log_file = "forensic_log.json"
        self.setup_routes()
        
    def setup_routes(self):
        @self.app.route('/track', methods=['GET'])
        def track():
            data = {
                'time': datetime.now().isoformat(),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'tracking_id': request.args.get('id', 'unknown'),
                'user': request.args.get('user', 'unknown'),
                'referer': request.headers.get('Referer', 'direct')
            }
            
            # Tampilkan notifikasi
            print("\n" + "="*50)
            print(f"🔔 PDF DI AKSES!")
            print(f"📄 Tracking ID: {data['tracking_id']}")
            print(f"👤 User: {data['user']}")
            print(f"🌍 IP: {data['ip']}")
            print(f"🕐 Time: {data['time']}")
            print(f"📱 User-Agent: {data['user_agent'][:50]}...")
            print("="*50)
            
            # Simpan ke file
            self.save_log(data)
            
            # Return 1x1 transparent pixel
            pixel = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
            return pixel, 200, {'Content-Type': 'image/gif'}
        
        @self.app.route('/logs', methods=['GET'])
        def view_logs():
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    return jsonify(json.load(f))
            return jsonify([])
    
    def save_log(self, data):
        logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        
        logs.append(data)
        
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def run(self):
        print(f"🚀 Forensic Tracking Server berjalan di port {self.port}")
        self.app.run(host='0.0.0.0', port=self.port, debug=False)

class FileCarver:
    """Tool untuk file carving (recovery file terhapus)"""
    
    def __init__(self):
        self.signatures = {
            'jpg': [b'\xFF\xD8\xFF', b'\xFF\xD8\xFF\xE0'],
            'png': [b'\x89\x50\x4E\x47'],
            'pdf': [b'\x25\x50\x44\x46'],
            'zip': [b'\x50\x4B\x03\x04'],
            'doc': [b'\xD0\xCF\x11\xE0'],
            'gif': [b'\x47\x49\x46\x38'],
        }
    
    def carve_file(self, data, start, signature):
        """Carve file berdasarkan signature"""
        # Cari end of file (EOF) - sederhana
        eof_markers = {
            b'\xFF\xD9': 'jpg',
            b'\x49\x45\x4E\x44': 'png',
            b'\x25\x25\x45\x4F\x46': 'pdf',
            b'\x50\x4B\x05\x06': 'zip'
        }
        
        for marker, ext in eof_markers.items():
            end = data.find(marker, start)
            if end != -1:
                return data[start:end + len(marker)]
        
        return data[start:start + 1024*1024]  # Max 1MB
    
    def recover_files(self, filepath, output_dir):
        """Recover files dari binary blob"""
        print(f"{Fore.YELLOW}[*] Scanning {filepath} untuk file terhapus...")
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        recovered = []
        
        for ext, sigs in self.signatures.items():
            for sig in sigs:
                offset = 0
                while True:
                    pos = data.find(sig, offset)
                    if pos == -1:
                        break
                    
                    print(f"{Fore.GREEN}[+] Menemukan file {ext} di offset {hex(pos)}")
                    
                    # Carve file
                    file_data = self.carve_file(data, pos, sig)
                    
                    # Simpan
                    filename = f"recovered_{len(recovered)}_{pos}.{ext}"
                    filepath = os.path.join(output_dir, filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(file_data)
                    
                    recovered.append(filepath)
                    offset = pos + 1
        
        print(f"{Fore.CYAN}[✓] Berhasil recover {len(recovered)} files di {output_dir}")
        return recovered

def main():
    parser = argparse.ArgumentParser(description='PDF Forensic Tools')
    parser.add_argument('mode', choices=['generate', 'server', 'carve'],
                       help='Mode operasi')
    parser.add_argument('-f', '--file', help='File untuk di-carve')
    parser.add_argument('-o', '--output', default='output',
                       help='Output file/directory')
    parser.add_argument('-c', '--content', help='Konten PDF')
    parser.add_argument('-u', '--user', help='Email user')
    parser.add_argument('-n', '--name', help='Nama user')
    parser.add_argument('-p', '--port', type=int, default=5000,
                       help='Port server')
    
    args = parser.parse_args()
    
    if args.mode == 'generate':
        if not args.content or not args.user:
            print("Error: Butuh --content dan --user")
            return
        
        tracker = PDFTracker(f"http://localhost:{args.port}")
        tracker.create_pdf(args.output, args.content, args.user, args.name)
        
    elif args.mode == 'server':
        server = TrackingServer(args.port)
        server.run()
        
    elif args.mode == 'carve':
        if not args.file:
            print("Error: Butuh --file untuk di-carve")
            return
        
        carver = FileCarver()
        os.makedirs(args.output, exist_ok=True)
        carver.recover_files(args.file, args.output)

if __name__ == "__main__":
    main()