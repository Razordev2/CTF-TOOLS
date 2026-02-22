#!/usr/bin/env python3
"""
OSINT TOOLS - Open Source Intelligence untuk CTF
"""

import argparse
import requests
import json
import re
import socket
import dns.resolver
from urllib.parse import urlparse
import whois
import shodan
import phonenumbers
from phonenumbers import geocoder, carrier

class OSINTTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (CTF OSINT Tool)'
        })
        
    def get_ip_info(self, ip):
        """Dapatkan informasi IP address"""
        try:
            # ip-api.com (free)
            resp = self.session.get(f'http://ip-api.com/json/{ip}')
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return None
    
    def get_dns_info(self, domain):
        """Dapatkan DNS records"""
        records = {}
        
        try:
            # A records
            answers = dns.resolver.resolve(domain, 'A')
            records['A'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # MX records
            answers = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # NS records
            answers = dns.resolver.resolve(domain, 'NS')
            records['NS'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(r) for r in answers]
        except:
            pass
        
        return records
    
    def get_whois(self, domain):
        """Dapatkan WHOIS info"""
        try:
            w = whois.whois(domain)
            return {
                'domain': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails
            }
        except:
            return None
    
    def google_dork(self, query, site=None):
        """Google dorking sederhana (simulasi)"""
        dorks = {
            'filetype:pdf': 'PDF files',
            'filetype:doc': 'Word documents',
            'filetype:xls': 'Excel files',
            'intitle:index.of': 'Directory listings',
            'inurl:admin': 'Admin panels',
            'inurl:login': 'Login pages',
            'ext:sql': 'SQL files',
            'ext:bak': 'Backup files',
            'ext:conf': 'Config files',
            'password': 'Password mentions',
            'config': 'Config mentions',
            'backup': 'Backup mentions'
        }
        
        results = []
        for dork, desc in dorks.items():
            if dork in query:
                results.append(f"[*] Mencari: {desc}")
        
        return results
    
    def extract_metadata(self, url):
        """Ekstrak metadata dari website"""
        try:
            resp = self.session.get(url, timeout=5)
            html = resp.text
            
            metadata = {}
            
            # Title
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if title_match:
                metadata['title'] = title_match.group(1)
            
            # Meta tags
            meta_tags = re.findall(r'<meta\s+name=["\'](.*?)["\']\s+content=["\'](.*?)["\']', html)
            for name, content in meta_tags:
                metadata[f'meta_{name}'] = content
            
            # Links
            links = re.findall(r'href=["\'](.*?)["\']', html)
            metadata['links'] = links[:10]  # Limit 10
            
            # Emails
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', html)
            metadata['emails'] = list(set(emails))
            
            return metadata
        except:
            return None
    
    def phone_lookup(self, phone):
        """Informasi nomor telepon"""
        try:
            number = phonenumbers.parse(phone)
            info = {
                'valid': phonenumbers.is_valid_number(number),
                'country': geocoder.description_for_number(number, 'en'),
                'carrier': carrier.name_for_number(number, 'en'),
                'timezone': phonenumbers.timezone.time_zones_for_number(number)
            }
            return info
        except:
            return None
    
    def github_search(self, query):
        """Search di GitHub (simulasi)"""
        # Catatan: Untuk real, perlu API key
        return [
            f"https://github.com/search?q={query}",
            f"https://github.com/{query}",
            f"https://gist.github.com/search?q={query}"
        ]
    
    def shodan_lookup(self, ip, api_key=None):
        """Shodan lookup (butuh API key)"""
        if not api_key:
            return {"error": "Shodan API key diperlukan"}
        
        try:
            api = shodan.Shodan(api_key)
            results = api.host(ip)
            return {
                'ip': results['ip_str'],
                'ports': results.get('ports', []),
                'hostnames': results.get('hostnames', []),
                'country': results.get('country_name', ''),
                'city': results.get('city', ''),
                'org': results.get('org', '')
            }
        except:
            return None

def main():
    parser = argparse.ArgumentParser(description='OSINT Tools untuk CTF')
    parser.add_argument('action', choices=['ip', 'dns', 'whois', 'web', 'phone',
                       'github', 'dork'])
    parser.add_argument('-t', '--target', required=True, help='Target')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    tools = OSINTTools()
    
    if args.action == 'ip':
        info = tools.get_ip_info(args.target)
        print(json.dumps(info, indent=2))
    
    elif args.action == 'dns':
        info = tools.get_dns_info(args.target)
        print(json.dumps(info, indent=2))
    
    elif args.action == 'whois':
        info = tools.get_whois(args.target)
        print(json.dumps(info, indent=2))
    
    elif args.action == 'web':
        info = tools.extract_metadata(args.target)
        print(json.dumps(info, indent=2))
    
    elif args.action == 'phone':
        info = tools.phone_lookup(args.target)
        print(json.dumps(info, indent=2))
    
    elif args.action == 'github':
        results = tools.github_search(args.target)
        for r in results:
            print(r)
    
    elif args.action == 'dork':
        results = tools.google_dork(args.target)
        for r in results:
            print(r)
    
    # Simpan output jika diminta
    if args.output and 'info' in locals():
        with open(args.output, 'w') as f:
            json.dump(info, f, indent=2)

if __name__ == "__main__":
    main()