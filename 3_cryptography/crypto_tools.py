#!/usr/bin/env python3
"""
CRYPTOGRAPHY TOOLS - Untuk CTF Cryptography
Mendukung berbagai cipher dan encoding
"""

import base64
import hashlib
import argparse
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
import binascii
import codecs
import re

class CryptoTools:
    def __init__(self):
        self.common_encodings = [
            'base64', 'base32', 'base16', 'hex', 'rot13', 'rot47',
            'ascii85', 'base85', 'binary', 'url'
        ]
    
    def detect_encoding(self, text):
        """Coba deteksi encoding dari teks"""
        results = []
        
        # Base64
        try:
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if len(decoded) > 0 and all(ord(c) < 128 for c in decoded):
                results.append(('base64', decoded))
        except:
            pass
        
        # Base32
        try:
            decoded = base64.b32decode(text).decode('utf-8', errors='ignore')
            if len(decoded) > 0:
                results.append(('base32', decoded))
        except:
            pass
        
        # Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', text):
                decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
                if len(decoded) > 0:
                    results.append(('hex', decoded))
        except:
            pass
        
        # ROT13
        rot13 = codecs.decode(text, 'rot_13')
        if rot13 != text and all(ord(c) < 128 for c in rot13):
            results.append(('rot13', rot13))
        
        return results
    
    def rot47(self, text):
        """ROT47 untuk ASCII printable"""
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
            else:
                result.append(c)
        return ''.join(result)
    
    def vigenere(self, text, key, decrypt=False):
        """Vigenere cipher"""
        result = []
        key = key.upper()
        key_len = len(key)
        key_pos = 0
        
        for c in text:
            if c.isalpha():
                shift = ord(key[key_pos % key_len]) - 65
                if decrypt:
                    shift = -shift
                
                if c.isupper():
                    result.append(chr((ord(c) - 65 + shift) % 26 + 65))
                else:
                    result.append(chr((ord(c) - 97 + shift) % 26 + 97))
                
                key_pos += 1
            else:
                result.append(c)
        
        return ''.join(result)
    
    def caesar(self, text, shift):
        """Caesar cipher"""
        result = []
        for c in text:
            if c.isalpha():
                if c.isupper():
                    result.append(chr((ord(c) - 65 + shift) % 26 + 65))
                else:
                    result.append(chr((ord(c) - 97 + shift) % 26 + 97))
            else:
                result.append(c)
        return ''.join(result)
    
    def xor(self, data, key):
        """XOR cipher"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ key[i % len(key)])
        
        return result
    
    def aes_decrypt(self, ciphertext, key, mode='CBC', iv=None):
        """AES decryption"""
        if mode == 'CBC':
            if not iv:
                iv = ciphertext[:16]
                ciphertext = ciphertext[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)
        
        try:
            decrypted = cipher.decrypt(ciphertext)
            return unpad(decrypted, AES.block_size)
        except:
            return cipher.decrypt(ciphertext)
    
    def frequency_analysis(self, text):
        """Frequency analysis untuk cryptanalysis"""
        freq = {}
        total = 0
        
        for c in text:
            if c.isalpha():
                c = c.upper()
                freq[c] = freq.get(c, 0) + 1
                total += 1
        
        # Persentase
        for k in freq:
            freq[k] = (freq[k] / total) * 100
        
        # Urutkan
        freq = dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))
        
        return freq
    
    def hash_crack(self, hash_value, wordlist=None):
        """Crack hash sederhana"""
        common_hashes = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }
        
        # Deteksi tipe hash dari panjang
        hash_type = None
        for name, length in common_hashes.items():
            if len(hash_value) == length:
                hash_type = name
                break
        
        if not hash_type:
            return {'error': 'Unknown hash type'}
        
        result = {'type': hash_type, 'matches': []}
        
        # Coba common passwords
        common_passwords = ['password', '123456', 'admin', 'root', 'toor',
                           'qwerty', 'abc123', 'letmein', 'welcome']
        
        for pwd in common_passwords:
            if hash_type == 'md5':
                h = hashlib.md5(pwd.encode()).hexdigest()
            elif hash_type == 'sha1':
                h = hashlib.sha1(pwd.encode()).hexdigest()
            elif hash_type == 'sha256':
                h = hashlib.sha256(pwd.encode()).hexdigest()
            elif hash_type == 'sha512':
                h = hashlib.sha512(pwd.encode()).hexdigest()
            
            if h == hash_value:
                result['matches'].append(pwd)
        
        return result

def main():
    parser = argparse.ArgumentParser(description='Cryptography Tools untuk CTF')
    parser.add_argument('action', choices=['encode', 'decode', 'crack', 'analyze',
                       'caesar', 'xor', 'vigenere', 'rot47'])
    parser.add_argument('-t', '--text', help='Text to process')
    parser.add_argument('-f', '--file', help='Input file')
    parser.add_argument('-k', '--key', help='Key for cipher')
    parser.add_argument('-s', '--shift', type=int, default=3, help='Shift for Caesar')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    tools = CryptoTools()
    
    # Baca input
    if args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    else:
        text = args.text
    
    if args.action == 'analyze':
        # Frequency analysis
        freq = tools.frequency_analysis(text)
        print("Frequency Analysis:")
        for c, p in freq.items():
            print(f"{c}: {p:.2f}%")
        
        # Coba deteksi encoding
        results = tools.detect_encoding(text)
        if results:
            print("\nPossible encodings:")
            for enc, decoded in results:
                print(f"{enc}: {decoded[:100]}...")
    
    elif args.action == 'caesar':
        if args.shift:
            result = tools.caesar(text, args.shift)
            print(f"Caesar (shift={args.shift}):\n{result}")
            
            # Coba semua shift
            print("\nAll shifts:")
            for s in range(26):
                print(f"Shift {s:2d}: {tools.caesar(text, s)[:50]}")
    
    elif args.action == 'xor':
        if args.key:
            result = tools.xor(text, args.key)
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(result)
                print(f"Saved to {args.output}")
            else:
                try:
                    print(result.decode())
                except:
                    print(result.hex())
    
    elif args.action == 'vigenere':
        if args.key:
            result = tools.vigenere(text, args.key)
            print(f"Vigenere:\n{result}")
    
    elif args.action == 'rot47':
        result = tools.rot47(text)
        print(f"ROT47:\n{result}")
    
    elif args.action == 'crack':
        result = tools.hash_crack(text)
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()