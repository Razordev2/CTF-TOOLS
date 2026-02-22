#!/usr/bin/env python3
"""
REVERSE ENGINEERING TOOLS - Untuk CTF Reverse Engineering
"""

import argparse
import struct
import binascii
import string
import os
from elftools.elf.elffile import ELFFile
import pefile

class RETools:
    def __init__(self):
        self.ascii = string.printable
        
    def extract_strings(self, filepath, min_length=4):
        """Ekstrak string ASCII dari binary"""
        strings = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        current = []
        for b in data:
            if 32 <= b <= 126:  # ASCII printable
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    def analyze_elf(self, filepath):
        """Analisis ELF file"""
        info = {'sections': [], 'symbols': [], 'imports': []}
        
        with open(filepath, 'rb') as f:
            elffile = ELFFile(f)
            
            info['type'] = elffile.header['e_type']
            info['machine'] = elffile.header['e_machine']
            info['entry'] = hex(elffile.header['e_entry'])
            
            # Sections
            for section in elffile.iter_sections():
                if section.name:
                    info['sections'].append({
                        'name': section.name,
                        'addr': hex(section['sh_addr']),
                        'size': section['sh_size']
                    })
            
            # Symbols
            if elffile.has_dwarf_info():
                dwarfinfo = elffile.get_dwarf_info()
                for CU in dwarfinfo.iter_CUs():
                    for die in CU.iter_DIEs():
                        if die.tag == 'DW_TAG_subprogram':
                            name = die.attributes.get('DW_AT_name')
                            if name:
                                info['symbols'].append(name.value.decode())
        
        return info
    
    def analyze_pe(self, filepath):
        """Analisis PE file (Windows)"""
        info = {'sections': [], 'imports': [], 'exports': []}
        
        pe = pefile.PE(filepath)
        
        info['machine'] = hex(pe.FILE_HEADER.Machine)
        info['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        
        # Sections
        for section in pe.sections:
            info['sections'].append({
                'name': section.Name.decode().rstrip('\x00'),
                'virt_addr': hex(section.VirtualAddress),
                'virt_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData
            })
        
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode()
                for imp in entry.imports:
                    if imp.name:
                        info['imports'].append(f"{dll}:{imp.name.decode()}")
        
        return info
    
    def disassemble_x86(self, data, arch='x86'):
        """Disassemble x86/x64 (simplified)"""
        from capstone import *
        
        if arch == 'x86':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        instructions = []
        for i in md.disasm(data, 0x1000):
            instructions.append({
                'address': hex(i.address),
                'mnemonic': i.mnemonic,
                'op_str': i.op_str
            })
        
        return instructions
    
    def patch_binary(self, filepath, offset, new_bytes, output=None):
        """Patch binary pada offset tertentu"""
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        # Patch
        for i, b in enumerate(new_bytes):
            if isinstance(b, str):
                b = ord(b)
            data[offset + i] = b
        
        # Simpan
        outfile = output if output else filepath + '.patched'
        with open(outfile, 'wb') as f:
            f.write(data)
        
        return outfile
    
    def find_rop_gadgets(self, filepath):
        """Cari ROP gadgets (sederhana)"""
        gadgets = []
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Cari pola ret (0xC3) dan pop (0x58-0x5F)
        for i in range(len(data) - 2):
            if data[i] == 0xC3:  # ret
                # Cari instruction sebelum ret
                for j in range(max(0, i-10), i):
                    if 0x58 <= data[j] <= 0x5F:  # pop r32
                        gadgets.append({
                            'address': hex(j),
                            'gadget': f"pop + ret",
                            'bytes': data[j:i+1].hex()
                        })
        
        return gadgets

def main():
    parser = argparse.ArgumentParser(description='Reverse Engineering Tools')
    parser.add_argument('action', choices=['strings', 'elf', 'pe', 'gadgets'])
    parser.add_argument('-f', '--file', required=True, help='Target file')
    parser.add_argument('-m', '--min', type=int, default=4,
                       help='Minimum string length')
    
    args = parser.parse_args()
    
    tools = RETools()
    
    if args.action == 'strings':
        strings = tools.extract_strings(args.file, args.min)
        for s in strings:
            print(s)
    
    elif args.action == 'elf':
        try:
            info = tools.analyze_elf(args.file)
            print(json.dumps(info, indent=2))
        except Exception as e:
            print(f"Error: {e}")
    
    elif args.action == 'pe':
        try:
            info = tools.analyze_pe(args.file)
            print(json.dumps(info, indent=2))
        except Exception as e:
            print(f"Error: {e}")
    
    elif args.action == 'gadgets':
        gadgets = tools.find_rop_gadgets(args.file)
        for g in gadgets[:50]:  # Limit 50
            print(f"{g['address']}: {g['gadget']} [{g['bytes']}]")

if __name__ == "__main__":
    main()