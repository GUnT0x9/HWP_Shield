#!/usr/bin/env python3
"""Create test files and run debug analysis"""
import struct
import os

print("[*] Creating test files...")

# Test 1: EPS exploit pattern
eps_test = bytearray()
header = bytearray(512)
header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
header[48:52] = struct.pack('<I', 1)
header[52:56] = struct.pack('<I', 0)
eps_test.extend(header)

fat = bytearray(512)
fat[0:4] = struct.pack('<I', 0xFFFFFFFE)
fat[4:8] = struct.pack('<I', 0xFFFFFFFE)
eps_test.extend(fat)

dir = bytearray(512)
root = bytearray(128)
root[0:20] = b"R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00"
root[64:66] = struct.pack('<H', 11)
root[66:67] = b'\x05'
root[76:80] = struct.pack('<I', 1)
dir[0:128] = root

eps_entry = bytearray(128)
eps_entry[0:24] = b'B\x00I\x00N\x000\x000\x000\x001\x00.\x00e\x00p\x00s\x00'
eps_entry[64:66] = struct.pack('<H', 10)
eps_entry[66:67] = b'\x02'
eps_entry[116:120] = struct.pack('<I', 1)
eps_entry[120:124] = struct.pack('<I', 512)
dir[128:256] = eps_entry
eps_test.extend(dir)

eps_content = b'''%!PS-Adobe-3.1 EPSF-3.0
%%BoundingBox: 0 0 100 100
%%Title: TEST FILE FOR SCANNER

% Scanner test patterns (harmless):
eqproc
test_execute_command
system_test

%%EOF
'''
eps_stream = bytearray(512)
eps_stream[0:len(eps_content)] = eps_content
eps_test.extend(eps_stream)

with open('test_eps_exploit.hwp', 'wb') as f:
    f.write(eps_test)
print(f"[+] Created: test_eps_exploit.hwp ({len(eps_test)} bytes)")

# Test 2: EXE dropper pattern
exe_test = bytearray()
header2 = bytearray(512)
header2[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
header2[48:52] = struct.pack('<I', 1)
header2[52:56] = struct.pack('<I', 0)
exe_test.extend(header2)

fat2 = bytearray(512)
fat2[0:4] = struct.pack('<I', 0xFFFFFFFE)
fat2[4:8] = struct.pack('<I', 0xFFFFFFFE)
exe_test.extend(fat2)

dir2 = bytearray(512)
root2 = bytearray(128)
root2[0:20] = b"R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00"
root2[64:66] = struct.pack('<H', 11)
root2[66:67] = b'\x05'
root2[76:80] = struct.pack('<I', 1)
dir2[0:128] = root2

ole_entry = bytearray(128)
ole_entry[0:12] = b'\x01Ole10Native'
ole_entry[66:67] = b'\x02'
ole_entry[116:120] = struct.pack('<I', 1)
ole_entry[120:124] = struct.pack('<I', 1024)
dir2[128:256] = ole_entry
exe_test.extend(dir2)

ole_stream = bytearray(1024)
ole_stream[0:2] = b'MZ'
fake = b'TEST - NOT REAL EXE - FOR SCANNER TEST - '
ole_stream[2:2+len(fake)] = fake
temp_ref = b'%TEMP%\\test_dropper.txt'
ole_stream[400:400+len(temp_ref)] = temp_ref
exe_test.extend(ole_stream)

with open('test_exe_dropper.hwp', 'wb') as f:
    f.write(exe_test)
print(f"[+] Created: test_exe_dropper.hwp ({len(exe_test)} bytes)")

# Now run debug analysis
print("\n[*] Running debug analysis...")

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_scanner import analyze_file, OLEParser
from improved_analyzer import ImprovedThreatAnalyzer

def debug_file(filepath):
    print(f"\n{'='*60}")
    print(f"DEBUG: {filepath}")
    print(f"{'='*60}")
    
    if not os.path.exists(filepath):
        print(f"[!] File not found")
        return
    
    size = os.path.getsize(filepath)
    print(f"[*] Size: {size} bytes")
    
    with open(filepath, 'rb') as f:
        magic = f.read(8)
    print(f"[*] Magic: {magic.hex()}")
    
    parser = OLEParser(filepath)
    result, error = parser.parse()
    
    if error:
        print(f"[!] Parse error: {error}")
        return
    
    print(f"[+] Parse OK!")
    print(f"[*] Streams: {list(result.get('streams', {}).keys())}")
    print(f"[*] has_eps: {result.get('has_eps')}")
    print(f"[*] has_macro: {result.get('has_macro')}")
    print(f"[*] ole_objects: {len(result.get('ole_objects', []))}")
    
    for obj in result.get('ole_objects', []):
        print(f"    OLE: {obj}")
    
    # Check stream contents
    print("\n[*] Stream contents check:")
    for name, data in result.get('streams', {}).items():
        print(f"  {name}: {len(data)} bytes")
        if b'%!PS-Adobe' in data:
            print("    -> PS-Adobe found!")
        if b'eqproc' in data:
            print("    -> eqproc found!")
        if b'execute' in data:
            print("    -> execute found!")
        if b'MZ' in data:
            print("    -> MZ found!")
        if b'%TEMP%' in data:
            print("    -> TEMP found!")
    
    # Threat analysis
    print("\n[*] Threat analysis:")
    analyzer = ImprovedThreatAnalyzer()
    threat = analyzer.analyze(result, 'HWP')
    print(f"  Score: {threat['score']}")
    print(f"  Risk: {threat['risk_level']}")
    print(f"  Threats: {len(threat['threats'])}")
    for t in threat['threats']:
        print(f"    - {t['type']} ({t['category']}): {t['description']}")
    
    # Full analysis
    print("\n[*] Full result:")
    full = analyze_file(filepath)
    print(f"  Risk: {full['overall_risk']}")
    print(f"  Score: {full['risk_score']}")

# Test both
for f in ['test_eps_exploit.hwp', 'test_exe_dropper.hwp']:
    debug_file(f)

print("\n[!] DISCLAIMER: These are SAFE test files with suspicious patterns.")
