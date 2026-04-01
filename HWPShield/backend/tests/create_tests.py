#!/usr/bin/env python3
"""Generate test files in current directory"""
import struct
import os

# Test 1: EPS exploit pattern
eps_test = bytearray()

# OLE Header (512 bytes)
header = bytearray(512)
header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
header[48:52] = struct.pack('<I', 1)
header[52:56] = struct.pack('<I', 0)
eps_test.extend(header)

# FAT sector
fat = bytearray(512)
fat[0:4] = struct.pack('<I', 0xFFFFFFFE)  # FATSECT (-2 as unsigned)
fat[4:8] = struct.pack('<I', 0xFFFFFFFE)  # End of chain
eps_test.extend(fat)

# Directory with EPS entry
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

# EPS stream with test patterns
eps_content = b'''%!PS-Adobe-3.1 EPSF-3.0
%%BoundingBox: 0 0 100 100
%%Title: TEST FILE

% Scanner test patterns:
eqproc
test_execute
system

%%EOF
'''
eps_stream = bytearray(512)
eps_stream[0:len(eps_content)] = eps_content
eps_test.extend(eps_stream)

with open('test_eps_exploit.hwp', 'wb') as f:
    f.write(eps_test)
print("Created: test_eps_exploit.hwp - Should trigger CRITICAL (EPS patterns)")

# Test 2: EXE dropper pattern
exe_test = bytearray()
header2 = bytearray(512)
header2[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
header2[48:52] = struct.pack('<I', 1)
header2[52:56] = struct.pack('<I', 0)
exe_test.extend(header2)

fat2 = bytearray(512)
fat2[0:4] = struct.pack('<I', 0xFFFFFFFE)  # FATSECT
fat2[4:8] = struct.pack('<I', 0xFFFFFFFE)  # End of chain
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
fake = b'TEST FILE - NOT REAL EXE - FOR SCANNER TESTING - '
ole_stream[2:2+len(fake)] = fake
temp_ref = b'%TEMP%\\test.txt'
ole_stream[400:400+len(temp_ref)] = temp_ref
exe_test.extend(ole_stream)

with open('test_exe_dropper.hwp', 'wb') as f:
    f.write(exe_test)
print("Created: test_exe_dropper.hwp - Should trigger CRITICAL (MZ + TEMP)")

print("\n[!] DISCLAIMER: These are SAFE test files with suspicious PATTERNS only.")
print("    They are NOT actual malware. Use only for scanner testing.")
