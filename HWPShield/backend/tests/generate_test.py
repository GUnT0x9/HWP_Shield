#!/usr/bin/env python3
"""Generate test malicious HWP files for scanner testing"""
import struct
import os

# Create test_files directory
test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
os.makedirs(test_dir, exist_ok=True)

# Test 1: EPS exploit pattern test file
eps_test = bytearray()

# OLE Header (512 bytes)
header = bytearray(512)
header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE magic
header[48:52] = struct.pack('<I', 1)  # FAT count
header[52:56] = struct.pack('<I', 0)  # First directory sector
header[60:64] = struct.pack('<I', 4096)  # Mini stream cutoff
eps_test.extend(header)

# FAT sector
fat = bytearray(512)
fat[0:4] = struct.pack('<I', -2)  # FATSECT
fat[4:8] = struct.pack('<I', -2)  # End chain for sector 1
eps_test.extend(fat)

# Directory sector
dir = bytearray(512)
# Root entry
root = bytearray(128)
root[0:20] = b"R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00"
root[64:66] = struct.pack('<H', 11)
root[66:67] = b'\x05'  # Root storage
root[76:80] = struct.pack('<I', 1)  # Child
dir[0:128] = root

# EPS entry (BIN0001)
eps_entry = bytearray(128)
eps_entry[0:24] = b'B\x00I\x00N\x000\x000\x000\x001\x00.\x00e\x00p\x00s\x00'  # BIN0001.eps in UTF-16-LE
eps_entry[64:66] = struct.pack('<H', 10)
eps_entry[66:67] = b'\x02'  # Stream
eps_entry[116:120] = struct.pack('<I', 1)  # Start sector
eps_entry[120:124] = struct.pack('<I', 512)  # Size
dir[128:256] = eps_entry
eps_test.extend(dir)

# EPS stream with suspicious patterns
# Contains keywords that scanner looks for: eqproc, execute, system
eps_content = b'''%!PS-Adobe-3.1 EPSF-3.0
%%BoundingBox: 0 0 100 100
%%Title: TEST FILE - Scanner Detection Test
%%Creator: HWPShield Test
%%Purpose: Verify scanner detects EPS exploit patterns safely

% Test patterns (non-functional):
eqproc
test_execute_command
system_test_string

%%EOF
'''
eps_stream = bytearray(512)
eps_stream[0:len(eps_content)] = eps_content
eps_test.extend(eps_stream)

# Save EPS test file
eps_path = os.path.join(test_dir, 'test_eps_exploit.hwp')
with open(eps_path, 'wb') as f:
    f.write(eps_test)
print(f"[+] Created EPS test file: {eps_path}")
print(f"    Size: {len(eps_test)} bytes")
print(f"    Expected: CRITICAL (EPS with exploit keywords)")

# Test 2: EXE dropper test file
exe_test = bytearray()

# OLE Header
header2 = bytearray(512)
header2[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
header2[48:52] = struct.pack('<I', 1)
header2[52:56] = struct.pack('<I', 0)
exe_test.extend(header2)

# FAT
fat2 = bytearray(512)
fat2[0:4] = struct.pack('<I', -2)
fat2[4:8] = struct.pack('<I', -2)
exe_test.extend(fat2)

# Directory
dir2 = bytearray(512)
root2 = bytearray(128)
root2[0:20] = b"R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00"
root2[64:66] = struct.pack('<H', 11)
root2[66:67] = b'\x05'
root2[76:80] = struct.pack('<I', 1)
dir2[0:128] = root2

# Ole10Native entry with fake EXE
ole_entry = bytearray(128)
# Marker with 0x01 prefix then Ole10Native
ole_entry[0:12] = b'\x01\x00\x00\x00Ole10Native'
ole_entry[66:67] = b'\x02'
ole_entry[116:120] = struct.pack('<I', 1)
ole_entry[120:124] = struct.pack('<I', 1024)
dir2[128:256] = ole_entry
exe_test.extend(dir2)

# Ole10Native stream with fake "EXE" data
# Starts with MZ but followed by harmless text
ole_stream = bytearray(1024)
ole_stream[0:2] = b'MZ'  # Fake EXE magic
# Add harmless data
fake_exe = b'TEST FILE - NOT A REAL EXECUTABLE - FOR SCANNER TESTING - ' * 30
ole_stream[2:2+len(fake_exe)] = fake_exe

# Add %TEMP% reference for dropper detection
temp_ref = b'%TEMP%\\test_dropper.txt - TEMP path for testing'
ole_stream[400:400+len(temp_ref)] = temp_ref

exe_test.extend(ole_stream)

# Save EXE dropper test file
exe_path = os.path.join(test_dir, 'test_exe_dropper.hwp')
with open(exe_path, 'wb') as f:
    f.write(exe_test)
print(f"\n[+] Created EXE dropper test file: {exe_path}")
print(f"    Size: {len(exe_test)} bytes")
print(f"    Expected: CRITICAL (MZ header + TEMP path)")

print(f"\n[!] DISCLAIMER: These are TEST files with suspicious PATTERNS.")
print(f"    They are NOT actual malware and cannot harm your system.")
print(f"    Use them only to verify the scanner's detection capabilities.")
