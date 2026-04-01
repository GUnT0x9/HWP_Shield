#!/usr/bin/env python3
"""Debug test file parsing"""
import sys
import os

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_scanner import analyze_file, OLEParser
from improved_analyzer import ImprovedThreatAnalyzer
import json

def debug_file(filepath):
    print(f"\n{'='*60}")
    print(f"DEBUGGING: {filepath}")
    print(f"{'='*60}")
    
    # Check file exists
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return
    
    # Check file size
    size = os.path.getsize(filepath)
    print(f"[*] File size: {size} bytes")
    
    # Read and check magic
    with open(filepath, 'rb') as f:
        magic = f.read(8)
    ole_magic = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    print(f"[*] Magic bytes: {magic.hex()}")
    print(f"[*] Is OLE: {magic[:8] == ole_magic}")
    
    # Try parsing
    print(f"\n[*] Parsing with OLEParser...")
    parser = OLEParser(filepath)
    result, error = parser.parse()
    
    if error:
        print(f"[!] Parse error: {error}")
        return
    
    print(f"[+] Parse successful!")
    print(f"[*] Streams found: {list(result.get('streams', {}).keys())}")
    print(f"[*] has_eps: {result.get('has_eps', False)}")
    print(f"[*] has_macro: {result.get('has_macro', False)}")
    print(f"[*] ole_objects: {len(result.get('ole_objects', []))}")
    
    for i, obj in enumerate(result.get('ole_objects', [])):
        print(f"    OLE Object {i}: {obj}")
    
    # Check raw data in streams
    print(f"\n[*] Checking stream contents:")
    for name, data in result.get('streams', {}).items():
        print(f"  Stream '{name}': {len(data)} bytes")
        if b'%!PS-Adobe' in data:
            print(f"    -> Found PS-Adobe header!")
        if b'eqproc' in data:
            print(f"    -> Found 'eqproc' keyword!")
        if b'execute' in data:
            print(f"    -> Found 'execute' keyword!")
        if b'MZ' in data:
            print(f"    -> Found MZ header!")
        if b'%TEMP%' in data:
            print(f"    -> Found TEMP path!")
    
    # Try threat analysis
    print(f"\n[*] Running threat analysis...")
    analyzer = ImprovedThreatAnalyzer()
    threat_result = analyzer.analyze(result, 'HWP')
    
    print(f"[*] Score: {threat_result['score']}")
    print(f"[*] Risk: {threat_result['risk_level']}")
    print(f"[*] Threats found: {len(threat_result['threats'])}")
    
    for t in threat_result['threats']:
        print(f"    - {t['type']} ({t['category']}): {t['description']}")
    
    # Full analysis
    print(f"\n[*] Full analysis result:")
    full_result = analyze_file(filepath)
    print(f"  overall_risk: {full_result['overall_risk']}")
    print(f"  risk_score: {full_result['risk_score']}")

if __name__ == '__main__':
    # Test both files
    files = ['test_eps_exploit.hwp', 'test_exe_dropper.hwp']
    for f in files:
        if os.path.exists(f):
            debug_file(f)
        else:
            print(f"[!] File not found: {f}")
