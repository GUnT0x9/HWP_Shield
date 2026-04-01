"""
Quick Scanner Test
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from enhanced_scanner import analyze_file
    
    print("🔍 Quick Scanner Test")
    print("=" * 40)
    
    # Test 1: Benign file (MZ patterns only)
    print("\n1. Testing MZ patterns only (should be CLEAN)...")
    benign_data = b'MZ' + b'A' * 100 + b'MZ' + b'B' * 100
    with open('test_benign.hwp', 'wb') as f:
        f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + benign_data)
    
    result = analyze_file('test_benign.hwp')
    print(f"   Result: {result.get('overall_risk', 'ERROR')}")
    print(f"   Score: {result.get('risk_score', 0)}")
    print(f"   Threats: {len(result.get('threats', []))}")
    
    # Test 2: Malicious file (real PE)
    print("\n2. Testing real PE (should be MALICIOUS)...")
    # Simple PE structure
    pe_data = (
        b'MZ' + b'\x00' * 58 +  # DOS header
        b'\x80\x00\x00\x00' +  # e_lfanew
        b'\x00' * 12 +         # Padding
        b'PE\0\0' +           # PE signature
        b'\x4c\x01\x01\x00' + # COFF (i386, 1 section)
        b'\x70\x00\x00\x00' + # Optional header size
        b'\x0b\x01' +         # PE32 magic
        b'\x00\x20\x00\x00' + # Entry point
        b'.text\x00\x00\x00' + # Section name
        b'\x20\x00\x00\x60'   # Executable characteristics
    )
    
    with open('test_malicious.hwp', 'wb') as f:
        f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + pe_data)
    
    result = analyze_file('test_malicious.hwp')
    print(f"   Result: {result.get('overall_risk', 'ERROR')}")
    print(f"   Score: {result.get('risk_score', 0)}")
    print(f"   Threats: {len(result.get('threats', []))}")
    
    # Test 3: Suspicious file (EPS keywords)
    print("\n3. Testing EPS keywords (should be SUSPICIOUS)...")
    eps_data = b'eqproc\nexecute\nsystem\nShellExecute'
    with open('test_eps.hwp', 'wb') as f:
        f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + eps_data)
    
    result = analyze_file('test_eps.hwp')
    print(f"   Result: {result.get('overall_risk', 'ERROR')}")
    print(f"   Score: {result.get('risk_score', 0)}")
    print(f"   Threats: {len(result.get('threats', []))}")
    
    # Cleanup
    for f in ['test_benign.hwp', 'test_malicious.hwp', 'test_eps.hwp']:
        if os.path.exists(f):
            os.remove(f)
    
    print("\n✅ Quick test complete!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
