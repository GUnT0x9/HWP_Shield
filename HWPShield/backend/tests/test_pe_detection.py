"""
PE Detection Test Script
Tests the improved PE detection with various scenarios
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.pe_analyzer import PEAnalyzer
from utils.rule_based_analyzer import RuleBasedThreatAnalyzer

def test_pe_detection():
    """Test PE detection with various scenarios"""
    
    print("🔍 PE Detection Test Suite")
    print("=" * 50)
    
    # Test 1: Valid PE header (simulated)
    print("\n1. Testing Valid PE Structure")
    pe_data = create_mock_pe()
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(pe_data)
    print(f"   Result: {pe_analysis['threat_level']}")
    print(f"   Valid PEs: {pe_analysis['valid_pe_count']}")
    print(f"   Reason: {pe_analysis['reason']}")
    
    # Test 2: MZ without PE (false positive)
    print("\n2. Testing MZ without PE Structure")
    mz_only_data = b'MZ' + b'A' * 1000
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(mz_only_data)
    print(f"   Result: {pe_analysis['threat_level']}")
    print(f"   Valid PEs: {pe_analysis['valid_pe_count']}")
    print(f"   False Positives: {pe_analysis['false_positive_count']}")
    
    # Test 3: Multiple MZ patterns
    print("\n3. Testing Multiple MZ Patterns")
    multi_mz = b'MZ' + b'A' * 100 + b'MZ' + b'B' * 100 + b'MZ' + b'C' * 100
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(multi_mz)
    print(f"   Result: {pe_analysis['threat_level']}")
    print(f"   Total MZ: {pe_analysis['total_mz_signatures']}")
    print(f"   False Positives: {pe_analysis['false_positive_count']}")
    
    # Test 4: Compressed data simulation
    print("\n4. Testing Compressed-like Data")
    compressed_sim = b'MZ' + b'\x00\x01\x02\x03' * 250  # Simulated compressed data
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(compressed_sim)
    print(f"   Result: {pe_analysis['threat_level']}")
    print(f"   Valid PEs: {pe_analysis['valid_pe_count']}")
    
    # Test 5: Rule-based analyzer integration
    print("\n5. Testing Rule-based Analyzer Integration")
    analyzer = RuleBasedThreatAnalyzer()
    
    # Mock parse result
    parse_result = {
        'streams': {
            'TestData': pe_data + mz_only_data  # Mix of valid and false positives
        }
    }
    
    analysis = analyzer.analyze(parse_result, 'HWP')
    print(f"   Overall Risk: {analysis['risk_level']}")
    print(f"   Total Score: {analysis['score']}")
    print(f"   Threats: {len(analysis['threats'])}")
    
    for threat in analysis['threats']:
        print(f"   - {threat['type']}: {threat['description']} (Score: {threat['score']})")
    
    print("\n✅ Test Complete!")

def create_mock_pe() -> bytes:
    """Create a mock PE structure for testing"""
    # DOS header
    dos_header = b'MZ' + b'\x00' * 58
    e_lfanew = b'\x80\x00\x00\x00'  # PE header at offset 0x80
    
    # PE signature
    pe_sig = b'PE\0\0'
    
    # COFF header
    coff_header = (
        b'\x4c\x01'  # Machine (i386)
        b'\x01\x00'  # Number of sections
        b'\x00\x00\x00\x00'  # Timestamp
        b'\x00\x00\x00\x00'  # Symbol table pointer
        b'\x00\x00\x00\x00'  # Number of symbols
        b'\x70\x00\x00\x00'  # Optional header size
        b'\x03\x00'  # Characteristics
    )
    
    # Optional header (PE32)
    opt_header = (
        b'\x0b\x01'  # Magic (PE32)
        b'\x08\x00\x00\x00'  # Linker version
        b'\x00\x10\x00\x00'  # Size of code
        b'\x00\x10\x00\x00'  # Size of initialized data
        b'\x00\x00\x00\x00'  # Size of uninitialized data
        b'\x00\x20\x00\x00'  # Entry point
        b'\x00\x20\x00\x00'  # Base of code
        b'\x00\x00\x00\x00'  # Base of data
    )
    
    # Section header
    section_header = (
        b'.text\x00\x00\x00'  # Name
        b'\x00\x10\x00\x00'  # Virtual size
        b'\x00\x20\x00\x00'  # Virtual address
        b'\x00\x10\x00\x00'  # Size of raw data
        b'\x00\x40\x00\x00'  # Pointer to raw data
        b'\x00\x00\x00\x00'  # Pointer to relocations
        b'\x00\x00\x00\x00'  # Pointer to line numbers
        b'\x00\x00\x00\x00'  # Number of relocations
        b'\x00\x00\x00\x00'  # Number of line numbers
        b'\x20\x00\x00\x60'  # Characteristics (code, executable)
    )
    
    # Combine all parts
    pe_data = (
        dos_header +  # 60 bytes
        e_lfanew +   # 4 bytes
        b'\x00' * 12 +  # Padding to reach PE header at 0x80
        pe_sig +     # 4 bytes
        coff_header + # 24 bytes
        opt_header + # 96 bytes
        section_header  # 40 bytes
    )
    
    return pe_data

if __name__ == '__main__':
    test_pe_detection()
