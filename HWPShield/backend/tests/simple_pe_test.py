"""
Simple PE Detection Test
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from utils.pe_analyzer import PEAnalyzer
    from utils.rule_based_analyzer import RuleBasedThreatAnalyzer
    print("✅ Imports successful")
    
    # Test 1: MZ without PE
    print("\n🔍 Testing MZ without PE structure...")
    mz_only = b'MZ' + b'A' * 1000
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(mz_only)
    print(f"   Threat Level: {pe_analysis['threat_level']}")
    print(f"   Valid PEs: {pe_analysis['valid_pe_count']}")
    print(f"   False Positives: {pe_analysis['false_positive_count']}")
    print(f"   Reason: {pe_analysis['reason']}")
    
    # Test 2: Multiple MZ patterns
    print("\n🔍 Testing Multiple MZ patterns...")
    multi_mz = b'MZ' + b'A' * 100 + b'MZ' + b'B' * 100 + b'MZ' + b'C' * 100
    pe_analysis = PEAnalyzer.analyze_exe_embeddings(multi_mz)
    print(f"   Threat Level: {pe_analysis['threat_level']}")
    print(f"   Total MZ: {pe_analysis['total_mz_signatures']}")
    print(f"   False Positives: {pe_analysis['false_positive_count']}")
    
    # Test 3: Rule-based analyzer
    print("\n🔍 Testing Rule-based Analyzer...")
    analyzer = RuleBasedThreatAnalyzer()
    parse_result = {'streams': {'TestData': multi_mz}}
    analysis = analyzer.analyze(parse_result, 'HWP')
    print(f"   Risk Level: {analysis['risk_level']}")
    print(f"   Score: {analysis['score']}")
    print(f"   Threats: {len(analysis['threats'])}")
    
    for threat in analysis['threats']:
        print(f"   - {threat['type']}: {threat['description']}")
    
    print("\n✅ Test Complete!")
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
