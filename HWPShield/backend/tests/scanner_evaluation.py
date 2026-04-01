"""
HWPShield Scanner Performance Evaluation Suite
Tests false positive rate, detection rate, and security stability
"""
import os
import sys
import time
import json
import hashlib
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict

# Add path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_scanner import analyze_file
from utils.pe_analyzer import PEAnalyzer
from utils.rule_based_analyzer import RuleBasedThreatAnalyzer

@dataclass
class TestCase:
    """Test case for evaluation"""
    name: str
    file_path: str
    expected_result: str  # CLEAN, SUSPICIOUS, HIGH_RISK, MALICIOUS
    description: str
    category: str  # benign, malware, suspicious

@dataclass
class TestResult:
    """Test result"""
    test_case: TestCase
    actual_result: str
    score: int
    execution_time: float
    threats: List[Dict]
    indicators: List[Dict]
    is_correct: bool
    false_positive: bool
    false_negative: bool

class ScannerEvaluator:
    """Comprehensive scanner performance evaluator"""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.stats = defaultdict(int)
        
    def create_test_samples(self) -> List[TestCase]:
        """Create comprehensive test samples"""
        test_cases = []
        
        # 1. Benign HWP files (should be CLEAN)
        benign_cases = [
            TestCase("Empty HWP", "test_empty.hwp", "CLEAN", "Empty HWP document", "benign"),
            TestCase("Normal Text", "test_text.hwp", "CLEAN", "HWP with text only", "benign"),
            TestCase("Images Only", "test_images.hwp", "CLEAN", "HWP with images only", "benign"),
            TestCase("Compressed Data", "test_compressed.hwp", "CLEAN", "HWP with compressed streams", "benign"),
            TestCase("MZ Patterns Only", "test_mz_only.hwp", "CLEAN", "HWP with MZ patterns but no PE", "benign"),
        ]
        
        # 2. Suspicious HWP files
        suspicious_cases = [
            TestCase("EPS Keywords", "test_eps.hwp", "SUSPICIOUS", "HWP with EPS keywords", "suspicious"),
            TestCase("External Links", "test_links.hwp", "SUSPICIOUS", "HWP with external URLs", "suspicious"),
            TestCase("Temp References", "test_temp.hwp", "SUSPICIOUS", "HWP with %TEMP% references", "suspicious"),
            TestCase("Multiple MZ", "test_multi_mz.hwp", "SUSPICIOUS", "HWP with multiple MZ patterns", "suspicious"),
        ]
        
        # 3. Malicious HWP files
        malicious_cases = [
            TestCase("Real EXE", "test_real_exe.hwp", "MALICIOUS", "HWP with embedded EXE", "malware"),
            TestCase("EPS Exploit", "test_eps_exploit.hwp", "MALICIOUS", "HWP with EPS exploit", "malware"),
            TestCase("Macro + EXE", "test_macro_exe.hwp", "MALICIOUS", "HWP with macro and EXE", "malware"),
            TestCase("Dropper", "test_dropper.hwp", "MALICIOUS", "HWP dropper with temp execution", "malware"),
        ]
        
        test_cases.extend(benign_cases)
        test_cases.extend(suspicious_cases) 
        test_cases.extend(malicious_cases)
        
        return test_cases
    
    def create_mock_hwp(self, filename: str, content_type: str) -> bytes:
        """Create mock HWP file for testing"""
        # Basic OLE header
        ole_header = (
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE magic
            b'\x00\x00\x00\x00' * 8  # Version and other fields
            b'\x00\x00\x00\x00' * 4  # Sector count
            b'\xfe\xff\xff\xff'  # First directory sector
            b'\x00\x00\x00\x00' * 3  # Other fields
            b'\x00\x00\x04\x00'  # Mini stream cutoff (1024)
        )
        
        # Add content based on type
        if content_type == "empty":
            content = b''
        elif content_type == "text":
            content = b'This is normal text content in HWP format.' * 50
        elif content_type == "images":
            # Simulate image data with MZ patterns (false positive)
            content = b'\x89PNG' + b'MZ' + b'A' * 1000 + b'IEND'
        elif content_type == "compressed":
            # Simulate compressed data with random patterns
            import random
            content = bytes([random.randint(0, 255) for _ in range(2000)])
            # Add some MZ patterns randomly
            content = content.replace(b'MZ', b'MZ', 5)
        elif content_type == "mz_only":
            # Multiple MZ patterns without PE structure
            content = b'MZ' + b'A' * 100 + b'MZ' + b'B' * 100 + b'MZ' + b'C' * 100
        elif content_type == "eps":
            # EPS exploit patterns
            content = (
                b'%!PS-Adobe-3.0 EPSF-3.0\n'
                b'%%BoundingBox: 0 0 100 100\n'
                b'/findfont /def begin\n'
                b'eqproc\n'
                b'execute\n'
                b'system\n'
                b'end\n'
            )
        elif content_type == "links":
            # External URLs
            content = (
                b'Visit http://malicious.com/payload.exe\n'
                b'And https://evil.site/scan.html\n'
            )
        elif content_type == "temp":
            # Temp path references
            content = (
                b'Execute %TEMP%\\payload.exe\n'
                b'Write to %TEMP%\\malware.dll\n'
                b'Create file in temp directory\n'
            )
        elif content_type == "multi_mz":
            # Many MZ patterns
            content = b''
            for i in range(10):
                content += b'MZ' + f'Pattern{i}'.encode() * 50
        elif content_type == "real_exe":
            # Create a simple PE executable
            pe_content = self.create_simple_pe()
            content = pe_content
        elif content_type == "eps_exploit":
            # EPS exploit with more patterns
            content = (
                b'%!PS-Adobe-3.0\n'
                b'%%BoundingBox: 0 0 612 792\n'
                b'/Helvetica findfont 12 scalefont setfont\n'
                b'100 700 moveto (Document) show\n'
                b'eqproc\n'
                b'execute\n'
                b'system\n'
                b'ShellExecute\n'
                b'powershell\n'
                b'cmd.exe\n'
            )
        elif content_type == "macro_exe":
            # Macro + EXE combination
            content = (
                b'\x01Script\x00'  # Macro storage marker
                b'MZ' + self.create_simple_pe()  # Embedded EXE
                b'powershell -c "Invoke-Expression"\n'
            )
        elif content_type == "dropper":
            # Dropper with temp execution
            content = (
                b'%TEMP%\\dropper.exe\n'
                b'ShellExecute\n'
                b'MZ' + self.create_simple_pe()
                b'URLDownloadToFile\n'
                b'CreateProcess\n'
            )
        else:
            content = b'Default content'
        
        # Combine into complete HWP structure
        hwp_content = ole_header + content
        
        # Pad to minimum size
        if len(hwp_content) < 1024:
            hwp_content += b'\x00' * (1024 - len(hwp_content))
        
        return hwp_content
    
    def create_simple_pe(self) -> bytes:
        """Create a simple PE executable for testing"""
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
        pe_content = (
            dos_header + e_lfanew + b'\x00' * 12 +  # Padding to PE header
            pe_sig + coff_header + opt_header + section_header
        )
        
        return pe_content
    
    def run_single_test(self, test_case: TestCase) -> TestResult:
        """Run single test case"""
        # Create test file
        content_type = test_case.name.lower().replace(" ", "_")
        test_data = self.create_mock_hwp(test_case.file_path, content_type)
        
        # Save to temp file
        temp_path = f"temp_{test_case.file_path}"
        with open(temp_path, 'wb') as f:
            f.write(test_data)
        
        try:
            # Run analysis
            start_time = time.time()
            analysis_result = analyze_file(temp_path)
            execution_time = time.time() - start_time
            
            # Extract results
            actual_result = analysis_result.get('overall_risk', 'ERROR')
            score = analysis_result.get('risk_score', 0)
            threats = analysis_result.get('threats', [])
            indicators = analysis_result.get('indicators', [])
            
            # Evaluate correctness
            is_correct = actual_result == test_case.expected_result
            false_positive = (test_case.category == "benign" and 
                            actual_result in ["SUSPICIOUS", "HIGH_RISK", "MALICIOUS"])
            false_negative = (test_case.category == "malware" and 
                            actual_result in ["CLEAN", "SUSPICIOUS"])
            
            return TestResult(
                test_case=test_case,
                actual_result=actual_result,
                score=score,
                execution_time=execution_time,
                threats=threats,
                indicators=indicators,
                is_correct=is_correct,
                false_positive=false_positive,
                false_negative=false_negative
            )
            
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    def run_evaluation(self) -> Dict[str, Any]:
        """Run complete evaluation"""
        print("🔍 HWPShield Scanner Performance Evaluation")
        print("=" * 60)
        
        test_cases = self.create_test_samples()
        print(f"Created {len(test_cases)} test cases")
        
        # Run tests
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n[{i}/{len(test_cases)}] Testing: {test_case.name}")
            result = self.run_single_test(test_case)
            self.results.append(result)
            
            # Print result
            status = "✅" if result.is_correct else "❌"
            print(f"   {status} Expected: {test_case.expected_result}, Got: {result.actual_result}")
            print(f"   Score: {result.score}, Time: {result.execution_time:.3f}s")
            
            if result.false_positive:
                print(f"   ⚠️ False Positive!")
            elif result.false_negative:
                print(f"   ⚠️ False Negative!")
        
        # Calculate statistics
        stats = self.calculate_statistics()
        
        # Print summary
        self.print_summary(stats)
        
        return stats
    
    def calculate_statistics(self) -> Dict[str, Any]:
        """Calculate performance statistics"""
        total_tests = len(self.results)
        correct_tests = sum(1 for r in self.results if r.is_correct)
        false_positives = sum(1 for r in self.results if r.false_positive)
        false_negatives = sum(1 for r in self.results if r.false_negative)
        
        # By category
        benign_tests = [r for r in self.results if r.test_case.category == "benign"]
        suspicious_tests = [r for r in self.results if r.test_case.category == "suspicious"]
        malware_tests = [r for r in self.results if r.test_case.category == "malware"]
        
        benign_correct = sum(1 for r in benign_tests if r.is_correct)
        suspicious_correct = sum(1 for r in suspicious_tests if r.is_correct)
        malware_correct = sum(1 for r in malware_tests if r.is_correct)
        
        # Performance metrics
        avg_time = sum(r.execution_time for r in self.results) / total_tests
        avg_score = sum(r.score for r in self.results) / total_tests
        
        # Detection rates
        true_positive_rate = malware_correct / len(malware_tests) if malware_tests else 0
        false_positive_rate = false_positives / len(benign_tests) if benign_tests else 0
        accuracy = correct_tests / total_tests
        
        return {
            "total_tests": total_tests,
            "accuracy": accuracy,
            "true_positive_rate": true_positive_rate,
            "false_positive_rate": false_positive_rate,
            "false_negatives": false_negatives,
            "avg_execution_time": avg_time,
            "avg_score": avg_score,
            "by_category": {
                "benign": {"total": len(benign_tests), "correct": benign_correct},
                "suspicious": {"total": len(suspicious_tests), "correct": suspicious_correct},
                "malware": {"total": len(malware_tests), "correct": malware_correct}
            }
        }
    
    def print_summary(self, stats: Dict[str, Any]):
        """Print evaluation summary"""
        print("\n" + "=" * 60)
        print("📊 PERFORMANCE SUMMARY")
        print("=" * 60)
        
        print(f"\n🎯 Overall Accuracy: {stats['accuracy']:.1%}")
        print(f"✅ True Positive Rate: {stats['true_positive_rate']:.1%}")
        print(f"❌ False Positive Rate: {stats['false_positive_rate']:.1%}")
        print(f"📉 False Negatives: {stats['false_negatives']}")
        
        print(f"\n⏱️  Average Execution Time: {stats['avg_execution_time']:.3f}s")
        print(f"📈 Average Score: {stats['avg_score']:.1f}")
        
        print(f"\n📋 Results by Category:")
        for category, data in stats['by_category'].items():
            accuracy = data['correct'] / data['total'] if data['total'] > 0 else 0
            print(f"   {category.capitalize()}: {data['correct']}/{data['total']} ({accuracy:.1%})")
        
        # Performance grade
        grade = self.calculate_performance_grade(stats)
        print(f"\n🏆 Performance Grade: {grade}")
        
        # Recommendations
        self.print_recommendations(stats)
    
    def calculate_performance_grade(self, stats: Dict[str, Any]) -> str:
        """Calculate overall performance grade"""
        accuracy = stats['accuracy']
        fpr = stats['false_positive_rate']
        tpr = stats['true_positive_rate']
        
        if accuracy >= 0.95 and fpr <= 0.05 and tpr >= 0.95:
            return "A+ (Excellent)"
        elif accuracy >= 0.90 and fpr <= 0.10 and tpr >= 0.90:
            return "A (Very Good)"
        elif accuracy >= 0.85 and fpr <= 0.15 and tpr >= 0.85:
            return "B (Good)"
        elif accuracy >= 0.75 and fpr <= 0.20 and tpr >= 0.75:
            return "C (Fair)"
        elif accuracy >= 0.60:
            return "D (Poor)"
        else:
            return "F (Very Poor)"
    
    def print_recommendations(self, stats: Dict[str, Any]):
        """Print improvement recommendations"""
        print(f"\n💡 RECOMMENDATIONS:")
        
        if stats['false_positive_rate'] > 0.10:
            print("   🔧 Reduce false positives:")
            print("      - Improve PE structure validation")
            print("      - Add more context checks for MZ patterns")
            print("      - Refine EPS exploit detection")
        
        if stats['true_positive_rate'] < 0.90:
            print("   🔍 Improve detection rate:")
            print("      - Add more malware patterns")
            print("      - Improve macro detection")
            print("      - Add obfuscation detection")
        
        if stats['avg_execution_time'] > 1.0:
            print("   ⚡ Improve performance:")
            print("      - Optimize parsing algorithms")
            print("      - Add caching for repeated patterns")
                print("      - Consider parallel processing")
        
        if stats['false_negatives'] > 0:
            print("   🛡️ Fix false negatives:")
            for result in self.results:
                if result.false_negative:
                    print(f"      - {result.test_case.name}: Expected {result.test_case.expected_result}, got {result.actual_result}")

if __name__ == '__main__':
    evaluator = ScannerEvaluator()
    stats = evaluator.run_evaluation()
    
    # Save results
    with open('scanner_evaluation_results.json', 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"\n📁 Detailed results saved to: scanner_evaluation_results.json")
