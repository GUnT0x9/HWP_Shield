"""
Security Stability Analysis for HWPShield
Analyzes potential security vulnerabilities and stability issues
"""
import os
import sys
import re
import ast
import subprocess
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass

@dataclass
class SecurityIssue:
    """Security issue found during analysis"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # INJECTION, OVERFLOW, XSS, PATH_TRAVERSAL, etc.
    description: str
    file: str
    line: int
    code_snippet: str
    recommendation: str

class SecurityAnalyzer:
    """Security stability analyzer for HWPShield"""
    
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.scan_patterns = self._get_security_patterns()
    
    def _get_security_patterns(self) -> Dict[str, List[Dict]]:
        """Get security vulnerability patterns to scan for"""
        return {
            "command_injection": [
                {
                    "pattern": r"os\.system\s*\(",
                    "severity": "CRITICAL",
                    "description": "Potential command injection"
                },
                {
                    "pattern": r"subprocess\.call\s*\(",
                    "severity": "HIGH", 
                    "description": "Potential command injection via subprocess"
                },
                {
                    "pattern": r"eval\s*\(",
                    "severity": "CRITICAL",
                    "description": "Code execution via eval()"
                },
                {
                    "pattern": r"exec\s*\(",
                    "severity": "CRITICAL",
                    "description": "Code execution via exec()"
                }
            ],
            "path_traversal": [
                {
                    "pattern": r"\.\./",
                    "severity": "HIGH",
                    "description": "Path traversal pattern"
                },
                {
                    "pattern": r"open\s*\([^)]*\+[^)]*\)",
                    "severity": "MEDIUM",
                    "description": "File path concatenation without validation"
                }
            ],
            "buffer_overflow": [
                {
                    "pattern": r"read\s*\([^)]*\,\s*[^)]*\,\s*[0-9]+\s*\)",
                    "severity": "MEDIUM",
                    "description": "Fixed-size buffer read"
                },
                {
                    "pattern": r"struct\.unpack.*\*",
                    "severity": "LOW",
                    "description": "Potential buffer overflow in struct unpack"
                }
            ],
            "injection_sql": [
                {
                    "pattern": r"execute\s*\([^)]*%[^)]*\)",
                    "severity": "HIGH",
                    "description": "SQL injection via string formatting"
                }
            ],
            "xss": [
                {
                    "pattern": r"innerHTML\s*=",
                    "severity": "HIGH",
                    "description": "XSS via innerHTML assignment"
                },
                {
                    "pattern": r"document\.write\s*\(",
                    "severity": "HIGH",
                    "description": "XSS via document.write"
                }
            ],
            "hardcoded_secrets": [
                {
                    "pattern": r"(password|secret|key|token)\s*=\s*['\"][^'\"]+['\"]",
                    "severity": "MEDIUM",
                    "description": "Hardcoded credentials or secrets"
                }
            ],
            "unsafe_deserialization": [
                {
                    "pattern": r"pickle\.loads?\s*\(",
                    "severity": "CRITICAL",
                    "description": "Unsafe pickle deserialization"
                },
                {
                    "pattern": r"yaml\.load\s*\(",
                    "severity": "HIGH",
                    "description": "Unsafe YAML loading"
                }
            ]
        }
    
    def scan_file(self, filepath: str) -> List[SecurityIssue]:
        """Scan single file for security issues"""
        issues = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for category, patterns in self.scan_patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info['pattern']
                    
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            issue = SecurityIssue(
                                severity=pattern_info['severity'],
                                category=category.upper(),
                                description=pattern_info['description'],
                                file=filepath,
                                line=line_num,
                                code_snippet=line.strip(),
                                recommendation=self._get_recommendation(category, pattern_info['description'])
                            )
                            issues.append(issue)
        
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")
        
        return issues
    
    def _get_recommendation(self, category: str, description: str) -> str:
        """Get security recommendation for issue"""
        recommendations = {
            "command_injection": "Use parameterized queries or proper input validation",
            "path_traversal": "Validate and sanitize file paths, use os.path.join()",
            "buffer_overflow": "Use bounds checking and safe string operations",
            "injection_sql": "Use parameterized queries or ORM",
            "xss": "Use proper output encoding and CSP headers",
            "hardcoded_secrets": "Use environment variables or secure configuration",
            "unsafe_deserialization": "Use safe serialization formats or validate input"
        }
        return recommendations.get(category, "Review and secure the implementation")
    
    def analyze_codebase(self, directory: str) -> Dict[str, Any]:
        """Analyze entire codebase for security issues"""
        print("🔒 Security Stability Analysis")
        print("=" * 50)
        
        # Find Python files
        python_files = []
        for root, dirs, files in os.walk(directory):
            # Skip venv and __pycache__
            dirs[:] = [d for d in dirs if d not in ['venv', '__pycache__', '.git']]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        print(f"Scanning {len(python_files)} Python files...")
        
        # Scan all files
        all_issues = []
        for filepath in python_files:
            print(f"  Scanning: {os.path.relpath(filepath, directory)}")
            issues = self.scan_file(filepath)
            all_issues.extend(issues)
        
        # Categorize issues
        issues_by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": []
        }
        
        issues_by_category = {}
        
        for issue in all_issues:
            issues_by_severity[issue.severity].append(issue)
            
            if issue.category not in issues_by_category:
                issues_by_category[issue.category] = []
            issues_by_category[issue.category].append(issue)
        
        # Print results
        self.print_security_report(all_issues, issues_by_severity, issues_by_category)
        
        return {
            "total_issues": len(all_issues),
            "by_severity": {k: len(v) for k, v in issues_by_severity.items()},
            "by_category": {k: len(v) for k, v in issues_by_category.items()},
            "all_issues": all_issues
        }
    
    def print_security_report(self, all_issues: List[SecurityIssue], 
                            by_severity: Dict, by_category: Dict):
        """Print comprehensive security report"""
        print(f"\n📊 SECURITY ANALYSIS RESULTS")
        print("=" * 50)
        
        print(f"\n🎯 Summary:")
        print(f"   Total Issues: {len(all_issues)}")
        for severity, issues in by_severity.items():
            if issues:
                print(f"   {severity}: {len(issues)}")
        
        print(f"\n📋 Issues by Category:")
        for category, issues in by_category.items():
            if issues:
                print(f"   {category}: {len(issues)}")
        
        # Print critical and high issues
        critical_issues = by_severity.get("CRITICAL", [])
        high_issues = by_severity.get("HIGH", [])
        
        if critical_issues or high_issues:
            print(f"\n🚨 Critical & High Priority Issues:")
            
            for issue in critical_issues + high_issues:
                rel_file = os.path.relpath(issue.file, os.getcwd())
                print(f"\n   {issue.severity} - {issue.category}")
                print(f"   File: {rel_file}:{issue.line}")
                print(f"   Description: {issue.description}")
                print(f"   Code: {issue.code_snippet}")
                print(f"   Recommendation: {issue.recommendation}")
        
        # Security score
        security_score = self.calculate_security_score(by_severity)
        print(f"\n🏆 Security Score: {security_score}/100")
        
        # Overall assessment
        assessment = self.get_security_assessment(security_score)
        print(f"📈 Security Level: {assessment}")
        
        # Recommendations
        self.print_overall_recommendations(by_severity, by_category)
    
    def calculate_security_score(self, by_severity: Dict) -> int:
        """Calculate security score (0-100)"""
        weights = {
            "CRITICAL": -25,
            "HIGH": -10,
            "MEDIUM": -3,
            "LOW": -1
        }
        
        score = 100
        for severity, issues in by_severity.items():
            score += weights.get(severity, 0) * len(issues)
        
        return max(0, min(100, score))
    
    def get_security_assessment(self, score: int) -> str:
        """Get security level assessment"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Fair"
        elif score >= 60:
            return "Poor"
        else:
            return "Critical"
    
    def print_overall_recommendations(self, by_severity: Dict, by_category: Dict):
        """Print overall security recommendations"""
        print(f"\n💡 OVERALL SECURITY RECOMMENDATIONS:")
        
        # Based on severity
        if by_severity.get("CRITICAL"):
            print("   🚨 IMMEDIATE ACTION REQUIRED:")
            print("      - Fix all critical security vulnerabilities")
            print("      - Review code execution and input validation")
        
        if by_severity.get("HIGH"):
            print("   ⚠️ HIGH PRIORITY FIXES:")
            print("      - Address high-severity security issues")
            print("      - Implement proper input sanitization")
        
        # Based on categories
        if by_category.get("COMMAND_INJECTION"):
            print("   🔒 COMMAND INJECTION PREVENTION:")
            print("      - Use subprocess.run() with shell=False")
            print("      - Validate all user inputs")
            print("      - Use allowlists for commands")
        
        if by_category.get("PATH_TRAVERSAL"):
            print("   📁 PATH TRAVERSAL PROTECTION:")
            print("      - Use os.path.join() for path construction")
            print("      - Validate file paths with os.path.abspath()")
            print("      - Restrict access to allowed directories")
        
        if by_category.get("UNSAFE_DESERIALIZATION"):
            print("   📦 SAFE DESERIALIZATION:")
            print("      - Use JSON instead of pickle for data exchange")
            print("      - Validate serialized data structure")
            print("      - Use safe_load() for YAML")

if __name__ == '__main__':
    analyzer = SecurityAnalyzer()
    results = analyzer.analyze_codebase('.')
    
    # Save results
    import json
    with open('security_analysis_results.json', 'w') as f:
        # Convert issues to dict for JSON serialization
        serializable_results = {
            "total_issues": results["total_issues"],
            "by_severity": results["by_severity"],
            "by_category": results["by_category"],
            "security_score": analyzer.calculate_security_score(results["by_severity"])
        }
        json.dump(serializable_results, f, indent=2)
    
    print(f"\n📁 Detailed results saved to: security_analysis_results.json")
