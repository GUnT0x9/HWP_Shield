"""
Rule-based Threat Scoring System
Implements structured scoring with multiple indicators
"""
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from .pe_analyzer import PEAnalyzer

@dataclass
class ThreatIndicator:
    """Individual threat indicator"""
    type: str
    severity: str  # critical, high, medium, low
    score: int
    description: str
    context: Optional[str] = None

@dataclass
class ScoringRule:
    """Scoring rule definition"""
    name: str
    indicators: List[str]
    base_score: int
    required_count: int = 1
    max_score: int = 100

class RuleBasedThreatAnalyzer:
    """Rule-based threat analyzer with structured scoring"""
    
    # Scoring rules
    SCORING_RULES = {
        'executable_embedded': ScoringRule(
            name='실행 파일 임베드',
            indicators=['exe_embedded'],
            base_score=50,
            max_score=80
        ),
        'mz_patterns_only': ScoringRule(
            name='MZ 패턴만 존재',
            indicators=['mz_patterns_only'],
            base_score=5,
            max_score=15
        ),
        'macro_present': ScoringRule(
            name='매크로 존재',
            indicators=['macro_storage', 'script_storage'],
            base_score=30,
            max_score=50
        ),
        'eps_exploit': ScoringRule(
            name='EPS 취약점',
            indicators=['eps_exploit', 'execute_keyword', 'system_keyword'],
            base_score=25,
            required_count=2,  # Need 2+ indicators
            max_score=90
        ),
        'dropper_behavior': ScoringRule(
            name='드로퍼 행위',
            indicators=['temp_path', 'temp_path_alt'],
            base_score=20,
            max_score=40
        ),
        'suspicious_apis': ScoringRule(
            name='의심스러운 API',
            indicators=['shell_exec', 'powershell', 'wscript', 'cscript'],
            base_score=15,
            max_score=30
        ),
        'encryption_suspicious': ScoringRule(
            name='의심스러운 암호화',
            indicators=['entropy_high', 'encrypted_patterns'],
            base_score=10,
            max_score=20
        ),
        'external_links': ScoringRule(
            name='외부 링크',
            indicators=['external_url'],
            base_score=5,
            max_score=15
        )
    }
    
    # Pattern definitions with context
    PATTERNS = {
        # Executable indicators (with context)
        'exe_magic': {
            'pattern': rb'\x4d\x5a',  # MZ header
            'context_check': None,
            'description': 'EXE 매직 바이트'
        },
        'exe_magic_alt': {
            'pattern': b'MZ',
            'context_check': None,
            'description': 'EXE 매직 바이트 (문자열)'
        },
        
        # Macro/Script indicators
        'macro_storage': {
            'pattern': rb'\x01Script',
            'context_check': None,
            'description': '매크로 스토리지'
        },
        'script_storage': {
            'pattern': rb'\x05Macros',
            'context_check': None,
            'description': '스크립트 스토리지'
        },
        
        # EPS exploit indicators
        'eps_exploit': {
            'pattern': b'eqproc',
            'context_check': None,
            'description': 'EPS eqproc 키워드'
        },
        'execute_keyword': {
            'pattern': b'execute',
            'context_check': None,
            'description': 'EPS execute 키워드'
        },
        'system_keyword': {
            'pattern': b'system',
            'context_check': None,
            'description': 'EPS system 키워드'
        },
        
        # Dropper indicators
        'temp_path': {
            'pattern': b'%TEMP%',
            'context_check': None,
            'description': 'TEMP 경로 참조'
        },
        'temp_path_alt': {
            'pattern': rb'\\Temp\\',
            'context_check': None,
            'description': 'Temp 디렉터리 참조'
        },
        
        # Suspicious APIs
        'shell_exec': {
            'pattern': b'ShellExecute',
            'context_check': None,
            'description': 'ShellExecute API'
        },
        'powershell': {
            'pattern': b'powershell',
            'context_check': None,
            'description': 'PowerShell 참조'
        },
        'wscript': {
            'pattern': b'wscript',
            'context_check': None,
            'description': 'Windows Script Host'
        },
        'cscript': {
            'pattern': b'cscript',
            'context_check': None,
            'description': 'Windows Script Host (CScript)'
        },
        
        # External URLs
        'external_url': {
            'pattern': rb'http[s]?://',
            'context_check': None,
            'description': '외부 URL'
        }
    }
    
    def _check_exe_context(self, data: bytes, pattern_pos: int) -> bool:
        """Check if EXE pattern is in valid context"""
        # Check for image signatures (false positive prevention)
        window_start = max(0, pattern_pos - 50)
        window_end = min(len(data), pattern_pos + 50)
        context = data[window_start:window_end]
        
        # Image signatures that might contain MZ
        image_signatures = [
            b'\xff\xd8\xff',  # JPEG
            b'\x89PNG',      # PNG
            b'GIF8',         # GIF
            b'BM'            # BMP
        ]
        
        # If image signature found nearby, it's likely a false positive
        for sig in image_signatures:
            if sig in context[:20]:  # Check first 20 bytes
                return False
        
        # Check for PE header structure
        if pattern_pos + 64 < len(data):
            pe_offset = pattern_pos + 60  # PE header offset
            pe_sig = data[pe_offset:pe_offset + 4]
            if pe_sig == b'PE\0\0':  # Valid PE signature
                return True
        
        return False
    
    def _check_eps_context(self, data: bytes, pattern_pos: int) -> bool:
        """Check if EPS pattern is in valid EPS context"""
        window_start = max(0, pattern_pos - 100)
        window_end = min(len(data), pattern_pos + 100)
        context = data[window_start:window_end]
        
        # EPS context markers
        eps_markers = [
            b'%!PS-Adobe',
            b'%%BoundingBox',
            b'/findfont',
            b'/def',
            b'/dict',
            b'begin',
            b'end'
        ]
        
        # Count EPS markers in context
        marker_count = sum(1 for marker in eps_markers if marker in context)
        
        # Need at least 2 EPS markers for valid context
        return marker_count >= 2
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for encryption detection"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * (freq.bit_length() - 1)
        
        return entropy
    
    def _detect_indicators(self, data: bytes) -> List[ThreatIndicator]:
        """Detect all threat indicators in data"""
        indicators = []
        
        # Enhanced EXE detection with PE validation
        pe_analysis = PEAnalyzer.analyze_exe_embeddings(data)
        if pe_analysis["has_real_executable"]:
            for detail in pe_analysis["mz_details"]:
                if detail["is_valid_pe"]:
                    indicator = ThreatIndicator(
                        type="exe_embedded",
                        severity="critical",
                        score=50,
                        description=f"Valid PE executable at offset {detail['offset']} ({detail['pe_type']})",
                        context=f"Sections: {detail['sections']}"
                    )
                    indicators.append(indicator)
        elif pe_analysis["false_positive_count"] > 0:
            # Low confidence for MZ without PE structure
            if pe_analysis["false_positive_count"] >= 5:
                indicator = ThreatIndicator(
                    type="mz_patterns_only",
                    severity="low",
                    score=10,
                    description=f"MZ patterns without PE structure: {pe_analysis['false_positive_count']} occurrences",
                    context="Likely compressed data or false positives"
                )
                indicators.append(indicator)
        
        # Continue with other patterns (excluding MZ)
        for pattern_name, pattern_info in self.PATTERNS.items():
            if pattern_name in ['exe_magic', 'exe_magic_alt']:
                continue  # Skip, handled by PE analyzer
            
            pattern = pattern_info['pattern']
            context_check = pattern_info.get('context_check')
            
            # Find all occurrences
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                
                # Check context if required
                context_valid = True
                if context_check:
                    context_valid = context_check(data, pos)
                
                if context_valid:
                    # Determine severity
                    severity = self._get_pattern_severity(pattern_name)
                    
                    indicator = ThreatIndicator(
                        type=pattern_name,
                        severity=severity,
                        score=self._get_pattern_score(pattern_name),
                        description=pattern_info['description'],
                        context=f"Position: {pos}"
                    )
                    indicators.append(indicator)
                
                start = pos + len(pattern)
        
        return indicators
    
    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Get severity level for pattern"""
        severity_map = {
            'exe_magic': 'critical',
            'exe_magic_alt': 'critical',
            'macro_storage': 'high',
            'script_storage': 'high',
            'eps_exploit': 'critical',
            'execute_keyword': 'high',
            'system_keyword': 'medium',
            'temp_path': 'high',
            'temp_path_alt': 'medium',
            'shell_exec': 'critical',
            'powershell': 'high',
            'wscript': 'medium',
            'cscript': 'medium',
            'external_url': 'low'
        }
        return severity_map.get(pattern_name, 'low')
    
    def _get_pattern_score(self, pattern_name: str) -> int:
        """Get base score for pattern - INCREASED for higher sensitivity"""
        score_map = {
            'exe_magic': 50,      # Increased from 40
            'exe_magic_alt': 50,  # Increased from 40
            'macro_storage': 35,  # Increased from 30
            'script_storage': 35, # Increased from 30
            'eps_exploit': 35,    # Increased from 25
            'execute_keyword': 25, # Increased from 20
            'system_keyword': 20,  # Increased from 15
            'temp_path': 25,       # Increased from 20
            'temp_path_alt': 20,   # Increased from 15
            'shell_exec': 40,      # Increased from 35
            'powershell': 30,      # Increased from 25
            'wscript': 20,         # Increased from 15
            'cscript': 20,         # Increased from 15
            'external_url': 10     # Increased from 5
        }
        return score_map.get(pattern_name, 10)  # Default increased from 5
    
    def _apply_scoring_rules(self, indicators: List[ThreatIndicator]) -> Dict:
        """Apply scoring rules to indicators"""
        rule_scores = {}
        
        for rule_name, rule in self.SCORING_RULES.items():
            # Count matching indicators
            matching_indicators = [
                ind for ind in indicators 
                if ind.type in rule.indicators
            ]
            
            if len(matching_indicators) >= rule.required_count:
                # Calculate rule score
                base_score = rule.base_score
                indicator_bonus = sum(ind.score for ind in matching_indicators)
                rule_score = min(base_score + indicator_bonus, rule.max_score)
                
                rule_scores[rule_name] = {
                    'score': rule_score,
                    'indicators': matching_indicators,
                    'rule': rule
                }
        
        return rule_scores
    
    def analyze(self, parse_result: Dict, file_format: str) -> Dict:
        """Analyze file with rule-based scoring"""
        # Collect all data
        all_data = b''
        
        # Try to get streams with content first (streams_dict has actual data)
        streams = parse_result.get('streams_dict', parse_result.get('streams', {}))
        
        # Handle both dict and list types for streams
        if isinstance(streams, dict):
            for stream_name, stream_data in streams.items():
                if isinstance(stream_data, bytes):
                    all_data += stream_data
        elif isinstance(streams, list):
            # If streams is a list, we can't get the data directly
            # Skip stream content analysis for list format
        
        # Add raw strings if available
        if 'raw_strings' in parse_result:
            all_data += ''.join(parse_result['raw_strings']).encode('utf-8', errors='ignore')
        
        # Detect indicators
        indicators = self._detect_indicators(all_data)
        
        # Apply scoring rules
        rule_scores = self._apply_scoring_rules(indicators)
        
        # Calculate total score
        total_score = sum(rule['score'] for rule in rule_scores.values())
        
        # Determine risk level - LOWERED THRESHOLDS for higher sensitivity
        if total_score >= 50:
            risk_level = "MALICIOUS"
        elif total_score >= 25:
            risk_level = "HIGH_RISK"
        elif total_score >= 10:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "CLEAN"
        
        # Build threat list
        threats = []
        for rule_name, rule_result in rule_scores.items():
            rule = rule_result['rule']
            rule_indicators = rule_result['indicators']
            
            threat = {
                'type': rule_name,
                'description': f"{rule.name} ({len(rule_indicators)}개 지표)",
                'score': rule_result['score'],
                'category': 'CRITICAL' if rule_result['score'] >= 50 else 'HIGH',
                'details': [ind.description for ind in rule_indicators]
            }
            threats.append(threat)
        
        # Build result
        result = {
            'score': total_score,
            'risk_level': risk_level,
            'threats': threats,
            'indicators': [
                {
                    'type': ind.type,
                    'description': ind.description,
                    'severity': ind.severity,
                    'score': ind.score
                }
                for ind in indicators
            ],
            'rule_scores': rule_scores,
            'analysis_summary': {
                'total_indicators': len(indicators),
                'critical_indicators': len([i for i in indicators if i.severity == 'critical']),
                'high_indicators': len([i for i in indicators if i.severity == 'high']),
                'rules_triggered': len(rule_scores)
            }
        }
        
        return result
