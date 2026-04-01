"""
SIMPLIFIED Threat Analyzer - Direct pattern matching without complex context
Just look for bad stuff and score immediately
"""
from typing import Dict, List, Tuple
import re

class SimpleThreatAnalyzer:
    """Direct threat detection - find suspicious patterns and score immediately"""
    
    # CRITICAL patterns - immediate high scores
    CRITICAL_PATTERNS = {
        # EPS Exploit (CVE-2017-8291)
        b'eqproc': ('eps_exploit', 50, 'EPS eqproc 키워드'),
        b'%!PS-Adobe': ('eps_header', 10, 'PS-Adobe 헤더'),
        b'%%BoundingBox': ('eps_header', 5, 'BoundingBox'),
        b'execute': ('execute_keyword', 30, 'execute 키워드'),
        b'system': ('system_keyword', 25, 'system 키워드'),
        
        # EXE/Embedded malware
        b'MZ': ('exe_magic', 60, 'EXE 매직 바이트 (MZ)'),
        b'\x4d\x5a': ('exe_magic_alt', 60, 'EXE 매직 바이트 (4D5A)'),
        
        # Dropper indicators  
        b'%TEMP%': ('temp_path', 40, 'TEMP 경로 참조'),
        b'%APPDATA%': ('appdata_path', 35, 'APPDATA 경로 참조'),
        
        # Script/Shell indicators
        b'powershell': ('powershell', 45, 'PowerShell 참조'),
        b'cmd.exe': ('cmd_ref', 40, 'cmd.exe 참조'),
        b'wscript': ('wscript', 40, 'WScript 참조'),
        b'CreateObject': ('create_object', 35, 'CreateObject (VBScript)'),
        b'ShellExecute': ('shell_exec', 50, 'ShellExecute'),
        b'WinExec': ('winexec', 45, 'WinExec'),
        
        # Network
        b'URLDownloadToFile': ('url_download', 50, 'URLDownloadToFile'),
        b'http://': ('http_url', 15, 'HTTP URL'),
        b'https://': ('https_url', 10, 'HTTPS URL'),
    }
    
    # OLE specific patterns
    OLE_PATTERNS = {
        b'\xd0\xcf\x11\xe0': ('ole_magic', 10, 'OLE Object'),
        b'\x4d\x5a': ('exe_in_ole', 60, 'Embedded EXE in OLE'),
        b'MZ': ('exe_magic', 60, 'Windows executable'),
        b'Ole10Native': ('ole_native', 40, 'OLE Native object'),
        b'Package': ('ole_package', 30, 'OLE Package'),
        b'Embedded': ('embedded_obj', 20, 'Embedded object'),
    }
    EPS_CONTEXT_MARKERS = [
        b'%!PS-Adobe',      # PostScript header
        b'%%BoundingBox',   # EPS bounding box
        b'%%EndComments',  # EPS comment section
        b'/EPS',            # EPS object
        b'%%EOF',           # EPS end marker
        b'@showpage',        # PostScript showpage
        b'/findfont',        # PostScript font operation
        b'/def',             # PostScript definition
        b'/Device',          # PostScript device
        b'ColorRendering',   # EPS specific
        b'ColorSpace',       # Color space definition
    ]
    
    # Image file signatures to exclude from pattern matching
    IMAGE_SIGNATURES = {
        b'\xff\xd8\xff': 'JPEG',      # JPEG start
        b'\x89PNG': 'PNG',           # PNG header
        b'GIF8': 'GIF',              # GIF
        b'BM': 'BMP',                # BMP
        b'RIFF': 'RIFF',             # RIFF container (WEBP)
    }
    
    def _check_pattern_context(self, data: bytes, pattern_pos: int, window_size: int = 100) -> bool:
        """Check if pattern at given position is in valid PostScript/EPS context"""
        start = max(0, pattern_pos - window_size)
        end = min(len(data), pattern_pos + window_size)
        context = data[start:end]
        
        # Check for EPS/PostScript context markers
        context_score = 0
        for marker in self.EPS_CONTEXT_MARKERS:
            if marker in context:
                context_score += 1
        
        # Check for image signatures (if found, this is likely false positive from image data)
        for sig, img_type in self.IMAGE_SIGNATURES.items():
            if sig in context[:50]:  # Check beginning of context window
                # If we find image signature, pattern is likely in image data
                return False
        
        # Need at least 2 context markers to be valid EPS
        return context_score >= 2
    
    def _find_pattern_with_context(self, data: bytes, pattern: bytes) -> List[Tuple[int, bool]]:
        """Find all occurrences of pattern and verify context for each"""
        results = []
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            is_valid_context = self._check_pattern_context(data, pos)
            results.append((pos, is_valid_context))
            pos += len(pattern)
        return results
    
    def analyze(self, parse_result: Dict, file_format: str) -> Dict:
        """Simple analysis - scan all data for patterns"""
        threats = []
        total_score = 0
        
        # Get raw data from all streams
        all_data = b''
        streams = parse_result.get('streams_dict', parse_result.get('streams', {}))
        if isinstance(streams, dict):
            for name, data in streams.items():
                if isinstance(data, bytes):
                    all_data += data
        else:
        
        # Also check raw_strings
        raw_strings = parse_result.get('raw_strings', [])
        for s in raw_strings:
            if isinstance(s, str):
                all_data += s.encode('utf-8', errors='ignore')
        
        # Check for critical patterns with context verification for EPS
        found_patterns = []
        
        for pattern, (threat_type, score, description) in self.CRITICAL_PATTERNS.items():
            if threat_type in ['eps_exploit', 'eps_header', 'execute_keyword', 'system_keyword']:
                # For EPS-related patterns, verify context
                matches = self._find_pattern_with_context(all_data, pattern)
                for pos, is_valid in matches:
                    if is_valid:
                        found_patterns.append((threat_type, score, description, pattern))
                    else:
                        # Found in invalid context (probably image data), mark as suspicious with lower score
                        found_patterns.append((threat_type + '_invalid_context', 5, description + ' (이미지 데이터 내 발견 - 의심)', pattern))
            else:
                # Non-EPS patterns: direct match
                if pattern in all_data:
                    found_patterns.append((threat_type, score, description, pattern))
        
        # Check for OLE patterns
        for pattern, (threat_type, score, description) in self.OLE_PATTERNS.items():
            if pattern in all_data:
                found_patterns.append((threat_type, score, description, pattern))
        
        
        # Build threats from found patterns
        # Separate valid EPS from invalid context EPS
        valid_eps = [p for p in found_patterns if p[0] in ['eps_exploit', 'eps_header', 'execute_keyword', 'system_keyword']]
        invalid_eps = [p for p in found_patterns if p[0].endswith('_invalid_context')]
        exe_indicators = [p for p in found_patterns if p[0] in ['exe_magic', 'exe_magic_alt']]
        dropper_indicators = [p for p in found_patterns if p[0] in ['temp_path', 'appdata_path']]
        script_indicators = [p for p in found_patterns if 'script' in p[0] or p[0] in ['powershell', 'cmd_ref', 'wscript', 'create_object']]
        
        # EPS Exploit - only count valid context patterns for high score
        if valid_eps:
            eps_score = sum(p[1] for p in valid_eps)
            eps_score = min(eps_score, 90)  # Cap at 90
            threats.append({
                'type': 'eps_exploit',
                'description': f"EPS 취약점 패턴 ({len(valid_eps)}개 유효 지표)",
                'score': eps_score,
                'category': 'CRITICAL' if eps_score >= 60 else 'HIGH',
                'details': [p[2] for p in valid_eps]
            })
            total_score += eps_score
        
        # Invalid context EPS - just informational, no score
        if invalid_eps:
            threats.append({
                'type': 'eps_false_positive',
                'description': f"EPS 패턴 비정상 컨텍스트 ({len(invalid_eps)}개 - 이미지 데이터 가능성)",
                'score': 0,
                'category': 'INFO',
                'details': [p[2] for p in invalid_eps]
            })
        
        # EXE embedded - only if not an image file
        # Filter out image OLE objects (false positives from MZ in image data)
        non_image_exe = [p for p in exe_indicators if not p[2].startswith('이미지')]
        
        if non_image_exe:
            exe_score = 70
            if dropper_indicators:
                exe_score = 85  # Higher if combined with dropper behavior
            
            threats.append({
                'type': 'exe_embedded',
                'description': "실행 파일 데이터 감지",
                'score': exe_score,
                'category': 'CRITICAL',
                'details': [p[2] for p in non_image_exe]
            })
            total_score += exe_score
        
        # Image OLE objects with MZ - just informational
        image_exe = [p for p in exe_indicators if p[2].startswith('이미지')]
        if image_exe:
            threats.append({
                'type': 'image_ole_object',
                'description': "이미지 파일 OLE 객체 (EXE 패턴 우연 포함 가능)",
                'score': 0,
                'category': 'INFO',
                'details': ['JPEG/PNG/GIF/BMP 파일 - 정상 이미지일 가능성 높음']
            })
        
        # Dropper without EXE
        elif dropper_indicators:
            threats.append({
                'type': 'dropper_behavior',
                'description': "드로퍼 행위 (TEMP 경로 참조)",
                'score': 40,
                'category': 'HIGH',
                'details': [p[2] for p in dropper_indicators]
            })
            total_score += 40
        
        # Script execution
        if script_indicators:
            script_score = sum(p[1] for p in script_indicators)
            script_score = min(script_score, 50)
            threats.append({
                'type': 'script_execution',
                'description': "스크립트 실행 코드",
                'score': script_score,
                'category': 'HIGH',
                'details': [p[2] for p in script_indicators]
            })
            total_score += script_score
        
        # Determine risk level
        if total_score >= 50:
            risk_level = "MALICIOUS"
        elif total_score >= 25:
            risk_level = "HIGH_RISK"
        elif total_score >= 10:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "CLEAN"
        
        # Build indicators list
        indicators = []
        for t in threats:
            indicators.append({
                'type': t['type'],
                'description': t['description'],
                'severity': t['category'].lower(),
                'score': t['score']
            })
        
        return {
            'threats': threats,
            'score': total_score,
            'risk_level': risk_level,
            'indicators': indicators,
            'iocs': [],
            'found_patterns': len(found_patterns)
        }

# Backward compatibility
class ImprovedThreatAnalyzer(SimpleThreatAnalyzer):
    """Alias for backward compatibility"""
    pass

# Keep old function for compatibility
def analyze_threats(parse_result: Dict, file_format: str) -> Dict:
    """Wrapper for backward compatibility"""
    analyzer = ImprovedThreatAnalyzer()
    return analyzer.analyze(parse_result, file_format)
