"""
Enhanced HWP Threat Detector v2.0
Based on AhnLab ASEC Research (https://asec.ahnlab.com)
Implements detection for EPS exploits, DefaultJScript macros, and advanced persistence techniques
"""
import os
import re
import zlib
import struct
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class ThreatIndicator:
    """Threat indicator with context"""
    type: str
    severity: str  # critical, high, medium, low
    description: str
    location: str
    evidence: List[str]
    confidence: float

class EPSExploitDetector:
    """
    EPS (Encapsulated PostScript) Exploit Detector
    Based on AhnLab research on EPS-based HWP attacks
    """
    
    # Critical EPS operators abused for exploitation
    DANGEROUS_EPS_OPERATORS = {
        # File manipulation operators (Trend Micro research)
        'eqproc': 'File execution via eqproc',
        'execute': 'Direct command execution',
        'system': 'System shell execution',
        'fork': 'Process forking',
        'wait': 'Process waiting',
        
        # File I/O operators
        'file': 'File handle creation',
        'open': 'File open operation',
        'read': 'File read operation',
        'write': 'File write operation',
        'close': 'File close operation',
        'delete': 'File deletion',
        'rename': 'File renaming',
        
        # Directory traversal
        'chdir': 'Directory change',
        'mkdir': 'Directory creation',
        'rmdir': 'Directory removal',
        'for': 'Loop iteration (often abused)',
        'repeat': 'Repeat operation',
        'loop': 'Infinite loop',
        
        # Suspicious patterns
        'run': 'Run external command',
        'runfile': 'Run file execution',
        'pipe': 'Pipe creation',
        'getenv': 'Environment variable access',
        'putenv': 'Environment variable modification',
        'setenv': 'Environment setup',
    }
    
    # CVE-specific patterns
    CVE_PATTERNS = {
        'CVE-2013-4979': rb'%!PS-Adobe.*?eqproc.*?system',
        'CVE-2013-0808': rb'%!PS-Adobe.*?execute.*?shell',
        'NOP_sled': rb'\x90{10,}|\xb5{10,}',  # NOP sled detection
    }
    
    def __init__(self):
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile regex patterns for EPS detection"""
        patterns = {}
        for operator, description in self.DANGEROUS_EPS_OPERATORS.items():
            try:
                patterns[operator] = re.compile(operator.encode(), re.IGNORECASE)
            except:
                pass
        return patterns
    
    def analyze_eps_content(self, data: bytes, stream_name: str = '') -> List[ThreatIndicator]:
        """
        Analyze EPS content for exploit indicators
        Based on AhnLab research methodology
        """
        indicators = []
        
        # 1. Check for PostScript header
        if not self._has_postscript_header(data):
            return indicators
        
        # 2. Detect dangerous operators
        for operator, pattern in self.compiled_patterns.items():
            matches = list(pattern.finditer(data))
            if matches:
                positions = [m.start() for m in matches]
                description = self.DANGEROUS_EPS_OPERATORS.get(operator, 'Unknown operator')
                
                indicators.append(ThreatIndicator(
                    type='eps_exploit',
                    severity='critical' if operator in ['eqproc', 'execute', 'system'] else 'high',
                    description=description,
                    location=stream_name,
                    evidence=[f"Position: {pos}, Operator: {operator}" for pos in positions[:5]],
                    confidence=min(1.0, len(matches) * 0.2)
                ))
        
        # 3. Detect CVE-specific patterns
        for cve_id, pattern in self.CVE_PATTERNS.items():
            if cve_id == 'NOP_sled':
                matches = list(re.finditer(pattern, data))
                if matches:
                    indicators.append(ThreatIndicator(
                        type='cve_exploit',
                        severity='critical',
                        description=f'CVE Pattern: {cve_id} - NOP sled detected',
                        location=stream_name,
                        evidence=[f"NOP sled at position: {m.start()}" for m in matches[:3]],
                        confidence=0.9
                    ))
        
        # 4. Detect file drop patterns
        drop_patterns = self._detect_file_drop_patterns(data)
        indicators.extend(drop_patterns)
        
        # 5. Detect startup folder manipulation
        startup_patterns = self._detect_startup_manipulation(data)
        indicators.extend(startup_patterns)
        
        return indicators
    
    def _has_postscript_header(self, data: bytes) -> bool:
        """Check for valid PostScript header"""
        ps_headers = [b'%!PS-Adobe', b'%!PS', b'%PDF']
        return any(header in data[:100] for header in ps_headers)
    
    def _detect_file_drop_patterns(self, data: bytes) -> List[ThreatIndicator]:
        """Detect patterns indicating file dropping"""
        indicators = []
        
        # Common drop locations
        drop_locations = [
            (b'Startup', 'Startup folder drop'),
            (b'%TEMP%', 'Temp directory drop'),
            (b'%APPDATA%', 'AppData directory drop'),
            (b'gswin32c.exe', 'PostScript interpreter manipulation'),
            (b'ProgramData', 'ProgramData directory access'),
        ]
        
        for pattern, description in drop_locations:
            if pattern in data:
                indicators.append(ThreatIndicator(
                    type='file_drop',
                    severity='high',
                    description=description,
                    location='EPS content',
                    evidence=[f"Pattern found: {pattern.decode('utf-8', errors='ignore')}"],
                    confidence=0.8
                ))
        
        return indicators
    
    def _detect_startup_manipulation(self, data: bytes) -> List[ThreatIndicator]:
        """Detect startup folder manipulation attempts"""
        indicators = []
        
        startup_patterns = [
            rb'Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            rb'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            rb'Programs\\Startup',
        ]
        
        for pattern in startup_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    type='persistence',
                    severity='critical',
                    description='Startup folder persistence mechanism',
                    location='EPS content',
                    evidence=['Startup folder path detected'],
                    confidence=0.9
                ))
                break
        
        return indicators


class DefaultJScriptDetector:
    """
    DefaultJScript (HWP Macro) Detector
    HWP's macro language similar to VBA in Office
    """
    
    # Suspicious JavaScript patterns in DefaultJScript
    SUSPICIOUS_PATTERNS = {
        # File operations
        b'ActiveXObject': 'ActiveX object creation',
        b'CreateObject': 'COM object creation',
        b'WScript.Shell': 'WScript shell access',
        b'Shell.Application': 'Shell application access',
        b'FileSystemObject': 'File system access',
        
        # Network operations
        b'XMLHTTP': 'HTTP request',
        b'WinHttpRequest': 'WinHTTP request',
        b'InternetExplorer.Application': 'IE automation',
        b'navigator': 'Browser object access',
        
        # Process execution
        b'Run(': 'Process execution',
        b'Exec(': 'Command execution',
        b'ShellExecute': 'Shell execution',
        b'cmd.exe': 'Command prompt',
        b'powershell': 'PowerShell execution',
        b'rundll32': 'DLL execution',
        b'mshta.exe': 'HTML Application execution',
        
        # Encoding/Obfuscation
        b'Base64': 'Base64 encoding',
        b'atob(': 'Base64 decode',
        b'btoa(': 'Base64 encode',
        b'eval(': 'Code evaluation',
        b'Function(': 'Dynamic function',
        b'unescape(': 'URL decode',
        b'fromCharCode': 'Character code conversion',
        b'String.fromCharCode': 'String from char code',
        
        # Persistence
        b'Registry': 'Registry access',
        b'RegRead': 'Registry read',
        b'RegWrite': 'Registry write',
        b'SpecialFolders': 'Special folder access',
        
        # Drop indicators
        b'WriteFile': 'File write',
        b'SaveToFile': 'File save',
        b'CreateTextFile': 'Text file creation',
        b'OpenTextFile': 'Text file open',
        
        # Network indicators
        b'DownloadFile': 'File download',
        b'Send': 'Data transmission',
        b'Post': 'HTTP POST',
        b'Get(': 'HTTP GET',
    }
    
    def analyze_jscript(self, data: bytes, stream_name: str = '') -> List[ThreatIndicator]:
        """
        Analyze DefaultJScript content for malicious patterns
        """
        indicators = []
        
        # Decompress if needed (zlib)
        decompressed = self._try_decompress(data)
        content = decompressed if decompressed else data
        
        # Remove null bytes (Unicode pattern)
        clean_content = content.replace(b'\x00', b'')
        
        # Check for JavaScript patterns
        for pattern, description in self.SUSPICIOUS_PATTERNS.items():
            if pattern in clean_content:
                # Calculate confidence based on pattern severity
                severity = self._calculate_severity(pattern)
                confidence = 0.7 if severity == 'critical' else 0.5
                
                indicators.append(ThreatIndicator(
                    type='jscript_macro',
                    severity=severity,
                    description=description,
                    location=stream_name,
                    evidence=[f"Pattern: {pattern.decode('utf-8', errors='ignore')}"],
                    confidence=confidence
                ))
        
        # Detect Base64 encoded payloads
        base64_indicators = self._detect_base64_payloads(clean_content)
        indicators.extend(base64_indicators)
        
        # Detect URL patterns
        url_indicators = self._detect_malicious_urls(clean_content)
        indicators.extend(url_indicators)
        
        return indicators
    
    def _try_decompress(self, data: bytes) -> Optional[bytes]:
        """Try to decompress zlib compressed data"""
        try:
            # Try various zlib approaches
            try:
                return zlib.decompress(data)
            except:
                # Try with wbits
                for wbits in [-15, -zlib.MAX_WBITS, 15, 31]:
                    try:
                        decompressor = zlib.decompressobj(wbits)
                        return decompressor.decompress(data)
                    except:
                        continue
        except:
            pass
        return None
    
    def _calculate_severity(self, pattern: bytes) -> str:
        """Calculate severity based on pattern type"""
        critical_patterns = [b'eval(', b'Exec(', b'Run(', b'powershell', b'cmd.exe']
        high_patterns = [b'WScript.Shell', b'ShellExecute', b'ActiveXObject', b'DownloadFile']
        
        if any(cp in pattern for cp in critical_patterns):
            return 'critical'
        elif any(hp in pattern for hp in high_patterns):
            return 'high'
        return 'medium'
    
    def _detect_base64_payloads(self, content: bytes) -> List[ThreatIndicator]:
        """Detect Base64 encoded malicious payloads"""
        indicators = []
        
        # Look for long Base64 strings
        base64_pattern = rb'[A-Za-z0-9+/]{100,}={0,2}'
        matches = list(re.finditer(base64_pattern, content))
        
        for match in matches:
            encoded_data = match.group()
            # Check if it's likely a binary payload (size check)
            if len(encoded_data) > 200:
                try:
                    import base64
                    decoded = base64.b64decode(encoded_data)
                    # Check for executable patterns
                    if decoded[:2] == b'MZ' or b'PE\x00\x00' in decoded[:100]:
                        indicators.append(ThreatIndicator(
                            type='encoded_payload',
                            severity='critical',
                            description='Base64 encoded executable payload',
                            location='DefaultJScript',
                            evidence=[f"Position: {match.start()}, Size: {len(decoded)} bytes"],
                            confidence=0.9
                        ))
                except:
                    pass
        
        return indicators
    
    def _detect_malicious_urls(self, content: bytes) -> List[ThreatIndicator]:
        """Detect malicious URLs in script"""
        indicators = []
        
        # URL patterns
        url_patterns = [
            rb'https?://[^\s\x00-\x1f<>"{}|\^`[\]]+',
            rb'ftp://[^\s\x00-\x1f<>"{}|\^`[\]]+',
        ]
        
        suspicious_domains = [
            b'.tk', b'.ml', b'.ga', b'.cf',  # Free domains
            b'pastebin.com', b'githubusercontent', b'raw.githubusercontent',
            b'bit.ly', b'tinyurl.com', b'goo.gl',
        ]
        
        for pattern in url_patterns:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                url = match.group()
                if any(domain in url.lower() for domain in suspicious_domains):
                    indicators.append(ThreatIndicator(
                        type='malicious_url',
                        severity='high',
                        description='Suspicious URL in macro',
                        location='DefaultJScript',
                        evidence=[f"URL: {url.decode('utf-8', errors='ignore')}"],
                        confidence=0.7
                    ))
        
        return indicators


class PersistenceMechanismDetector:
    """
    Detect persistence mechanisms used by HWP malware
    Based on real-world attack patterns
    """
    
    PERSISTENCE_LOCATIONS = {
        'startup_folder_user': [
            rb'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            rb'AppData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        ],
        'startup_folder_common': [
            rb'ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        ],
        'registry_run': [
            rb'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            rb'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            rb'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
        ],
        'registry_services': [
            rb'System\\CurrentControlSet\\Services',
        ],
        'scheduled_tasks': [
            rb'Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks',
            rb'Windows\\System32\\Tasks',
        ],
        'wmi_subscription': [
            rb'ROOT\\subscription',
            b'ActiveScriptEventConsumer',
        ],
    }
    
    DROP_LOCATIONS = {
        'temp': [b'%TEMP%', b'%tmp%', b'\\Temp\\', b'/tmp/'],
        'appdata': [b'%APPDATA%', b'\\AppData\\'],
        'programdata': [b'%ProgramData%', b'\\ProgramData\\'],
        'public': [b'%PUBLIC%', b'\\Users\\Public\\'],
        'windows': [b'%windir%', b'\\Windows\\'],
        'system32': [b'\\System32\\', b'\\SysWOW64\\'],
    }
    
    def detect_persistence(self, data: bytes, stream_name: str = '') -> List[ThreatIndicator]:
        """Detect persistence mechanisms in HWP content"""
        indicators = []
        
        # Check persistence locations
        for persistence_type, patterns in self.PERSISTENCE_LOCATIONS.items():
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    indicators.append(ThreatIndicator(
                        type='persistence',
                        severity='critical',
                        description=f'{persistence_type.replace("_", " ").title()} persistence',
                        location=stream_name,
                        evidence=[f"Pattern: {pattern.decode('utf-8', errors='ignore')}"],
                        confidence=0.85
                    ))
                    break
        
        # Check drop locations
        for drop_type, patterns in self.DROP_LOCATIONS.items():
            found = False
            for pattern in patterns:
                if pattern in data:
                    found = True
                    break
            if found:
                indicators.append(ThreatIndicator(
                    type='file_drop',
                    severity='high',
                    description=f'{drop_type.upper()} directory drop',
                    location=stream_name,
                    evidence=[f'{drop_type} path detected'],
                    confidence=0.7
                ))
        
        return indicators


class EnhancedHWPDetector:
    """
    Main detector class integrating all detection modules
    Based on AhnLab research findings
    """
    
    def __init__(self):
        self.eps_detector = EPSExploitDetector()
        self.jscript_detector = DefaultJScriptDetector()
        self.persistence_detector = PersistenceMechanismDetector()
        
        # Stream names of interest
        self.CRITICAL_STREAMS = [
            'DefaultJScript',
            'BinData',
            'PrvText',
            'DocInfo',
            'FileHeader',
        ]
    
    def analyze_hwp_file(self, filepath: str, streams: Dict[str, bytes]) -> Dict[str, Any]:
        """
        Comprehensive HWP file analysis
        """
        all_indicators = []
        
        # 1. Analyze EPS content in BinData
        for stream_name, stream_data in streams.items():
            if 'BinData' in stream_name or stream_name.endswith('.EPS') or stream_name.endswith('.PS'):
                eps_indicators = self.eps_detector.analyze_eps_content(stream_data, stream_name)
                all_indicators.extend(eps_indicators)
        
        # 2. Analyze DefaultJScript
        if 'DefaultJScript' in streams:
            jscript_indicators = self.jscript_detector.analyze_jscript(
                streams['DefaultJScript'], 
                'DefaultJScript'
            )
            all_indicators.extend(jscript_indicators)
        
        # 3. Analyze all streams for persistence mechanisms
        for stream_name, stream_data in streams.items():
            persistence_indicators = self.persistence_detector.detect_persistence(
                stream_data, 
                stream_name
            )
            all_indicators.extend(persistence_indicators)
        
        # 4. Calculate overall risk
        risk_score = self._calculate_risk_score(all_indicators)
        
        return {
            'indicators': all_indicators,
            'indicator_count': len(all_indicators),
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'critical_streams_analyzed': len([s for s in streams if any(cs in s for cs in self.CRITICAL_STREAMS)]),
        }
    
    def _calculate_risk_score(self, indicators: List[ThreatIndicator]) -> float:
        """Calculate overall risk score from indicators"""
        if not indicators:
            return 0.0
        
        severity_weights = {
            'critical': 30,
            'high': 15,
            'medium': 5,
            'low': 1
        }
        
        total_score = 0
        for indicator in indicators:
            weight = severity_weights.get(indicator.severity, 1)
            total_score += weight * indicator.confidence
        
        # Cap at 100
        return min(100.0, total_score)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'CLEAN'


# Global detector instance
enhanced_detector = EnhancedHWPDetector()
