"""
EPS/PostScript Detection Module
Detects CVE-2017-8291 (GhostButt) exploitation patterns.
"""
import re
from typing import List, Dict, Tuple, Any
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    """Detection result container."""
    module_id: str
    name: str
    name_en: str
    status: str = "CLEAN"
    score_contribution: int = 0
    indicators: List[Dict] = field(default_factory=list)
    details: str = ""
    
    def add_indicator(self, type_: str, value: str, severity: str):
        """Add a detected indicator."""
        self.indicators.append({
            "type": type_,
            "value": value,
            "severity": severity
        })
        if severity in ["high", "critical"]:
            self.status = "DETECTED"
        elif severity == "medium" and self.status == "CLEAN":
            self.status = "SUSPICIOUS"


class EPSDetector:
    """
    Detector for EPS/PostScript-based attacks.
    Targets: CVE-2017-8291 (GhostButt)
    """
    
    # EPS signatures
    EPS_SIGNATURES = [
        b'%!PS-Adobe',
        b'%!PS',
        b'\xc5\xd0\xc3\xc6',  # Binary EPS header
    ]
    
    # CVE-2017-8291 trigger
    CVE_TRIGGER = b'.eqproc'
    
    # Win32 API strings (shellcode indicators)
    WIN32_APIS = [
        b'CreateFileA', b'CreateFileW',
        b'GetTempPath', b'GetTempPathA', b'GetTempPathW',
        b'WinExec', b'ShellExecuteA', b'ShellExecuteW',
        b'VirtualAlloc', b'VirtualProtect',
        b'WriteFile', b'ReadFile',
        b'LoadLibraryA', b'LoadLibraryW', b'GetProcAddress',
        b'CreateProcessA', b'CreateProcessW',
        b'URLDownloadToFileA', b'URLDownloadToFileW',
        b'InternetOpenA', b'InternetOpenW',
    ]
    
    # PostScript suspicious tokens
    SUSPICIOUS_TOKENS = [
        b'currentfile', b'eexec', b'def', b'exec',
        b'dup', b'exch', b'pop', b'stack',
        b'readstring', b'filter',
    ]
    
    def analyze(self, bindata_streams: List[Tuple[str, bytes]]) -> DetectionResult:
        """
        Analyze BinData streams for EPS threats.
        
        Args:
            bindata_streams: List of (stream_name, data) tuples
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="eps",
            name="EPS/PostScript 탐지",
            name_en="EPS/PostScript Detection"
        )
        
        total_score = 0
        findings = []
        
        for stream_name, data in bindata_streams:
            # Check if this is an EPS file
            if not self._is_eps(data):
                continue
            
            result.add_indicator("EPS_STREAM", stream_name, "medium")
            total_score += 10
            findings.append(f"EPS stream found: {stream_name}")
            
            # Check for CVE-2017-8291 trigger
            if self.CVE_TRIGGER in data:
                result.add_indicator("CVE-2017-8291", ".eqproc 발견", "critical")
                total_score += 30
                findings.append("CVE-2017-8291 exploit pattern detected")
            
            # Check for hex-encoded shellcode
            hex_patterns = self._find_hex_shellcode(data)
            if hex_patterns:
                result.add_indicator(
                    "HEX_SHELLCODE", 
                    f"{len(hex_patterns)}개 hex 패턴 (길이: {sum(len(p) for p in hex_patterns)})",
                    "high"
                )
                total_score += 20
            
            # Check for Win32 API strings
            apis_found = self._find_win32_apis(data)
            if apis_found:
                result.add_indicator(
                    "WIN32_APIS",
                    f"발견: {', '.join(apis_found[:5])}",
                    "critical"
                )
                total_score += 25
            
            # Check for obfuscation patterns
            obf_count = self._count_obfuscation(data)
            if obf_count > 5:
                result.add_indicator(
                    "OBFUSCATION",
                    f"{obf_count}개 난독화 패턴",
                    "medium"
                )
                total_score += 10
        
        result.score_contribution = min(total_score, 95)
        result.details = "; ".join(findings) if findings else "EPS/PostScript 관련 위협이 발견되지 않았습니다."
        
        return result
    
    def _is_eps(self, data: bytes) -> bool:
        """Check if data is an EPS file."""
        for sig in self.EPS_SIGNATURES:
            if data.startswith(sig):
                return True
        
        # Check for PostScript markers anywhere in first 1KB
        first_kb = data[:1024]
        if b'%!PS' in first_kb:
            return True
        
        return False
    
    def _find_hex_shellcode(self, data: bytes) -> List[str]:
        """Find hex-encoded shellcode patterns."""
        # Pattern: <[hex chars]> with length >= 100
        pattern = rb'<([0-9A-Fa-f]{100,})>'
        matches = re.findall(pattern, data)
        return [m.decode('ascii', errors='ignore') for m in matches]
    
    def _find_win32_apis(self, data: bytes) -> List[str]:
        """Find Win32 API strings in data."""
        found = []
        for api in self.WIN32_APIS:
            if api in data:
                found.append(api.decode('ascii', errors='ignore'))
        return found
    
    def _count_obfuscation(self, data: bytes) -> int:
        """Count obfuscation patterns."""
        count = 0
        
        # Octal escape: \ddd
        octal_pattern = rb'\\[0-7]{1,3}'
        count += len(re.findall(octal_pattern, data))
        
        # Hex escape: \xHH
        hex_escape_pattern = rb'\\x[0-9A-Fa-f]{2}'
        count += len(re.findall(hex_escape_pattern, data))
        
        return count
