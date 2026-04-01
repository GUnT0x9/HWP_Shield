"""
Script Analysis Module
Detects malicious patterns in HWP JavaScript macros.
"""
import re
from typing import List, Dict, Any
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


class ScriptDetector:
    """
    Detector for malicious JavaScript in HWP documents.
    Targets: VBE/VBS macro chains, PowerShell downloaders.
    """
    
    # COM object creation (ActiveX)
    COM_OBJECTS = {
        b'WScript.Shell': 'critical',
        b'Scripting.FileSystemObject': 'high',
        b'ADODB.Stream': 'critical',
        b'Microsoft.XMLHTTP': 'high',
        b'WinHttp.WinHttpRequest': 'high',
        b'InternetExplorer.Application': 'medium',
        b'Shell.Application': 'high',
    }
    
    # File operations
    FILE_OPERATIONS = [
        b'CreateTextFile',
        b'OpenTextFile',
        b'WriteLine',
        b'Write',
        b'SaveToFile',
        b'LoadFromFile',
    ]
    
    # Network operations
    NETWORK_OPERATIONS = [
        b'XMLHTTP',
        b'Send',
        b'ResponseBody',
        b'Open',
        b'User-Agent',
        b'Referer',
    ]
    
    # Process execution
    EXECUTION_PATTERNS = [
        rb'\.\s*Run\s*\(',
        rb'\.\s*Exec\s*\(',
        rb'Shell\s*\(',
        rb'eval\s*\(',
        rb'exec\s*\(',
        rb'Execute\s*\(',
    ]
    
    # Obfuscation patterns
    OBFUSCATION_PATTERNS = [
        rb'fromCharCode',           # String.fromCharCode()
        rb'charCodeAt',
        rb'%[0-9A-Fa-f]{2}',        # URL encoding
        rb'\\u[0-9A-Fa-f]{4}',       # Unicode escape
        rb'\\x[0-9A-Fa-f]{2}',       # Hex escape
    ]
    
    # Base64 patterns
    BASE64_PATTERNS = [
        rb'atob\s*\(',
        rb'btoa\s*\(',
        rb'Base64\.decode',
        rb'Base64\.encode',
    ]
    
    # PowerShell indicators
    POWERSHELL_PATTERNS = [
        b'powershell',
        b'-enc',
        b'-encodedcommand',
        b'IEX',
        b'Invoke-Expression',
        b'Net.WebClient',
        b'DownloadString',
        b'DownloadFile',
    ]
    
    def analyze(self, script_streams: Dict[str, bytes]) -> DetectionResult:
        """
        Analyze script streams for malicious patterns.
        
        Args:
            script_streams: Dictionary of script name -> content
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="script",
            name="스크립트 분석",
            name_en="Script Analysis"
        )
        
        if not script_streams:
            result.details = "스크립트가 발견되지 않았습니다."
            return result
        
        total_score = 0
        findings = []
        
        for script_name, data in script_streams.items():
            # 1. Check for COM objects
            com_objects = self._find_com_objects(data)
            for obj, severity in com_objects:
                result.add_indicator("COM_OBJECT", obj, severity)
                total_score += 25 if severity == "critical" else 15
                findings.append(f"COM object: {obj}")
            
            # 2. Check for file operations
            file_ops = self._find_file_operations(data)
            if file_ops:
                result.add_indicator(
                    "FILE_ACCESS",
                    f"{len(file_ops)}개 파일 작업",
                    "high"
                )
                total_score += 20
            
            # 3. Check for network operations
            net_ops = self._find_network_operations(data)
            if net_ops:
                result.add_indicator(
                    "NETWORK_ACCESS",
                    f"{len(net_ops)}개 네트워크 작업",
                    "medium"
                )
                total_score += 15
            
            # 4. Check for process execution
            exec_ops = self._find_execution(data)
            if exec_ops:
                result.add_indicator(
                    "PROCESS_EXECUTION",
                    f"실행 패턴: {len(exec_ops)}개",
                    "critical"
                )
                total_score += 30
                findings.append("Process execution detected")
            
            # 5. Check for obfuscation
            obf_count = self._count_obfuscation(data)
            if obf_count > 10:
                result.add_indicator(
                    "JAVASCRIPT_OBFUSCATION",
                    f"{obf_count}개 난독화 패턴",
                    "medium"
                )
                total_score += 15
            
            # 6. Check for Base64
            b64_count = self._count_base64(data)
            if b64_count > 0:
                result.add_indicator(
                    "BASE64_PAYLOAD",
                    f"{b64_count}개 Base64 패턴",
                    "high"
                )
                total_score += 20
            
            # 7. Check for PowerShell
            ps_count = self._count_powershell(data)
            if ps_count > 0:
                result.add_indicator(
                    "POWERSHELL",
                    f"{ps_count}개 PowerShell 인디케이터",
                    "high"
                )
                total_score += 20
                findings.append("PowerShell detected")
        
        result.score_contribution = min(total_score, 115)
        result.details = "; ".join(findings) if findings else "악성 스크립트 패턴이 발견되지 않았습니다."
        
        return result
    
    def _find_com_objects(self, data: bytes) -> List[tuple]:
        """Find COM object creation patterns."""
        found = []
        for obj, severity in self.COM_OBJECTS.items():
            if obj in data:
                found.append((obj.decode('ascii', errors='ignore'), severity))
        return found
    
    def _find_file_operations(self, data: bytes) -> List[str]:
        """Find file operation patterns."""
        found = []
        for op in self.FILE_OPERATIONS:
            if op in data:
                found.append(op.decode('ascii', errors='ignore'))
        return found
    
    def _find_network_operations(self, data: bytes) -> List[str]:
        """Find network operation patterns."""
        found = []
        for op in self.NETWORK_OPERATIONS:
            if op in data:
                found.append(op.decode('ascii', errors='ignore'))
        return found
    
    def _find_execution(self, data: bytes) -> List[str]:
        """Find process execution patterns."""
        found = []
        for pattern in self.EXECUTION_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                found.append(pattern.decode('ascii', errors='ignore'))
        return found
    
    def _count_obfuscation(self, data: bytes) -> int:
        """Count obfuscation patterns."""
        count = 0
        for pattern in self.OBFUSCATION_PATTERNS:
            count += len(re.findall(pattern, data, re.IGNORECASE))
        return count
    
    def _count_base64(self, data: bytes) -> int:
        """Count Base64 patterns."""
        count = 0
        for pattern in self.BASE64_PATTERNS:
            count += len(re.findall(pattern, data, re.IGNORECASE))
        return count
    
    def _count_powershell(self, data: bytes) -> int:
        """Count PowerShell indicators."""
        count = 0
        data_lower = data.lower()
        for pattern in self.POWERSHELL_PATTERNS:
            if pattern.lower() in data_lower:
                count += 1
        return count
