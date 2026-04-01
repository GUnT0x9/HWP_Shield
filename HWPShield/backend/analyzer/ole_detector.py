"""
OLE Object Detection Module
Detects embedded OLE objects and suspicious OLE patterns.
"""
import re
import struct
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


class OLEDetector:
    """
    Detector for embedded OLE objects.
    Targets: Post-2019 HWP attacks using OLE embedding.
    """
    
    OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    
    # Suspicious CLSIDs
    SUSPICIOUS_CLSIDS = [
        b'\x00\x02\x09\x05',  # Microsoft Equation (EQNEDT32) - vulnerable
        b'\x00\x02\x09\x00',  # Excel
        b'\x00\x02\x09\x06',  # Word
        b'\x00\x02\x09\x08',  # PowerPoint
    ]
    
    # Shell commands
    SHELL_COMMANDS = [
        b'cmd.exe', b'cmd',
        b'powershell', b'powershell.exe',
        b'powershell -enc', b'powershell -encodedcommand',
        b'wscript', b'wscript.exe',
        b'cscript', b'cscript.exe',
        b'rundll32', b'rundll32.exe',
        b'mshta', b'mshta.exe',
        b'IEX', b'Invoke-Expression',
        b'bitsadmin',
        b'regsvr32',
    ]
    
    # Auto-execution patterns
    AUTO_EXEC = [
        b'auto_open', b'autoexec',
        b'workbook_open', b'document_open',
        b'startup', b'auto_close',
    ]
    
    # Executable extensions
    EXEC_EXTENSIONS = [
        b'.exe', b'.dll', b'.scr',
        b'.bat', b'.cmd',
        b'.vbs', b'.vbe', b'.js',
        b'.ps1', b'.wsf', b'.hta',
        b'.jar', b'.com',
    ]
    
    def analyze(self, bindata_streams: List[Tuple[str, bytes]]) -> DetectionResult:
        """
        Analyze BinData streams for embedded OLE objects.
        
        Args:
            bindata_streams: List of (stream_name, data) tuples
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="ole",
            name="OLE 객체 탐지",
            name_en="OLE Object Detection"
        )
        
        total_score = 0
        findings = []
        
        for stream_name, data in bindata_streams:
            # Find nested OLE objects
            ole_positions = self._find_ole_objects(data)
            
            if ole_positions:
                for pos in ole_positions:
                    result.add_indicator(
                        "EMBEDDED_OLE",
                        f"{stream_name} @ offset {pos}",
                        "high"
                    )
                    total_score += 20
                    findings.append(f"Embedded OLE found in {stream_name}")
                    
                    # Analyze OLE header (first 4KB)
                    ole_header = data[pos:pos+4096]
                    
                    # Check CLSID
                    clsid = self._extract_clsid(ole_header)
                    if clsid:
                        result.add_indicator(
                            "OLE_CLSID",
                            f"CLSID: {clsid.hex()}",
                            "medium"
                        )
                        total_score += 5
                
                # Check for shell commands in entire stream
                shell_cmds = self._find_shell_commands(data)
                if shell_cmds:
                    result.add_indicator(
                        "SHELL_COMMAND",
                        f"발견: {', '.join(shell_cmds[:3])}",
                        "critical"
                    )
                    total_score += 35
                    findings.append("Shell command detected")
                
                # Check for UNC paths
                unc_paths = self._find_unc_paths(data)
                if unc_paths:
                    result.add_indicator(
                        "UNC_PATH",
                        f"원격 경로: {', '.join(unc_paths[:2])}",
                        "high"
                    )
                    total_score += 25
                
                # Check for auto-execution
                auto_exec = self._find_auto_exec(data)
                if auto_exec:
                    result.add_indicator(
                        "AUTO_EXEC",
                        f"자동 실행: {', '.join(auto_exec)}",
                        "critical"
                    )
                    total_score += 30
                
                # Check for executable references
                exec_refs = self._find_executable_refs(data)
                if exec_refs:
                    result.add_indicator(
                        "EXECUTABLE_REF",
                        f"실행 파일: {', '.join(exec_refs[:3])}",
                        "critical"
                    )
                    total_score += 30
        
        result.score_contribution = min(total_score, 145)
        result.details = "; ".join(findings) if findings else "OLE 객체 관련 위협이 발견되지 않았습니다."
        
        return result
    
    def _find_ole_objects(self, data: bytes) -> List[int]:
        """Find all OLE magic byte sequences in data."""
        positions = []
        start = 0
        
        while True:
            pos = data.find(self.OLE_MAGIC, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions
    
    def _extract_clsid(self, data: bytes) -> bytes:
        """Extract CLSID from OLE header."""
        # CLSID is at offset 0x14 (20 bytes from start)
        if len(data) >= 28:
            return data[20:28]
        return b''
    
    def _find_shell_commands(self, data: bytes) -> List[str]:
        """Find shell command strings."""
        found = []
        for cmd in self.SHELL_COMMANDS:
            if cmd.lower() in data.lower():
                found.append(cmd.decode('ascii', errors='ignore'))
        return found
    
    def _find_unc_paths(self, data: bytes) -> List[str]:
        """Find UNC path patterns."""
        pattern = rb'\\\\\\\\[\w\.-]+\\\\[\w\.-]+'
        matches = re.findall(pattern, data)
        return [m.decode('ascii', errors='ignore') for m in matches[:5]]
    
    def _find_auto_exec(self, data: bytes) -> List[str]:
        """Find auto-execution patterns."""
        found = []
        for pattern in self.AUTO_EXEC:
            if pattern in data:
                found.append(pattern.decode('ascii', errors='ignore'))
        return found
    
    def _find_executable_refs(self, data: bytes) -> List[str]:
        """Find executable file references."""
        found = []
        for ext in self.EXEC_EXTENSIONS:
            # Look for extension followed by non-alphanumeric or end
            pattern = re.escape(ext) + rb'[^a-zA-Z0-9]'
            if re.search(pattern, data, re.IGNORECASE):
                found.append(ext.decode('ascii', errors='ignore'))
        return found
