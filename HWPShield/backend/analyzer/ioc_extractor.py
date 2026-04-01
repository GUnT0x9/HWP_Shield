"""
IOC (Indicator of Compromise) Extraction Module
Extracts URLs, IPs, file paths, and other IOCs from document content.
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


class IOCExtractor:
    """
    Extracts Indicators of Compromise from document content.
    """
    
    # Regex patterns
    URL_PATTERN = re.compile(
        rb'https?://[\w\-\.]+[^\s\"<>{}|\^`\[\]]*',
        re.IGNORECASE
    )
    
    IP_PATTERN = re.compile(
        rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    EMAIL_PATTERN = re.compile(
        rb'[\w\.+-]+@[\w\.-]+\.[\w\.]+'
    )
    
    REGISTRY_PATTERN = re.compile(
        rb'HKEY_[A-Z_]+\\[\w\\]+|HK(?:LM|CU|CR|U|CC)\\[\w\\]+',
        re.IGNORECASE
    )
    
    # Suspicious TLDs (commonly used in malicious domains)
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club', '.online']
    
    # File hosting services (often abused)
    FILE_HOSTING = ['pastebin', 'githubusercontent', 'drive.google', 'dropbox', 'mega']
    
    def analyze(self, all_streams: Dict[str, bytes]) -> DetectionResult:
        """
        Extract IOCs from all document streams.
        
        Args:
            all_streams: Dictionary of stream name -> content
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="ioc",
            name="IOC 추출",
            name_en="IOC Extraction"
        )
        
        total_score = 0
        iocs = []
        
        # Combine all stream data
        combined_data = b''.join(all_streams.values())
        
        # 1. Extract URLs
        urls = self._extract_urls(combined_data)
        for url in urls:
            severity = self._assess_url_severity(url)
            iocs.append({"type": "url", "value": url, "severity": severity})
            result.add_indicator(f"URL_{severity.upper()}", url, severity)
            total_score += 15 if severity == "low" else 20
        
        # 2. Extract IPs
        ips = self._extract_ips(combined_data)
        for ip in ips:
            if not self._is_private_ip(ip):
                iocs.append({"type": "ip", "value": ip, "severity": "high"})
                result.add_indicator("IP_PUBLIC", ip, "high")
                total_score += 15
            else:
                iocs.append({"type": "ip", "value": ip, "severity": "low"})
        
        # 3. Extract file paths
        paths = self._extract_paths(combined_data)
        for path in paths:
            severity = self._assess_path_severity(path)
            iocs.append({"type": "path", "value": path, "severity": severity})
            if severity in ["high", "critical"]:
                result.add_indicator("PATH_SUSPICIOUS", path, severity)
                total_score += 20
        
        # 4. Extract registry paths
        reg_paths = self._extract_registry(combined_data)
        for reg in reg_paths:
            iocs.append({"type": "registry", "value": reg, "severity": "high"})
            result.add_indicator("REGISTRY", reg, "high")
            total_score += 15
        
        # 5. Extract hashes
        hashes = self._extract_hashes(combined_data)
        for h in hashes:
            iocs.append({"type": "hash", "value": h, "severity": "info"})
        
        # Remove duplicates
        unique_iocs = self._deduplicate_iocs(iocs)
        
        result.score_contribution = min(total_score, 85)
        result.details = f"{len(unique_iocs)}개 IOC 추출됨" if unique_iocs else "IOC가 발견되지 않았습니다."
        
        return result
    
    def _extract_urls(self, data: bytes) -> List[str]:
        """Extract URLs from data."""
        matches = self.URL_PATTERN.findall(data)
        urls = []
        for match in matches:
            try:
                url = match.decode('ascii', errors='ignore')
                if len(url) > 10:  # Filter out short matches
                    urls.append(url)
            except:
                pass
        return list(set(urls))[:20]  # Limit and deduplicate
    
    def _extract_ips(self, data: bytes) -> List[str]:
        """Extract IP addresses."""
        matches = self.IP_PATTERN.findall(data)
        ips = []
        for match in matches:
            try:
                ip = match.decode('ascii', errors='ignore')
                ips.append(ip)
            except:
                pass
        return list(set(ips))[:20]
    
    def _extract_paths(self, data: bytes) -> List[str]:
        """Extract file paths."""
        # Windows paths
        patterns = [
            rb'%[A-Z_0-9]+%\\[^\s]+',
            rb'C:\\[^\s]+',
            rb'\\\\[^\s]+',
        ]
        
        paths = []
        for pattern in patterns:
            matches = re.findall(pattern, data)
            for match in matches:
                try:
                    path = match.decode('ascii', errors='ignore')
                    if len(path) > 5:
                        paths.append(path)
                except:
                    pass
        
        return list(set(paths))[:20]
    
    def _extract_registry(self, data: bytes) -> List[str]:
        """Extract registry paths."""
        matches = self.REGISTRY_PATTERN.findall(data)
        reg_paths = []
        for match in matches:
            try:
                reg = match.decode('ascii', errors='ignore')
                reg_paths.append(reg)
            except:
                pass
        return list(set(reg_paths))[:10]
    
    def _extract_hashes(self, data: bytes) -> List[str]:
        """Extract hash patterns (MD5, SHA1, SHA256)."""
        # MD5: 32 hex chars
        md5_pattern = rb'\b[a-f0-9]{32}\b'
        # SHA1: 40 hex chars
        sha1_pattern = rb'\b[a-f0-9]{40}\b'
        # SHA256: 64 hex chars
        sha256_pattern = rb'\b[a-f0-9]{64}\b'
        
        hashes = []
        for pattern in [md5_pattern, sha1_pattern, sha256_pattern]:
            matches = re.findall(pattern, data, re.IGNORECASE)
            for match in matches[:5]:
                try:
                    h = match.decode('ascii', errors='ignore')
                    hashes.append(h)
                except:
                    pass
        
        return list(set(hashes))[:15]
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC1918)."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
        except:
            return False
        
        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if first == 127:
            return True
        
        return False
    
    def _assess_url_severity(self, url: str) -> str:
        """Assess severity of a URL."""
        url_lower = url.lower()
        
        # Check for file hosting services
        for hosting in self.FILE_HOSTING:
            if hosting in url_lower:
                return "high"
        
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or f"{tld}/" in url_lower:
                return "medium"
        
        # Check for executable downloads
        if any(ext in url_lower for ext in ['.exe', '.dll', '.zip', '.rar', '.ps1']):
            return "medium"
        
        return "low"
    
    def _assess_path_severity(self, path: str) -> str:
        """Assess severity of a file path."""
        path_upper = path.upper()
        
        # Critical system paths
        critical = ['%TEMP%', '%APPDATA%', '%LOCALAPPDATA%', 'WINDOWS\\SYSTEM32']
        for cp in critical:
            if cp in path_upper:
                return "high"
        
        # Executable extensions
        if any(ext in path.upper() for ext in ['.EXE', '.DLL', '.BAT', '.PS1', '.VBS']):
            return "high"
        
        return "low"
    
    def _deduplicate_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs."""
        seen = set()
        unique = []
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique
