"""
Structural Anomaly Detection Module
Detects metadata anomalies and structural inconsistencies.
"""
import re
from typing import Dict, Any, Optional
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


class StructuralAnalyzer:
    """
    Analyzes document structure for anomalies.
    Detects suspicious metadata and structural inconsistencies.
    """
    
    # Suspicious author patterns
    SUSPICIOUS_AUTHORS = [
        '', 'admin', 'user', 'test', 'sample',
        'windows', 'unknown', 'null',
    ]
    
    # Machine name patterns
    MACHINE_PATTERNS = [
        rb'DESKTOP-[A-Z0-9]{7,8}',
        rb'LAPTOP-[A-Z0-9]{7,8}',
        rb'PC-[0-9]+',
        rb'WIN-[A-Z0-9]+',
        rb'USER-PC',
    ]
    
    def analyze(
        self,
        file_header: Dict[str, Any],
        doc_info: bytes,
        body_text: bytes,
        bindata_size: int
    ) -> DetectionResult:
        """
        Analyze document structure for anomalies.
        
        Args:
            file_header: Parsed file header info
            doc_info: DocInfo stream content
            body_text: BodyText stream content
            bindata_size: Total size of BinData streams
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="structural",
            name="구조적 이상 탐지",
            name_en="Structural Analysis"
        )
        
        total_score = 0
        findings = []
        
        # 1. Check author metadata
        author = file_header.get('author', '') or ''
        if not author or author.lower() in self.SUSPICIOUS_AUTHORS:
            result.add_indicator(
                "SUSPICIOUS_AUTHOR",
                f"작성자: '{author}'",
                "medium"
            )
            total_score += 10
            findings.append("Suspicious author name")
        
        # Check for machine name pattern
        for pattern in self.MACHINE_PATTERNS:
            if re.search(pattern, author.encode() if author else b'', re.IGNORECASE):
                result.add_indicator(
                    "MACHINE_AUTHOR",
                    f"머신명 작성자: {author}",
                    "medium"
                )
                total_score += 10
                findings.append("Machine-generated author name")
                break
        
        # 2. Check HWP version
        version = file_header.get('version', '')
        if version:
            try:
                major = int(version.split('.')[0])
                if major < 5:
                    result.add_indicator(
                        "LEGACY_VERSION",
                        f"레거시 버전: {version}",
                        "low"
                    )
                    total_score += 5
            except:
                pass
        
        # 3. Check encryption flag
        if file_header.get('is_encrypted'):
            result.add_indicator(
                "ENCRYPTED_DOCUMENT",
                "암호화된 문서 - 수동 검사 필요",
                "high"
            )
            total_score += 20
            findings.append("Encrypted document")
        
        # 4. Check content/body ratio
        body_size = len(body_text)
        
        if body_size > 0:
            ratio = bindata_size / body_size
            if ratio > 10:  # Binary is 10x larger than text
                result.add_indicator(
                    "CONTENT_MISMATCH",
                    f"BinData/BodyText 비율: {ratio:.1f}:1",
                    "medium"
                )
                total_score += 15
                findings.append("Large binary to text ratio")
        elif bindata_size > 1000:
            # No body text but significant binary data
            result.add_indicator(
                "NO_BODY_TEXT",
                f"본문 없음, BinData 크기: {bindata_size}",
                "high"
            )
            total_score += 20
            findings.append("No body text found")
        
        # 5. Check document size
        total_size = body_size + bindata_size
        if total_size < 100:
            result.add_indicator(
                "TINY_DOCUMENT",
                f"비정상적으로 작은 문서: {total_size} bytes",
                "medium"
            )
            total_score += 10
        
        # 6. Check script flag
        if file_header.get('has_script'):
            result.add_indicator(
                "SCRIPT_FLAG",
                "문서에 스크립트 포함 플래그 설정",
                "medium"
            )
            total_score += 10
        
        result.score_contribution = min(total_score, 110)
        result.details = "; ".join(findings) if findings else "구조적 이상이 발견되지 않았습니다."
        
        return result
