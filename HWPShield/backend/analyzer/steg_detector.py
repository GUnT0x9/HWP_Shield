"""
Steganography Detection Module
Detects hidden data in images (JPEG, PNG) using steganography.
Targets: RedEyes M2RAT campaign (2023).
"""
import math
from typing import List, Dict, Tuple, Any, Optional
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


class StegDetector:
    """
    Detector for steganography in image files.
    Detects PE files hidden in JPEG/PNG images.
    """
    
    # Image signatures
    IMAGE_SIGNATURES = {
        b'\xff\xd8\xff': 'JPEG',
        b'\x89PNG': 'PNG',
        b'GIF87a': 'GIF',
        b'GIF89a': 'GIF',
        b'BM': 'BMP',
    }
    
    # Image end markers
    JPEG_EOI = b'\xff\xd9'
    
    # PE signatures
    PE_MAGIC = b'MZ'
    PE_SIGNATURE = b'PE\x00\x00'
    
    def analyze(self, bindata_streams: List[Tuple[str, bytes]]) -> DetectionResult:
        """
        Analyze BinData streams for steganography.
        
        Args:
            bindata_streams: List of (stream_name, data) tuples
            
        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(
            module_id="steg",
            name="스테가노그래피 탐지",
            name_en="Steganography Detection"
        )
        
        total_score = 0
        findings = []
        
        for stream_name, data in bindata_streams:
            # Identify image type
            image_type = self._identify_image_type(data)
            if not image_type:
                continue
            
            result.add_indicator("IMAGE_FOUND", f"{stream_name}: {image_type}", "info")
            
            # Analyze based on image type
            if image_type == 'JPEG':
                findings.extend(self._analyze_jpeg(data, stream_name, result, total_score))
            elif image_type == 'PNG':
                findings.extend(self._analyze_png(data, stream_name, result, total_score))
        
        # Calculate final score from indicators
        total_score = sum(
            30 if ind["severity"] == "critical" else
            20 if ind["severity"] == "high" else
            10 if ind["severity"] == "medium" else 0
            for ind in result.indicators
        )
        
        result.score_contribution = min(total_score, 85)
        result.details = "; ".join(findings) if findings else "스테가노그래피 패턴이 발견되지 않았습니다."
        
        return result
    
    def _identify_image_type(self, data: bytes) -> Optional[str]:
        """Identify image type by magic bytes."""
        for sig, img_type in self.IMAGE_SIGNATURES.items():
            if data.startswith(sig):
                return img_type
        return None
    
    def _analyze_jpeg(self, data: bytes, stream_name: str, 
                      result: DetectionResult, score: int) -> List[str]:
        """Analyze JPEG file for steganography."""
        findings = []
        
        # Find EOI (End of Image) marker
        eoi_pos = data.rfind(self.JPEG_EOI)
        
        if eoi_pos == -1:
            result.add_indicator("JPEG_NO_EOI", f"{stream_name}: EOI 마커 없음", "medium")
            return findings
        
        # Check for data after EOI
        trailing_data = data[eoi_pos + 2:]
        
        if trailing_data:
            # Check for PE header
            if trailing_data.startswith(self.PE_MAGIC):
                result.add_indicator(
                    "PE_IN_JPEG",
                    f"{stream_name}: JPEG EOI 이후 PE 실행 파일 발견",
                    "critical"
                )
                findings.append(f"Hidden PE executable in {stream_name}")
            
            # Check for PE signature
            pe_pos = trailing_data.find(self.PE_SIGNATURE)
            if pe_pos != -1:
                result.add_indicator(
                    "PE_SIGNATURE",
                    f"{stream_name}: PE 시그니처 @ offset {pe_pos}",
                    "high"
                )
            
            # Calculate entropy of trailing data
            entropy = self._calculate_entropy(trailing_data)
            if entropy > 7.5:
                result.add_indicator(
                    "HIGH_ENTROPY_TRAILING",
                    f"{stream_name}: 트레일링 데이터 엔트로피 {entropy:.2f}",
                    "high"
                )
                findings.append(f"High entropy trailing data in {stream_name}")
        
        # Check file size vs expected content size
        image_size = eoi_pos + 2
        actual_size = len(data)
        
        if actual_size > image_size * 1.5:
            ratio = actual_size / image_size
            result.add_indicator(
                "OVERSIZED_JPEG",
                f"{stream_name}: 크기 비율 {ratio:.1f}x (예상: {image_size}, 실제: {actual_size})",
                "medium"
            )
        
        return findings
    
    def _analyze_png(self, data: bytes, stream_name: str,
                    result: DetectionResult, score: int) -> List[str]:
        """Analyze PNG file for steganography."""
        findings = []
        
        # PNG ends with IEND chunk
        iend_pos = data.rfind(b'IEND')
        
        if iend_pos == -1:
            return findings
        
        # IEND chunk: 4 bytes length + "IEND" + 4 bytes CRC
        chunk_end = iend_pos + 4 + 4  # "IEND" + CRC
        
        if chunk_end < len(data):
            trailing_data = data[chunk_end:]
            
            # Check for PE header
            if trailing_data.startswith(self.PE_MAGIC):
                result.add_indicator(
                    "PE_IN_PNG",
                    f"{stream_name}: PNG IEND 이후 PE 실행 파일 발견",
                    "critical"
                )
                findings.append(f"Hidden PE executable in {stream_name}")
            
            # Check entropy
            entropy = self._calculate_entropy(trailing_data)
            if entropy > 7.5:
                result.add_indicator(
                    "HIGH_ENTROPY_PNG",
                    f"{stream_name}: PNG 트레일링 엔트로피 {entropy:.2f}",
                    "high"
                )
        
        return findings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        Returns value between 0 and 8 (bits per byte).
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        data_len = len(data)
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            frequency = count / data_len
            if frequency > 0:
                entropy -= frequency * math.log2(frequency)
        
        return entropy
    
    def _get_image_data_size(self, data: bytes, image_type: str) -> int:
        """Estimate expected image data size."""
        # This is a simplified estimation
        if image_type == 'JPEG':
            # Find SOI and EOI
            soi = data.find(b'\xff\xd8')
            eoi = data.rfind(b'\xff\xd9')
            if soi != -1 and eoi != -1:
                return eoi - soi + 2
        
        return len(data)
