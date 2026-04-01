"""
Risk Scoring Module
Calculates overall risk score from all detection modules.
"""
from enum import Enum
from typing import List, Dict, Any
from dataclasses import dataclass


class RiskLevel(Enum):
    """Risk level enumeration."""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"


@dataclass
class ScoringResult:
    """Scoring result container."""
    total_score: int
    raw_score: int
    risk_level: str
    recommendation: str
    threshold_exceeded: bool


class RiskScorer:
    """
    Calculates risk scores based on detection results.
    """
    
    # Score matrix - indicator type to score mapping
    SCORE_MATRIX = {
        # EPS Detector
        'EPS_STREAM': 10,
        'CVE-2017-8291': 30,
        'HEX_SHELLCODE': 20,
        'WIN32_APIS': 25,
        'OBFUSCATION': 10,
        
        # OLE Detector
        'EMBEDDED_OLE': 20,
        'OLE_CLSID': 5,
        'SHELL_COMMAND': 35,
        'UNC_PATH': 25,
        'AUTO_EXEC': 30,
        'EXECUTABLE_REF': 30,
        
        # Script Detector
        'COM_OBJECT': 15,
        'FILE_ACCESS': 20,
        'NETWORK_ACCESS': 15,
        'PROCESS_EXECUTION': 30,
        'JAVASCRIPT_OBFUSCATION': 15,
        'BASE64_PAYLOAD': 20,
        'POWERSHELL': 20,
        
        # IOC Extractor
        'URL_LOW': 15,
        'URL_MEDIUM': 20,
        'URL_HIGH': 25,
        'IP_PUBLIC': 15,
        'PATH_SUSPICIOUS': 20,
        'REGISTRY': 15,
        
        # Steg Detector
        'OVERSized_JPEG': 10,
        'JPEG_NO_EOI': 10,
        'PE_IN_JPEG': 30,
        'PE_IN_PNG': 30,
        'PE_SIGNATURE': 20,
        'HIGH_ENTROPY_TRAILING': 15,
        'HIGH_ENTROPY_PNG': 15,
        'IMAGE_FOUND': 0,
        
        # Structural Analyzer
        'SUSPICIOUS_AUTHOR': 10,
        'MACHINE_AUTHOR': 10,
        'LEGACY_VERSION': 5,
        'ENCRYPTED_DOCUMENT': 20,
        'CONTENT_MISMATCH': 15,
        'NO_BODY_TEXT': 20,
        'TIMESTAMP_ANOMALY': 10,
        'TINY_DOCUMENT': 10,
        'SCRIPT_FLAG': 10,
    }
    
    # Risk level thresholds
    THRESHOLDS = {
        RiskLevel.CLEAN: (0, 14),
        RiskLevel.SUSPICIOUS: (15, 34),
        RiskLevel.HIGH_RISK: (35, 59),
        RiskLevel.MALICIOUS: (60, 1000),
    }
    
    # Recommendations by risk level (Korean)
    RECOMMENDATIONS = {
        RiskLevel.CLEAN: "정상 문서로 판단됩니다. 일반적인 용도로 사용 가능합니다.",
        RiskLevel.SUSPICIOUS: "의심스러운 요소가 발견되었습니다. 출처를 확인하고 주의해서 사용하세요.",
        RiskLevel.HIGH_RISK: "높은 위험이 탐지되었습니다. 실행하지 말고 보안팀에 문의하세요.",
        RiskLevel.MALICIOUS: "악성 코드가 탐지되었습니다. 절대 실행하지 말고 즉시 보안팀에 신고하세요.",
    }
    
    def calculate_score(self, module_results: List[Dict]) -> ScoringResult:
        """
        Calculate overall risk score from module results.
        
        Args:
            module_results: List of module detection results
            
        Returns:
            ScoringResult with score and risk level
        """
        total_score = 0
        
        for module in module_results:
            if not isinstance(module, dict):
                continue
            for indicator in module.get('indicators', []):
                if not isinstance(indicator, dict):
                    continue
                ind_type = indicator.get('type', '')
                severity = indicator.get('severity', 'low')
                
                # Get base score from matrix
                score = self.SCORE_MATRIX.get(ind_type, 0)
                
                # Adjust score based on severity if needed
                if ind_type.startswith('URL_') and severity in ['low', 'medium', 'high']:
                    score = self.SCORE_MATRIX.get(f'URL_{severity.upper()}', 15)
                
                total_score += score
        
        # Cap at 100
        capped_score = min(total_score, 100)
        
        # Determine risk level
        risk_level = self._determine_risk_level(capped_score)
        
        return ScoringResult(
            total_score=capped_score,
            raw_score=total_score,
            risk_level=risk_level.value,
            recommendation=self.RECOMMENDATIONS[risk_level],
            threshold_exceeded=total_score > 100
        )
    
    def _determine_risk_level(self, score: int) -> RiskLevel:
        """Determine risk level from score."""
        for level, (min_score, max_score) in self.THRESHOLDS.items():
            if min_score <= score <= max_score:
                return level
        return RiskLevel.MALICIOUS
    
    def get_risk_color(self, risk_level: str) -> str:
        """Get color code for risk level."""
        colors = {
            "CLEAN": "green",
            "SUSPICIOUS": "yellow",
            "HIGH_RISK": "orange",
            "MALICIOUS": "red"
        }
        return colors.get(risk_level, "gray")
    
    def get_risk_badge_class(self, risk_level: str) -> str:
        """Get CSS class for risk badge."""
        classes = {
            "CLEAN": "bg-green-500 text-white",
            "SUSPICIOUS": "bg-yellow-500 text-black",
            "HIGH_RISK": "bg-orange-500 text-white",
            "MALICIOUS": "bg-red-600 text-white"
        }
        return classes.get(risk_level, "bg-gray-500 text-white")
