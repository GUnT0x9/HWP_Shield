"""
Threat Report Module
Handles reporting of suspicious files to threat intelligence centers.
"""
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class ReportCenter:
    """Threat reporting center information."""
    name: str
    name_ko: str
    url: str
    description: str
    description_ko: str
    supported_types: List[str]
    requires_account: bool = False


# Korean Threat Reporting Centers
REPORTING_CENTERS = {
    "krcert": ReportCenter(
        name="KrCERT/CC (KISA)",
        name_ko="한국인터넷진흥원 (KISA)",
        url="https://www.krcert.or.kr/krcert/report/reportIntro.do",
        description="Korea Internet & Security Agency - Official incident reporting",
        description_ko="한국인터넷진흥원 공식 인시던트 신고센터",
        supported_types=["malware", "phishing", "hacking"],
        requires_account=False
    ),
    "cyber110": ReportCenter(
        name="Cyber Cop (Police)",
        name_ko="사이버수사국 (경찰청)",
        url="https://cyberbureau.police.go.kr/prevention/sub4.jsp?mid=010505",
        description="Korean National Police Agency - Cybercrime reporting",
        description_ko="경찰청 사이버수사국 - 사이버범죄 신고",
        supported_types=["cybercrime", "hacking", "fraud"],
        requires_account=False
    ),
    "avvendor": ReportCenter(
        name="Antivirus Vendors",
        name_ko="백신 업체",
        url="https://www.ahnlab.com/site/submain/submain083.do",
        description="Submit suspicious samples to AhnLab, V3, etc.",
        description_ko="안랩, V3 등 백신 업체에 샘플 제출",
        supported_types=["malware", "virus"],
        requires_account=True
    ),
    "virustotal": ReportCenter(
        name="VirusTotal",
        name_ko="바이러스토탈",
        url="https://www.virustotal.com/gui/home/upload",
        description="Upload to VirusTotal for multi-engine scanning",
        description_ko="VirusTotal에 업로드하여 다중 엔진 검사",
        supported_types=["malware", "suspicious"],
        requires_account=False
    ),
}


def get_recommended_centers(risk_level: str, file_type: str = "hwp") -> List[ReportCenter]:
    """
    Get recommended reporting centers based on risk level.
    
    Args:
        risk_level: Overall risk level (MALICIOUS, HIGH_RISK, SUSPICIOUS)
        file_type: Type of suspicious file
        
    Returns:
        List of recommended ReportCenter objects
    """
    centers = []
    
    # For MALICIOUS or HIGH_RISK, recommend official channels
    if risk_level in ["MALICIOUS", "HIGH_RISK"]:
        centers.extend([
            REPORTING_CENTERS["krcert"],
            REPORTING_CENTERS["cyber110"],
        ])
    
    # Always recommend AV vendors and VirusTotal for analysis
    centers.extend([
        REPORTING_CENTERS["avvendor"],
        REPORTING_CENTERS["virustotal"],
    ])
    
    return centers


def generate_report_guidance(
    filename: str,
    risk_level: str,
    score: int,
    indicators: List[Dict],
    file_hash: Optional[str] = None
) -> Dict:
    """
    Generate comprehensive reporting guidance for users.
    
    Returns:
        Dictionary with guidance information
    """
    centers = get_recommended_centers(risk_level)
    
    # Severity-based guidance
    if risk_level == "MALICIOUS":
        priority = "CRITICAL"
        immediate_actions = [
            "네트워크에서 해당 파일이 있는 PC를 즉시 분리하세요",
            "해당 파일을 절대 실행하지 마세요",
            "보안팀 또는 IT 관리자에게 즉시 신고하세요",
        ]
    elif risk_level == "HIGH_RISK":
        priority = "HIGH"
        immediate_actions = [
            "해당 파일을 실행하지 마세요",
            "발신자를 확인하고 의심스러우면 신고하세요",
        ]
    elif risk_level == "SUSPICIOUS":
        priority = "MEDIUM"
        immediate_actions = [
            "발신자를 확인하고 주의해서 사용하세요",
        ]
    else:
        priority = "LOW"
        immediate_actions = []
    
    # Generate summary for reporting
    indicator_summary = []
    for ind in indicators[:5]:  # Top 5 indicators
        indicator_summary.append(f"- {ind['type']}: {ind['value']}")
    
    return {
        "priority": priority,
        "immediate_actions": immediate_actions,
        "reporting_centers": [
            {
                "id": key,
                "name": center.name_ko,
                "name_en": center.name,
                "url": center.url,
                "description": center.description_ko,
                "requires_account": center.requires_account,
            }
            for key, center in [(c.name.lower().replace(" ", "_"), c) for c in centers]
        ],
        "report_template": {
            "title": f"의심 HWP 파일 신고 - {filename}",
            "content": f"""파일명: {filename}
파일 해시 (MD5): {file_hash or "N/A"}
위험 등급: {risk_level}
위험 점수: {score}/100

주요 발견 지표:
{chr(10).join(indicator_summary)}

분석 도구: HWPShield
"""
        },
        "disclaimer": "본 분석 결과는 참고용이며, 최종 악성 여부는 추가 분석이 필요합니다."
    }


def format_reporting_ui_data(risk_level: str, score: int) -> Dict:
    """Format data for reporting UI component."""
    show_reporting = risk_level in ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS"]
    
    urgency_texts = {
        "MALICIOUS": {
            "title": "🚨 즉시 신고 필요",
            "description": "악성 코드가 탐지되었습니다. 관련 기관에 신고하세요.",
            "color": "red",
        },
        "HIGH_RISK": {
            "title": "⚠️ 신고 권장",
            "description": "높은 위험이 탐지되었습니다. 신고를 검토하세요.",
            "color": "orange",
        },
        "SUSPICIOUS": {
            "title": "📋 정보 제공",
            "description": "추가 분석을 위해 제보할 수 있습니다.",
            "color": "yellow",
        },
    }
    
    return {
        "show_reporting_section": show_reporting,
        "urgency": urgency_texts.get(risk_level),
        "centers": get_recommended_centers(risk_level) if show_reporting else [],
    }
