# 05. 리스크 스코어링 시스템 (Risk Scoring System)

## 스코어링 개요

HWPShield의 리스크 스코어링은 **누적 점수(cumulative scoring)** 방식을 사용합니다. 각 탐지 모듈에서 발견된 지표(indicator)마다 점수가 부여되며, 최종 합계로 위험 등급이 결정됩니다.

### 스코어링 철학

- **보수적 접근**: 의심스러운 패턴에 즉시 점수 부여
- **누적 효과**: 다중 지표가 복합적 위험을 반영
- **APT 지향**: 실제 APT 캠페인 패턴에 최적화
- **오탐 최소화**: 낮은 점수부터 점진적 상승

---

## 점수 체계

### 모듈별 점수 매트릭스

#### Module 1: EPS/PostScript 탐지 (eps_detector)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| EPS_STREAM | +10 | MEDIUM | EPS 파일 발견 |
| CVE_2017_8291 | +30 | CRITICAL | .eqproc 트리거 |
| HEX_SHELLCODE | +20 | HIGH | 16진수 쉘코드 패턴 |
| WIN32_APIS | +25 | CRITICAL | Win32 API 문자열 |
| OBFUSCATION | +10 | MEDIUM | 난독화 패턴 |

**최대 점수**: +95

#### Module 2: OLE 객체 탐지 (ole_detector)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| EMBEDDED_OLE | +20 | HIGH | OLE 객체 포함 |
| OLE_CLSID | +5 | LOW | CLSID 식별 |
| SHELL_COMMAND | +35 | CRITICAL | cmd/powershell |
| UNC_PATH | +25 | HIGH | 원격 경로 |
| AUTO_EXEC | +30 | CRITICAL | 자동 실행 |
| EXECUTABLE_REF | +30 | CRITICAL | .exe/.dll 참조 |

**최대 점수**: +145

#### Module 3: 스크립트 분석 (script_detector)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| COM_OBJECT | +15 | MEDIUM | COM 객체 생성 |
| FILE_ACCESS | +20 | HIGH | 파일 시스템 접근 |
| NETWORK_ACCESS | +15 | MEDIUM | 네트워크 접근 |
| PROCESS_EXECUTION | +30 | CRITICAL | 프로세스 실행 |
| JAVASCRIPT_OBFUSCATION | +15 | MEDIUM | JS 난독화 |
| BASE64_PAYLOAD | +20 | HIGH | Base64 페이로드 |

**최대 점수**: +115

#### Module 4: IOC 추출 (ioc_extractor)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| URL | +15 | MEDIUM | 외부 URL |
| URL_SUSPICIOUS | +20 | MEDIUM | 의심 도메인 |
| IP_PUBLIC | +15 | MEDIUM | 공인 IP |
| PATH_TEMP | +20 | HIGH | TEMP/APPDATA 경로 |
| REGISTRY | +15 | MEDIUM | 레지스트리 경로 |
| HASH | +0 | INFO | 해시 (정보만) |

**최대 점수**: +85

#### Module 5: 스테가노그래피 탐지 (steg_detector)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| IMAGE_FOUND | +0 | INFO | 이미지 발견 |
| OVERSIZED_IMAGE | +10 | MEDIUM | 과대 크기 |
| PE_IN_IMAGE | +30 | CRITICAL | PE 파일 포함 |
| PE_SIGNATURE | +20 | HIGH | PE 시그니처 |
| HIGH_ENTROPY | +15 | HIGH | 높은 엔트로피 |
| JPEG_EOF_ANOMALY | +10 | MEDIUM | EOF 이상 |

**최대 점수**: +85

#### Module 6: 구조적 이상 (structural_analyzer)

| 지표 | 점수 | 위험도 | 설명 |
|------|------|--------|------|
| SUSPICIOUS_AUTHOR | +10 | MEDIUM | 의심 작성자 |
| MACHINE_AUTHOR | +10 | MEDIUM | 머신명 작성자 |
| LEGACY_VERSION | +5 | LOW | 레거시 버전 |
| ENCRYPTED_DOCUMENT | +20 | HIGH | 암호화 문서 |
| CONTENT_MISMATCH | +15 | MEDIUM | 콘텐츠 불일치 |
| NO_BODY_TEXT | +20 | HIGH | 본문 없음 |
| TIMESTAMP_ANOMALY | +10 | MEDIUM | 시간 이상 |
| TINY_DOCUMENT | +10 | MEDIUM | 매우 작음 |
| SCRIPT_FLAG | +10 | MEDIUM | 스크립트 플래그 |

**최대 점수**: +110

---

## 위험 등급

### 등급 임계값

```
0        15       35       60         100+
|---------|---------|---------|----------|
  CLEAN   SUSPICIOUS HIGH   MALICIOUS
```

| 등급 | 점수 범위 | 색상 | 설명 | 조치 |
|------|----------|------|------|------|
| **CLEAN** | 0-14 | 녹색 🟢 | 안전한 문서 | 정상 사용 가능 |
| **SUSPICIOUS** | 15-34 | 노란색 🟡 | 주의 필요 | 검증 후 사용 |
| **HIGH RISK** | 35-59 | 주황색 🟠 | 위험 의심 | 실행 금지, 분석 필요 |
| **MALICIOUS** | 60+ | 빨간색 🔴 | 악성 확실 | 즉시 차단, 보고 필수 |

### 등급별 권고사항

#### CLEAN (0-14)
```
✓ 정상 문서로 판단됩니다
✓ 바이러스 백신과 별도로 추가 검사 불필요
✓ 일반적인 용도로 사용 가능

참고: 분석 결과만으로 100% 안전을 보장하지는 않습니다.
```

#### SUSPICIOUS (15-34)
```
⚠ 의심스러운 요소가 발견되었습니다
⚠ 문서 출처를 확인하세요
⚠ 실행 시 주의가 필요합니다

권고: 발신자 확인, 샌드박스에서 미리 실행 테스트
```

#### HIGH RISK (35-59)
```
⚠⚠ 높은 위험 요소가 발견되었습니다
⚠⚠ 문서를 열지 마세요
⚠⚠ 보안팀에 문의하세요

권고: 즉시 실행 중단, CISO/보안팀 보고, 격리 조치
```

#### MALICIOUS (60+)
```
🚨 악성 코드가 탐지되었습니다
🚨 절대 실행하지 마세요
🚨 즉시 보안팀에 신고하세요

조치: 네트워크 분리, 디스크 이미징, 포렌식 수집
```

---

## 스코어링 엔진 구현

### scorer.py 핵심 로직

```python
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict

class RiskLevel(Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"

@dataclass
class Indicator:
    type: str
    description: str
    severity: str
    score: int

class RiskScorer:
    # 점수 매트릭스
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
        
        # IOC Extractor
        'URL': 15,
        'URL_SUSPICIOUS': 20,
        'IP': 15,
        'PATH_TEMP': 20,
        'REGISTRY': 15,
        'HASH': 0,
        
        # Steg Detector
        'IMAGE_FOUND': 0,
        'OVERSIZED_IMAGE': 10,
        'PE_IN_IMAGE': 30,
        'PE_SIGNATURE': 20,
        'HIGH_ENTROPY': 15,
        'JPEG_EOF_ANOMALY': 10,
        
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
    
    # 등급 임계값
    THRESHOLDS = {
        RiskLevel.CLEAN: (0, 14),
        RiskLevel.SUSPICIOUS: (15, 34),
        RiskLevel.HIGH_RISK: (35, 59),
        RiskLevel.MALICIOUS: (60, 1000),  # 상한선 없음
    }
    
    def calculate_score(self, module_results: List[Dict]) -> Dict:
        """최종 점수 계산"""
        total_score = 0
        indicators = []
        
        for module in module_results:
            for indicator in module.get('indicators', []):
                ind_type = indicator['type']
                score = self.SCORE_MATRIX.get(ind_type, 0)
                
                indicators.append(Indicator(
                    type=ind_type,
                    description=indicator['value'],
                    severity=indicator['severity'],
                    score=score
                ))
                
                total_score += score
        
        # 최대 100점으로 제한
        capped_score = min(total_score, 100)
        
        # 등급 결정
        risk_level = self._determine_risk_level(capped_score)
        
        return {
            'total_score': capped_score,
            'raw_score': total_score,
            'risk_level': risk_level.value,
            'indicators': indicators,
            'threshold_exceeded': total_score > 100,
        }
    
    def _determine_risk_level(self, score: int) -> RiskLevel:
        """점수로 등급 결정"""
        for level, (min_score, max_score) in self.THRESHOLDS.items():
            if min_score <= score <= max_score:
                return level
        return RiskLevel.MALICIOUS  # 기본값
    
    def get_recommendation(self, risk_level: RiskLevel) -> str:
        """등급별 권고사항"""
        recommendations = {
            RiskLevel.CLEAN: "정상 문서입니다. 일반적인 용도로 사용 가능합니다.",
            RiskLevel.SUSPICIOUS: 
                "의심스러운 요소가 발견되었습니다. 출처를 확인하고 주의해서 사용하세요.",
            RiskLevel.HIGH_RISK: 
                "높은 위험이 탐지되었습니다. 실행하지 말고 보안팀에 문의하세요.",
            RiskLevel.MALICIOUS: 
                "악성 코드가 탐지되었습니다. 절대 실행하지 말고 즉시 보안팀에 신고하세요.",
        }
        return recommendations.get(risk_level, "알 수 없음")


# 실제 사용 예시
scorer = RiskScorer()

module_results = [
    {
        'module_id': 'eps',
        'indicators': [
            {'type': 'EPS_STREAM', 'value': 'Bin0000', 'severity': 'medium'},
            {'type': 'CVE-2017-8291', 'value': '.eqproc', 'severity': 'critical'},
        ]
    },
    {
        'module_id': 'ioc',
        'indicators': [
            {'type': 'URL', 'value': 'http://evil.com/payload', 'severity': 'high'},
        ]
    }
]

result = scorer.calculate_score(module_results)
# result: {
#   'total_score': 55,
#   'risk_level': 'HIGH_RISK',
#   ...
# }
```

---

## 시각화

### 점수 미터 (Score Meter)

```
위험 점수: 55 / 100
████████████████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░

[주황색] HIGH RISK - 높은 위험
```

### 리스크 배지 (Risk Badge)

| 등급 | 배지 디자인 |
|------|-------------|
| CLEAN | 🟢 **CLEAN** - 안전 |
| SUSPICIOUS | 🟡 **SUSPICIOUS** - 주의 |
| HIGH RISK | 🟠 **HIGH RISK** - 위험 |
| MALICIOUS | 🔴 **MALICIOUS** - 악성 |

---

## 튜닝 및 보정

### 민감도 조정

현재 점수는 APT 캠페인에 최적화되어 있습니다. 환경에 따라 조정 가능:

```python
# 기업 환경 (높은 보안)
CORPORATE_MULTIPLIER = 1.2  # 20% 점수 상향

# 일반 사용자 (낮은 오탐)
CONSUMER_MULTIPLIER = 0.8   # 20% 점수 하향
```

### 화이트리스트

정상 문서에서 자주 오탐되는 패턴은 화이트리스트 처리:

```python
WHITELIST_PATTERNS = [
    {'type': 'URL', 'pattern': r'microsoft\\.com'},
    {'type': 'URL', 'pattern': r'hancom\\.com'},
    {'type': 'AUTHOR', 'pattern': r'@company\\.com$'},
]
```

### 가중치 동적 조정

```python
def adjust_weights(context: dict) -> dict:
    """컨텍스트에 따른 가중치 조정"""
    weights = BASE_WEIGHTS.copy()
    
    if context.get('known_apt_target'):
        # APT 타겟 조직은 보수적으로
        weights['SHELL_COMMAND'] *= 1.5
        weights['PROCESS_EXECUTION'] *= 1.5
    
    if context.get('internal_document'):
        # 내부 문서는 관대하게
        weights['SUSPICIOUS_AUTHOR'] *= 0.5
    
    return weights
```

---

## 성능 지표

### 목표 정확도

| 메트릭 | 목표값 | 측정 방법 |
|--------|--------|----------|
| 탐지율 (Recall) | > 95% | 알려진 악성 샘플 테스트 |
| 정확도 (Precision) | > 90% | 오탐 샘플 분석 |
| F1 Score | > 0.92 | 탐지율 + 정확도 조합 |
| 오탐율 (FPR) | < 5% | 정상 문서 세트 테스트 |

### 벤치마크 테스트 셋

```
test_samples/
├── malicious/
│   ├── ghostbutt_samples/      # CVE-2017-8291 (50개)
│   ├── ole_injection/          # OLE 객체 (30개)
│   ├── macro_scripts/          # 스크립트 (25개)
│   └── steganography/          # 스테가노그래피 (15개)
│
└── benign/
    ├── normal_hwp/             # 일반 문서 (100개)
    ├── with_images/            # 이미지 포함 (50개)
    └── with_macros_legit/      # 정상 매크로 (20개)
```
