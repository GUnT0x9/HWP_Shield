# HWPShield - 한글 문서 보안 분석 도구

> **한글 문서를 안전하게 열람할 수 있도록 도우는 사이트**

HWPShield는 한글 문서(.hwp, .hwpx)의 악성코드 위협을 탐지하고 분석하는 웹 기반 보안 도구입니다. 
불확실한 한글 문서를 열기 전에 안전성을 검사하여 사용자의 시스템을 보호합니다.

---

## 목차

- [프로젝트 개요](#프로젝트-개요)
- [시작하기](#시작하기)
- [아키텍처](#아키텍처)
- [주요 기능](#주요-기능)
- [위협 탐지 모듈](#위협-탐지-모듈)
- [API 명세](#api-명세)
- [보안 원칙](#보안-원칙)
- [폴더 구조](#폴더-구조)

---

## 프로젝트 개요

HWPShield는 **한글 문서 파일의 보안 위협을 실시간으로 분석**하여 사용자가 안심하고 문서를 열람할 수 있도록 돕는 도구입니다.

### 핵심 목표

- 한글 문서 내 잠재적 악성코드 탐지
- 웹 인터페이스를 통한 쉬운 파일 분석
- 정적 분석(Static Analysis)만을 통한 안전한 검사
- 상세한 위협 분석 리포트 제공

### 지원 파일 형식

| 형식 | 확장자 | 지원 상태 |
|------|--------|-----------|
| 한글 문서 | .hwp | ✅ 지원 (HWP 5.0+) |
| 한글 XML | .hwpx | ✅ 지원 |
| HWP 3.0 (레거시) | .hwp | ❌ 미지원 |

### 탐지 가능한 위협 유형

- **CVE-2017-8291 (GhostButt)**: EPS 취약점 공격
- **OLE 객체 임베딩**: 내부 실행 파일 포함
- **JavaScript 매크로**: 악성 스크립트 탐지
- **스테가노그래피**: 이미지 내부 숨겨진 페이로드
- **외부 링크/IP**: C2 서버 연결 시도
- **PE 파일 포함**: 실행 파일 삽입 탐지

---

## 시작하기

### 사전 요구사항

- Python 3.8+
- Node.js 18+
- pip
- npm 또는 yarn

### 설치 및 실행

#### 1. 백엔드 설정

```bash
# 백엔드 폴더로 이동
cd backend

# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는: venv\Scripts\activate.bat  # Windows

# 의존성 설치
pip install -r config/requirements.txt
pip install numpy scipy scikit-learn psutil

# 서버 실행
python core/simple_server.py
# 또는: python core/main.py
```

#### 2. 프론트엔드 설정

```bash
# 프론트엔드 폴더로 이동
cd frontend

# 의존성 설치
npm install

# 개발 서버 실행
npm run dev
```

#### 3. 접속

- 프론트엔드: http://localhost:5173
- 백엔드 API: http://localhost:8000

---

## 아키텍처

### 시스템 구성도

```
┌─────────────────────────────────────────────────────────────┐
│                      사용자 인터페이스                       │
│                    (React + TypeScript)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    HTTP/REST API
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      백엔드 서버                            │
│              (Python FastAPI/HTTPServer)                    │
├──────────────────────────┬──────────────────────────────────┤
│                          │                                  │
┌──────────────┐  ┌───────▼────────┐  ┌────────────────────┐
│  파일 업로드   │  │  HWP 파서      │  │   분석 엔진        │
│  및 검증     │──▶│  (OLE 파싱)    │──▶│  (6개 모듈)        │
└──────────────┘  └────────────────┘  └────────────────────┘
                                                │
              ┌─────────────────────────────────┼────────────┐
              │                                 │            │
       ┌──────▼──────┐  ┌──────────▼────────┐  ┌▼──────────┐ │
       │ EPS 탐지    │  │ OLE 객체 탐지     │  │ 스크립트  │ │
       │ (CVE-2017-  │  │ (임베딩 공격)     │  │ 분석      │ │
       │ 8291)       │  │                   │  │           │ │
       └─────────────┘  └───────────────────┘  └───────────┘ │
                                                              │
       ┌──────────┐  ┌──────────┐  ┌──────────┐              │
       │ IOC 추출 │  │ 스테가노 │  │ 구조적   │              │
       │ (URL/IP) │  │ 그래피   │  │ 이상 탐지│              │
       └──────────┘  └──────────┘  └──────────┘              │
                                                              │
                              ┌───────────────┐               │
                              │ 리스크 스코어링│◀──────────────┘
                              │ (점수 합산)   │
                              └───────┬───────┘
                                      │
                              ┌───────▼───────┐
                              │  결과 리포트   │
                              └───────────────┘
```

### 기술 스택

#### 프론트엔드
| 기술 | 버전 | 용도 |
|------|------|------|
| React | 18.x | UI 프레임워크 |
| TypeScript | 5.x | 타입 안전성 |
| Tailwind CSS | 3.x | 스타일링 |
| Axios | 1.x | HTTP 클라이언트 |
| Lucide React | - | 아이콘 |

#### 백엔드
| 기술 | 버전 | 용도 |
|------|------|------|
| Python | 3.8+ | 핵심 언어 |
| FastAPI | - | API 서버 |
| olefile | - | OLE 파일 파싱 |
| numpy/scikit-learn | - | ML 분류 |

---

## 주요 기능

### 1. 파일 업로드 및 분석

- 드래그앤드롭 파일 업로드
- 실시간 분석 진행 상태 표시
- 상세한 위협 분석 리포트

### 2. 위협 점수 시스템

| 위험 등급 | 점수 범위 | 설명 |
|-----------|-----------|------|
| CLEAN | 0-15 | 안전 |
| SUSPICIOUS | 16-35 | 주의 필요 |
| HIGH_RISK | 36-60 | 고위험 |
| MALICIOUS | 61-100 | 악성코드 확실 |

### 3. 탐지 결과 표시

- 리스크 배지 및 점수 미터
- 모듈별 상세 탐지 결과 (아코디언 UI)
- IOC (Indicator of Compromise) 테이블
- 추출된 원본 문자열 뷰어

---

## 위협 탐지 모듈

### Module 1: EPS/PostScript 탐지 (CVE-2017-8291)

GhostScript 취약점을 이용한 공격 탐지

| 지표 | 점수 | 위험도 |
|------|------|--------|
| EPS_STREAM | +10 | MEDIUM |
| CVE_2017_8291 | +30 | CRITICAL |
| HEX_SHELLCODE | +20 | HIGH |
| WIN32_APIS | +25 | CRITICAL |

### Module 2: OLE 객체 탐지

내부 임베디드 OLE 객체 탐지

| 지표 | 점수 | 위험도 |
|------|------|--------|
| EMBEDDED_OLE | +20 | HIGH |
| SHELL_COMMAND | +35 | CRITICAL |
| UNC_PATH | +25 | HIGH |
| AUTO_EXEC | +30 | CRITICAL |

### Module 3: 스크립트 분석

JavaScript 매크로 분석

| 지표 | 점수 | 위험도 |
|------|------|--------|
| COM_OBJECT | +15 | MEDIUM |
| FILE_ACCESS | +20 | HIGH |
| PROCESS_EXECUTION | +30 | CRITICAL |
| BASE64_PAYLOAD | +20 | HIGH |

### Module 4: IOC 추출

URL, IP, 파일 경로 등 추출

| 지표 | 점수 | 위험도 |
|------|------|--------|
| URL | +15 | MEDIUM |
| PATH_TEMP | +20 | HIGH |
| REGISTRY | +15 | MEDIUM |

### Module 5: 스테가노그래피 탐지

이미지 내 숨겨진 페이로드 탐지

| 지표 | 점수 | 위험도 |
|------|------|--------|
| PE_IN_IMAGE | +30 | CRITICAL |
| HIGH_ENTROPY | +15 | HIGH |
| JPEG_EOF_ANOMALY | +10 | MEDIUM |

### Module 6: 구조적 이상 탐지

파일 메타데이터 및 구조 분석

| 지표 | 점수 | 위험도 |
|------|------|--------|
| SUSPICIOUS_AUTHOR | +10 | MEDIUM |
| ENCRYPTED_DOCUMENT | +20 | HIGH |
| CONTENT_MISMATCH | +15 | MEDIUM |

---

## API 명세

### 기본 정보

| 항목 | 값 |
|------|-----|
| Base URL | `http://localhost:8000` |
| 프로토콜 | HTTP/HTTPS |
| 인코딩 | UTF-8 |
| 파일 업로드 | `multipart/form-data` |

### 주요 엔드포인트

#### 파일 분석
```
POST /api/analyze
```

**요청 예시:**
```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -F "file=@document.hwp"
```

**응답 예시:**
```json
{
  "filename": "document.hwp",
  "file_hash": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "file_size": 12345,
  "hwp_version": "5.0.1",
  "risk_level": "MALICIOUS",
  "threat_score": 75,
  "overall_risk_level": "MALICIOUS",
  "detected_threats": ["CVE-2017-8291", "EMBEDDED_OLE"],
  "modules": [
    {
      "id": "advanced_detector",
      "name": "고급 위협 탐지기",
      "status": "MALICIOUS",
      "score_contribution": 30
    }
  ],
  "iocs": {
    "urls": ["http://malicious.com"],
    "ips": ["192.168.1.1"],
    "file_paths": ["%TEMP%\\malware.exe"]
  }
}
```

---

## 보안 원칙

### 핵심 원칙

| 원칙 | 설명 | 위반 시 영향 |
|------|------|-------------|
| **정적 분석만** | 파일을 실행/열지 않고 구조만 검사 | 샌드박스 탈출, 감염 |
| **임시 저장** | 분석 중에만 디스크에 저장 | 영구 보관, 데이터 유출 |
| **즉시 삭제** | 분석 완료 후 즉시 파일 삭제 | 잔여 파일, 복구 가능 |
| **격리 환경** | 독립된 임시 디렉토리 사용 | 파일 시스템 오염 |

### 금지 행위

- ❌ OLE 객체 인스턴스화 (COM 객체 실행)
- ❌ EPS 렌더링 (GhostScript 취약점)
- ❌ 스크립트 실행 (매크로 실행)
- ❌ 이미지 렌더링 (파서 취약점)
- ❌ PE 파일 로드 (DLL 사이드로딩)

### 허용 행위

- ✅ 파일 시그니처 확인 (`data.startswith()`)
- ✅ 정규식 패턴 검색 (`re.search()`)
- ✅ 문자열 추출 (`extract_printable()`)
- ✅ 바이너리 데이터 분석

---

## 폴더 구조

```
HWPShield/
├── backend/              # Python 백엔드
│   ├── analyzer/        # 탐지 모듈 (6개)
│   │   ├── eps_detector.py
│   │   ├── ole_detector.py
│   │   ├── script_detector.py
│   │   ├── ioc_extractor.py
│   │   ├── steg_detector.py
│   │   └── structural_analyzer.py
│   ├── core/            # 메인 서버/스캐너
│   │   ├── simple_server.py
│   │   ├── enhanced_scanner.py
│   │   ├── improved_analyzer.py
│   │   └── main.py
│   ├── tests/           # 테스트 파일
│   ├── debug/           # 디버그 도구
│   ├── utils/           # 유틸리티
│   ├── docs/            # 백엔드 문서
│   └── config/          # 설정 파일
│       ├── requirements.txt
│       └── Dockerfile
├── frontend/            # React 프론트엔드
│   ├── src/
│   │   ├── components/  # UI 컴포넌트
│   │   ├── App.tsx
│   │   └── api.ts
│   └── package.json
├── docs/                # 프로젝트 문서
│   └── reports/         # 보고서
├── config/              # Docker 설정
├── scripts/             # 실행 스크립트
└── README.md           # 이 파일
```

---

## HWP 파일 형식 참고

### OLE2 구조

HWP 파일은 Microsoft OLE2 형식을 사용합니다.

**파일 시그니처:**
- OLE 매직: `D0 CF 11 E0 A1 B1 1A E1`
- HWP 시그니처: `HWP Document File`

**주요 스트림:**
| 스트림 | 설명 |
|--------|------|
| FileHeader | 메타정보 (압축 안됨) |
| DocInfo | 문서 설정 (zlib) |
| BodyText | 본문 텍스트 (zlib) |
| Scripts/DefaultJScript | JS 매크로 (zlib) |
| BinData/Bin#### | 바이너리 데이터 (zlib) |

---

## 기여 및 라이선스

이 프로젝트는 한글 문서 보안 향상을 위해 개발되었습니다.

**주의**: 이 도구는 정적 분석만 수행하며, 파일을 직접 실행하지 않습니다.

---

## 연락처

- GitHub: https://github.com/GUnT0x9/HWP_Shield
- Issues: https://github.com/GUnT0x9/HWP_Shield/issues

