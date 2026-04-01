# 07. 백엔드 API 명세 (Backend API Specification)

## API 개요

HWPShield 백엔드는 RESTful API를 제공합니다. 모든 응답은 JSON 형식입니다.

### 기본 정보

| 항목 | 값 |
|------|-----|
| Base URL | `http://localhost:8000` (개발) |
| 프로토콜 | HTTP/HTTPS |
| 인코딩 | UTF-8 |
| Content-Type | `application/json` |
| 파일 업로드 | `multipart/form-data` |

---

## 엔드포인트 목록

### 1. 파일 분석 (메인 엔드포인트)

```
POST /api/analyze
```

파일 업로드 및 악성코드 분석을 수행합니다.

#### 요청

**Content-Type**: `multipart/form-data`

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `file` | File | O | 분석할 .hwp/.hwpx 파일 |

#### 요청 예시

```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/document.hwp"
```

#### 응답 (성공 - 200 OK)

```json
{
  "filename": "정부문서_견적서.hwp",
  "file_hash": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "file_size": 2567890,
  "hwp_version": "5.0.1",
  "analysis_timestamp": "2024-03-31T08:30:00Z",
  "overall_risk": "HIGH_RISK",
  "risk_score": 55,
  "modules": [
    {
      "id": "eps",
      "name": "EPS/PostScript 탐지",
      "name_en": "EPS/PostScript Detection",
      "status": "DETECTED",
      "score_contribution": 30,
      "indicators": [
        {
          "type": "CVE-2017-8291",
          "value": ".eqproc",
          "severity": "critical"
        },
        {
          "type": "WIN32_APIS",
          "value": "WinExec, CreateFileA",
          "severity": "critical"
        }
      ],
      "details": "EPS 스트림에서 CVE-2017-8291 취약점 트리거 패턴(.eqproc)과 Win32 API 문자열이 발견되었습니다."
    },
    {
      "id": "ole",
      "name": "OLE 객체 탐지",
      "name_en": "OLE Object Detection",
      "status": "CLEAN",
      "score_contribution": 0,
      "indicators": [],
      "details": "OLE 객체가 발견되지 않았습니다."
    },
    {
      "id": "script",
      "name": "스크립트 분석",
      "name_en": "Script Analysis",
      "status": "SUSPICIOUS",
      "score_contribution": 15,
      "indicators": [
        {
          "type": "COM_OBJECT",
          "value": "WScript.Shell",
          "severity": "high"
        }
      ],
      "details": "스크립트에 COM 객체(WScript.Shell) 생성이 발견되었습니다."
    },
    {
      "id": "ioc",
      "name": "IOC 추출",
      "name_en": "IOC Extraction",
      "status": "DETECTED",
      "score_contribution": 20,
      "indicators": [
        {
          "type": "URL",
          "value": "http://evil.com/payload",
          "severity": "high"
        },
        {
          "type": "PATH_TEMP",
          "value": "%TEMP%\\\dropper.exe",
          "severity": "high"
        }
      ],
      "details": "2개의 의심 IOC가 추출되었습니다."
    },
    {
      "id": "steg",
      "name": "스테가노그래피 탐지",
      "name_en": "Steganography Detection",
      "status": "CLEAN",
      "score_contribution": 0,
      "indicators": [],
      "details": "이미지 파일에서 의심스러운 패턴이 발견되지 않았습니다."
    },
    {
      "id": "structural",
      "name": "구조적 이상 탐지",
      "name_en": "Structural Analysis",
      "status": "SUSPICIOUS",
      "score_contribution": 10,
      "indicators": [
        {
          "type": "SUSPICIOUS_AUTHOR",
          "value": "admin",
          "severity": "medium"
        }
      ],
      "details": "작성자 메타데이터가 의심스러운 패턴입니다."
    }
  ],
  "iocs": [
    {
      "type": "url",
      "value": "http://evil.com/payload",
      "severity": "high"
    },
    {
      "type": "ip",
      "value": "185.220.101.42",
      "severity": "medium"
    },
    {
      "type": "path",
      "value": "%TEMP%\\\dropper.exe",
      "severity": "high"
    },
    {
      "type": "registry",
      "value": "HKCU\\\Software\\\Malware",
      "severity": "high"
    }
  ],
  "raw_strings_sample": [
    "%!PS-Adobe-3.0 EPSF-3.0",
    "http://evil.com/payload",
    "WinExec",
    "CreateFileA",
    ".eqproc",
    "%TEMP%"
  ]
}
```

#### 응답 필드 설명

| 필드 | 타입 | 설명 |
|------|------|------|
| `filename` | string | 업로드된 파일명 |
| `file_hash.md5` | string | MD5 해시 |
| `file_hash.sha256` | string | SHA256 해시 |
| `file_size` | number | 파일 크기 (바이트) |
| `hwp_version` | string | HWP 버전 |
| `analysis_timestamp` | string | 분석 완료 시간 (ISO 8601) |
| `overall_risk` | enum | 전체 위험 등급 (CLEAN/SUSPICIOUS/HIGH_RISK/MALICIOUS) |
| `risk_score` | number | 위험 점수 (0-100) |
| `modules` | array | 모듈별 분석 결과 |
| `modules[].id` | string | 모듈 ID |
| `modules[].name` | string | 모듈 이름 (한국어) |
| `modules[].name_en` | string | 모듈 이름 (영어) |
| `modules[].status` | enum | 상태 (CLEAN/SUSPICIOUS/DETECTED) |
| `modules[].score_contribution` | number | 점수 기여도 |
| `modules[].indicators` | array | 발견된 지표 목록 |
| `modules[].indicators[].type` | string | 지표 유형 |
| `modules[].indicators[].value` | string | 지표 값 |
| `modules[].indicators[].severity` | enum | 심각도 (info/low/medium/high/critical) |
| `modules[].details` | string | 상세 설명 |
| `iocs` | array | 추출된 IOC 목록 |
| `raw_strings_sample` | array | 원본 문자열 샘플 (최대 100개) |

---

### 2. 헬스 체크

```
GET /api/health
```

서버 상태를 확인합니다.

#### 요청 예시

```bash
curl "http://localhost:8000/api/health"
```

#### 응답 (성공 - 200 OK)

```json
{
  "status": "healthy",
  "timestamp": "2024-03-31T08:30:00Z",
  "version": "1.0.0",
  "uptime": 3600
}
```

---

### 3. 버전 정보

```
GET /api/version
```

API 버전 및 서버 정보를 반환합니다.

#### 요청 예시

```bash
curl "http://localhost:8000/api/version"
```

#### 응답 (성공 - 200 OK)

```json
{
  "name": "HWPShield API",
  "version": "1.0.0",
  "python_version": "3.11.0",
  "fastapi_version": "0.100.0"
}
```

---

## 에러 응답

### 에러 응답 형식

모든 에러는 다음 형식을 따릅니다:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "additional info"
    }
  }
}
```

### 에러 코드 목록

| HTTP 상태 | 에러 코드 | 설명 | 조치 |
|-----------|-----------|------|------|
| 400 | `INVALID_FILE_TYPE` | 지원되지 않는 파일 형식 | .hwp/.hwpx 파일만 업로드 |
| 400 | `INVALID_MAGIC_BYTES` | 유효하지 않은 HWP 파일 | 파일이 손상되었을 수 있음 |
| 413 | `FILE_TOO_LARGE` | 파일 크기 초과 (50MB) | 더 작은 파일 업로드 |
| 413 | `REQUEST_TOO_LARGE` | 요청 크기 초과 | - |
| 429 | `RATE_LIMIT_EXCEEDED` | 요청 제한 초과 | 1시간 후 재시도 |
| 500 | `INTERNAL_ERROR` | 내부 서버 오류 | 관리자에게 문의 |
| 500 | `ANALYSIS_FAILED` | 분석 실패 | 다른 파일로 재시도 |
| 503 | `SERVICE_UNAVAILABLE` | 서비스 불가 | 잠시 후 재시도 |

### 에러 응답 예시

#### 400 - 잘못된 파일 형식

```json
{
  "error": {
    "code": "INVALID_FILE_TYPE",
    "message": "지원되지 않는 파일 형식입니다. .hwp 또는 .hwpx 파일만 업로드 가능합니다.",
    "details": {
      "received_extension": ".pdf",
      "supported_extensions": [".hwp", ".hwpx"]
    }
  }
}
```

#### 413 - 파일 크기 초과

```json
{
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "파일 크기는 50MB를 초과할 수 없습니다.",
    "details": {
      "max_size": 52428800,
      "max_size_human": "50MB",
      "received_size": 62914560,
      "received_size_human": "60MB"
    }
  }
}
```

#### 429 - 요청 제한 초과

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "요청 제한을 초과했습니다. 1시간 후에 다시 시도하세요.",
    "details": {
      "limit": 10,
      "window": "1 hour",
      "retry_after": 3600
    }
  }
}
```

---

## Pydantic 모델 (스키마)

### 요청 모델

```python
from pydantic import BaseModel, Field
from typing import Optional

class FileUploadRequest(BaseModel):
    """파일 업로드 요청 (multipart/form-data)"""
    file: UploadFile = Field(..., description="분석할 HWP 파일")
    
    class Config:
        max_file_size = 50 * 1024 * 1024  # 50MB

class AnalysisOptions(BaseModel):
    """분석 옵션 (향후 확장용)"""
    include_raw_strings: bool = Field(default=True, description="원본 문자열 포함")
    max_string_count: int = Field(default=100, ge=10, le=1000, description="최대 문자열 수")
    string_min_length: int = Field(default=4, ge=1, le=20, description="최소 문자열 길이")
```

### 응답 모델

```python
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Literal
from datetime import datetime

class FileHash(BaseModel):
    md5: str = Field(..., pattern=r'^[a-f0-9]{32}$')
    sha256: str = Field(..., pattern=r'^[a-f0-9]{64}$')

class Indicator(BaseModel):
    type: str = Field(..., description="지표 유형")
    value: str = Field(..., description="지표 값")
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = Field(...)

class ModuleResult(BaseModel):
    id: str = Field(..., description="모듈 ID")
    name: str = Field(..., description="모듈 이름 (한국어)")
    name_en: str = Field(..., description="모듈 이름 (영어)")
    status: Literal['CLEAN', 'SUSPICIOUS', 'DETECTED'] = Field(...)
    score_contribution: int = Field(..., ge=0, description="점수 기여도")
    indicators: List[Indicator] = Field(default_factory=list)
    details: str = Field(..., description="상세 설명")

class IOC(BaseModel):
    type: Literal['url', 'ip', 'path', 'registry', 'hash'] = Field(...)
    value: str = Field(..., description="IOC 값")
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = Field(...)

class AnalysisResponse(BaseModel):
    filename: str = Field(..., description="원본 파일명")
    file_hash: FileHash = Field(..., description="파일 해시")
    file_size: int = Field(..., ge=0, description="파일 크기 (바이트)")
    hwp_version: Optional[str] = Field(None, description="HWP 버전")
    analysis_timestamp: str = Field(..., description="분석 완료 시간 (ISO 8601)")
    overall_risk: Literal['CLEAN', 'SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'] = Field(...)
    risk_score: int = Field(..., ge=0, le=100, description="위험 점수")
    modules: List[ModuleResult] = Field(..., description="모듈별 결과")
    iocs: List[IOC] = Field(default_factory=list, description="IOC 목록")
    raw_strings_sample: List[str] = Field(default_factory=list, max_length=100)

class ErrorResponse(BaseModel):
    error: Dict[str, any] = Field(..., description="에러 정보")

class HealthResponse(BaseModel):
    status: Literal['healthy', 'degraded', 'unhealthy'] = Field(...)
    timestamp: str = Field(..., description="현재 시간 (ISO 8601)")
    version: str = Field(..., description="API 버전")
    uptime: int = Field(..., description="실행 시간 (초)")

class VersionResponse(BaseModel):
    name: str = Field(..., default="HWPShield API")
    version: str = Field(...)
    python_version: str = Field(...)
    fastapi_version: str = Field(...)
```

---

## FastAPI 구현 예시

### main.py

```python
from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib
import tempfile
import os

from analyzer.pipeline import AnalysisPipeline
from models.schemas import AnalysisResponse, HealthResponse, VersionResponse, ErrorResponse

# 속도 제한 설정
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="HWPShield API",
    description="한글 문서(.hwp) 악성코드 분석 API",
    version="1.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS 미들웨어
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 프론트엔드 주소
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# 파일 크기 제한 (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """전역 예외 핸들러"""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "서버 내부 오류가 발생했습니다.",
                "details": {"exception": str(exc)}
            }
        }
    )

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """서버 상태 확인"""
    import time
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "uptime": int(time.time() - start_time)
    }

@app.get("/api/version", response_model=VersionResponse)
async def get_version():
    """API 버전 정보"""
    import sys, fastapi
    return {
        "name": "HWPShield API",
        "version": "1.0.0",
        "python_version": sys.version,
        "fastapi_version": fastapi.__version__
    }

@app.post("/api/analyze", response_model=AnalysisResponse)
@limiter.limit("10/hour")
async def analyze_file(
    request: Request,
    file: UploadFile = File(..., description="분석할 HWP 파일")
):
    """HWP 파일 분석"""
    
    # 1. 파일 존재 확인
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "NO_FILE",
                "message": "파일이 제공되지 않았습니다."
            }
        )
    
    # 2. 파일 확장자 검증
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.hwp', '.hwpx']:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_FILE_TYPE",
                "message": "지원되지 않는 파일 형식입니다.",
                "details": {
                    "received_extension": ext,
                    "supported_extensions": [".hwp", ".hwpx"]
                }
            }
        )
    
    # 3. 파일 크기 검증 (헤더 확인)
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "FILE_TOO_LARGE",
                "message": "파일 크기는 50MB를 초과할 수 없습니다.",
                "details": {
                    "max_size": MAX_FILE_SIZE,
                    "received_size": len(content)
                }
            }
        )
    
    # 4. Magic bytes 검증
    if not content.startswith(b'\\xd0\\xcf\\x11\\xe0'):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_MAGIC_BYTES",
                "message": "유효하지 않은 HWP 파일입니다. OLE magic bytes가 일치하지 않습니다.",
                "details": {
                    "expected": "D0 CF 11 E0",
                    "received": content[:4].hex().upper()
                }
            }
        )
    
    # 5. 해시 계산
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    # 6. 임시 파일 저장 및 분석
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.hwp') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        
        # 분석 파이프라인 실행
        pipeline = AnalysisPipeline()
        result = await pipeline.analyze(tmp_path)
        
    finally:
        # 임시 파일 삭제
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    
    # 7. 응답 구성
    return AnalysisResponse(
        filename=file.filename,
        file_hash=FileHash(md5=md5_hash, sha256=sha256_hash),
        file_size=len(content),
        hwp_version=result.get('hwp_version'),
        analysis_timestamp=datetime.utcnow().isoformat() + "Z",
        overall_risk=result['risk_level'],
        risk_score=result['score'],
        modules=result['modules'],
        iocs=result['iocs'],
        raw_strings_sample=result.get('raw_strings', [])[:100]
    )

# 서버 시작 시간 기록
import time
start_time = time.time()
```

---

## 미들웨어

### 속도 제한 (Rate Limiting)

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10/hour"]
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
```

### CORS 설정

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://hwpshield.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=3600,
)
```

### 로깅

```python
import logging
from fastapi import Request

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """요청 로깅"""
    logger.info(f"{request.method} {request.url.path} - {request.client.host}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response
```

---

## 비동기 처리

### 분석 파이프라인

```python
import asyncio
from typing import Dict, List

class AnalysisPipeline:
    """비동기 분석 파이프라인"""
    
    def __init__(self):
        self.parser = HWPParser()
        self.scorer = RiskScorer()
        self.modules = [
            EPSDetector(),
            OLEDetector(),
            ScriptDetector(),
            IOCExtractor(),
            StegDetector(),
            StructuralAnalyzer(),
        ]
    
    async def analyze(self, file_path: str) -> Dict:
        """파일 분석 실행"""
        
        # 1. HWP 파싱 (동기 작업을 스레드 풀에서 실행)
        hwp_data = await asyncio.get_event_loop().run_in_executor(
            None, self.parser.parse, file_path
        )
        
        # 2. 모든 모듈 병렬 실행
        tasks = [
            self._run_module(module, hwp_data)
            for module in self.modules
        ]
        module_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 3. 결과 필터링 (예외 처리)
        valid_results = [
            r for r in module_results 
            if not isinstance(r, Exception)
        ]
        
        # 4. 리스크 스코어링
        scoring = self.scorer.calculate_score(valid_results)
        
        return {
            'hwp_version': hwp_data.get('version'),
            'score': scoring['total_score'],
            'risk_level': scoring['risk_level'],
            'modules': valid_results,
            'iocs': self._extract_all_iocs(valid_results),
            'raw_strings': hwp_data.get('strings', []),
        }
    
    async def _run_module(self, module, hwp_data: Dict) -> Dict:
        """개별 모듈 실행"""
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, module.analyze, hwp_data
            )
            return result
        except Exception as e:
            logger.error(f"Module {module.__class__.__name__} failed: {e}")
            return {
                'module_id': module.get_id(),
                'status': 'ERROR',
                'error': str(e),
                'score_contribution': 0,
                'indicators': []
            }
```
