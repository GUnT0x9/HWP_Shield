# 08. 보안 제약사항 (Security Constraints)

## 보안 원칙

HWPShield는 **정적 분석(Static Analysis)**만을 수행합니다. 이는 근본적인 보안 원칙이며 절대 위반되어서는 안 됩니다.

### 핵심 원칙

| 원칙 | 설명 | 위반 시 영향 |
|------|------|-------------|
| **정적 분석만** | 파일을 실행/열지 않고 구조만 검사 | 샌드박스 탈출, 감염 |
| **임시 저장** | 분석 중에만 디스크에 저장 | 영구 보관, 데이터 유출 |
| **즉시 삭제** | 분석 완료 후 즉시 파일 삭제 | 잔여 파일, 복구 가능 |
| **격리 환경** | 독립된 임시 디렉토리 사용 | 파일 시스템 오염 |
| **속도 제한** | IP당 시간당 요청 제한 | DoS 공격, 남용 |

---

## 정적 분석 규칙

### 금지 행위 (절대 실행 불가)

| 행위 | 이유 | 대안 |
|------|------|------|
| OLE 객체 열기 | COM 객체 실행 가능성 | 매직 바이트만 검사 |
| EPS 렌더링 | GhostScript 취약점 트리거 | 텍스트 문자열 검색 |
| 스크립트 실행 | 매크로 실행, 코드 주입 | AST 파싱 없이 패턴 매칭 |
| 이미지 뷰어로 열기 | 이미지 파서 취약점 | 바이너리 패턴 검사 |
| PE 파일 로드 | DLL 사이드로딩 | 헤더 시그니처만 검사 |

### 허용 행위

```python
# ✅ 허용: 파일 시그니처 확인
if data.startswith(b'%!PS-Adobe'):
    indicator = "EPS_FOUND"

# ✅ 허용: 정규식 패턴 검색
if re.search(rb'\.eqproc', data):
    indicator = "CVE_2017_8291"

# ✅ 허용: 문자열 추출
strings = extract_printable(data)

# ❌ 금지: OLE 객체 인스턴스화
ole = win32com.client.Dispatch("Excel.Application")  # 절대 금지!

# ❌ 금지: 이미지 렌더링
img = Image.open(io.BytesIO(data))  # 파서 취약점 우려
img.show()  # 절대 금지!

# ❌ 금지: 스크립트 실행
exec(script_content)  # 절대 금지!
```

---

## 파일 처리 보안

### 업로드 처리

```python
import os
import tempfile
from pathlib import Path
import hashlib

class SecureFileHandler:
    """보안 파일 핸들러"""
    
    # 허용된 확장자
    ALLOWED_EXTENSIONS = {'.hwp', '.hwpx'}
    
    # OLE 매직 바이트
    OLE_MAGIC = b'\\xd0\\xcf\\x11\\xe0'
    
    # 최대 파일 크기 (50MB)
    MAX_SIZE = 50 * 1024 * 1024
    
    # 임시 디렉토리 (격리된 디렉토리 사용)
    TEMP_DIR = tempfile.mkdtemp(prefix="hwpshield_")
    
    @classmethod
    def validate_upload(cls, filename: str, content: bytes) -> bool:
        """업로드 검증"""
        
        # 1. 확장자 검사
        ext = Path(filename).suffix.lower()
        if ext not in cls.ALLOWED_EXTENSIONS:
            raise SecurityError(f"허용되지 않는 확장자: {ext}")
        
        # 2. 파일명 정제 (sanitization)
        safe_name = cls._sanitize_filename(filename)
        
        # 3. 크기 검사
        if len(content) > cls.MAX_SIZE:
            raise SecurityError(f"파일 크기 초과: {len(content)} bytes")
        
        # 4. 매직 바이트 검사
        if not content.startswith(cls.OLE_MAGIC):
            raise SecurityError("유효하지 않은 HWP 파일")
        
        return True
    
    @classmethod
    def _sanitize_filename(cls, filename: str) -> str:
        """파일명 정제"""
        # 경로 구분자 제거
        safe = os.path.basename(filename)
        
        # 위험한 문자 제거
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', safe)
        
        # 길이 제한
        if len(safe) > 255:
            name, ext = os.path.splitext(safe)
            safe = name[:250] + ext
        
        return safe
    
    @classmethod
    def save_temporarily(cls, content: bytes, original_name: str) -> str:
        """임시 파일 저장 (격리된 디렉토리)"""
        
        # 안전한 파일명 생성
        safe_name = cls._sanitize_filename(original_name)
        
        # UUID 기반 고유 경로 생성
        import uuid
        unique_name = f"{uuid.uuid4()}_{safe_name}"
        
        # 임시 디렉토리에 저장
        temp_path = os.path.join(cls.TEMP_DIR, unique_name)
        
        # 파일 저장
        with open(temp_path, 'wb') as f:
            f.write(content)
        
        # 권한 제한 (소유자만 읽기/쓰기)
        os.chmod(temp_path, 0o600)
        
        return temp_path
    
    @classmethod
    def cleanup(cls, file_path: str):
        """파일 안전하게 삭제"""
        
        if not file_path:
            return
        
        # 경로 검증 (임시 디렉토리 내 파일만 삭제)
        if not file_path.startswith(cls.TEMP_DIR):
            raise SecurityError("임시 디렉토리 외부 파일은 삭제할 수 없습니다")
        
        if os.path.exists(file_path):
            # 안전 삭제 (덮어쓰기 후 삭제)
            cls._secure_delete(file_path)
    
    @classmethod
    def _secure_delete(cls, file_path: str):
        """안전 삭제 (덮어쓰기)"""
        
        file_size = os.path.getsize(file_path)
        
        # 3회 덮어쓰기 (간단한 버전)
        with open(file_path, 'ba+', buffering=0) as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # 파일 삭제
        os.unlink(file_path)
    
    @classmethod
    def cleanup_all(cls):
        """전체 임시 디렉토리 정리"""
        
        if os.path.exists(cls.TEMP_DIR):
            for file in os.listdir(cls.TEMP_DIR):
                file_path = os.path.join(cls.TEMP_DIR, file)
                try:
                    cls._secure_delete(file_path)
                except Exception as e:
                    logging.error(f"파일 삭제 실패: {file_path}, {e}")
            
            # 디렉토리 삭제
            os.rmdir(cls.TEMP_DIR)
```

---

## DoS 방지

### 속도 제한 설정

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# 속도 제한 설정
limiter = Limiter(
    key_func=get_remote_address,  # IP 기반 제한
    default_limits=["10/hour"]     # IP당 시간당 10회
)

@app.post("/api/analyze")
@limiter.limit("10/hour")
async def analyze_file(request: Request, file: UploadFile):
    """파일 분석 엔드포인트"""
    # ... 분석 로직

# Rate limit 초과 시 응답
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "요청 제한을 초과했습니다. 1시간 후에 다시 시도하세요.",
                "retry_after": 3600
            }
        }
    )
```

### 타임아웃 설정

```python
import asyncio

@app.post("/api/analyze")
@limiter.limit("10/hour")
async def analyze_file(request: Request, file: UploadFile):
    try:
        # 분석 작업 타임아웃 (30초)
        result = await asyncio.wait_for(
            perform_analysis(file),
            timeout=30.0
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408,
            detail={
                "code": "ANALYSIS_TIMEOUT",
                "message": "분석 시간이 초과되었습니다."
            }
        )
```

---

## 입력 검증

### 파일명 검증

```python
import re

def validate_filename(filename: str) -> str:
    """
    파일명 검증 및 정제
    
    위험한 패턴:
    - 경로 traversal: ../, ..\\
    - 널 바이트: file\x00.txt
    - 쉘 확장: $(cmd), `cmd`
    """
    
    # 널 바이트 제거
    if '\\x00' in filename:
        raise ValueError("파일명에 널 바이트가 포함되어 있습니다")
    
    # 경로 traversal 방지
    if '..' in filename or '~' in filename:
        raise ValueError("경로 traversal 문자가 포함되어 있습니다")
    
    # 쉘 특수문자 제거
    dangerous = ['$', '`', '|', ';', '&', '<', '>']
    for char in dangerous:
        if char in filename:
            raise ValueError(f"파일명에 위험한 문자가 포함되어 있습니다: {char}")
    
    # 기본명만 추출
    safe = os.path.basename(filename)
    
    # 확장자 확인
    if not re.match(r'^[a-zA-Z0-9._-]+$', safe):
        raise ValueError("파일명에 허용되지 않는 문자가 포함되어 있습니다")
    
    return safe
```

### 파일 크기 검증

```python
async def validate_file_size(file: UploadFile, max_size: int = 50*1024*1024):
    """파일 크기 검증 (스트리밍 방식)"""
    
    total_size = 0
    chunk_size = 8192
    
    while chunk := await file.read(chunk_size):
        total_size += len(chunk)
        
        if total_size > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"파일 크기가 {max_size} bytes를 초과했습니다"
            )
    
    # 파일 포인터 리셋
    await file.seek(0)
    
    return total_size
```

---

## 환경 격리

### Docker 보안 설정

```dockerfile
# backend/Dockerfile
FROM python:3.11-slim

# 보안: root가 아닌 사용자로 실행
RUN useradd -m -u 1000 hwpshield

# 애플리케이션 디렉토리
WORKDIR /app

# 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사 (소유자 변경)
COPY --chown=hwpshield:hwpshield . .

# 비특권 사용자로 전환
USER hwpshield

# 임시 디렉토리 (noexec, nosuid, nodev 마운트)
ENV TEMP=/tmp/hwpshield
RUN mkdir -p $TEMP

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose 보안 설정

```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    
    # 보안: read_only 루트 파일시스템
    read_only: true
    
    # 보안: tmpfs 마운트 (noexec, nosuid, nodev)
    tmpfs:
      - /tmp:size=100M,noexec,nosuid,nodev,mode=700
    
    # 보안: capability 제거
    cap_drop:
      - ALL
    
    # 보안: 보안 옵션
    security_opt:
      - no-new-privileges:true
    
    # 보안: 리소스 제한
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
    
    # 환경 변수
    environment:
      - TEMP=/tmp
      - MAX_FILE_SIZE=52428800
    
    # 포트
    ports:
      - "8000:8000"
```

---

## 로깅 및 모니터링

### 보안 이벤트 로깅

```python
import logging
import hashlib

security_logger = logging.getLogger('security')

class SecurityLogger:
    """보안 이벤트 로거"""
    
    @staticmethod
    def log_upload(client_ip: str, filename: str, file_hash: str, result: str):
        """파일 업로드 로깅"""
        security_logger.info(
            f"UPLOAD: ip={client_ip}, "
            f"file={filename}, "
            f"hash={file_hash}, "
            f"result={result}"
        )
    
    @staticmethod
    def log_threat_detected(client_ip: str, file_hash: str, threat_type: str, score: int):
        """위협 탐지 로깅"""
        security_logger.warning(
            f"THREAT: ip={client_ip}, "
            f"hash={file_hash}, "
            f"type={threat_type}, "
            f"score={score}"
        )
    
    @staticmethod
    def log_rate_limit_exceeded(client_ip: str, attempts: int):
        """속도 제한 초과 로깅"""
        security_logger.warning(
            f"RATE_LIMIT: ip={client_ip}, "
            f"attempts={attempts}"
        )
    
    @staticmethod
    def log_security_error(client_ip: str, error_type: str, details: str):
        """보안 오류 로깅"""
        security_logger.error(
            f"SECURITY_ERROR: ip={client_ip}, "
            f"type={error_type}, "
            f"details={details}"
        )
```

---

## 취약점 대응 체크리스트

### OWASP Top 10 대응

| 취약점 | 대응 방안 | 구현 위치 |
|--------|----------|----------|
| A01: Broken Access Control | Rate limiting | middleware/rate_limit.py |
| A02: Cryptographic Failures | SHA256 해시 | utils/hash_calc.py |
| A03: Injection | 파일명 sanitization | utils/validators.py |
| A04: Insecure Design | 정적 분석만 수행 | analyzer/*.py |
| A05: Security Misconfiguration | Docker security | Dockerfile, docker-compose.yml |
| A06: Vulnerable Components | 의존성 검사 | requirements.txt |
| A07: Auth Failures | (해당 없음 - 공개 API) | - |
| A08: Integrity Failures | 파일 해시 검증 | utils/hash_calc.py |
| A09: Logging Failures | 보안 이벤트 로깅 | utils/security_logger.py |
| A10: SSRF | URL 필터링 | ioc_extractor.py |

---

## 사고 대응 계획

### 파일 누출 의심 시

1. **즉시 조치**
   ```bash
   # 서비스 중지
   docker-compose down
   
   # 로그 수집
   docker logs hwpshield-backend > incident_$(date +%Y%m%d_%H%M%S).log
   
   # 파일 시스템 스캔
   find /tmp -name "hwpshield_*" -type f 2>/dev/null
   ```

2. **포렌식 수집**
   - 업로드된 파일 해시 목록
   - 클라이언트 IP 주소
   - 타임스탬프
   - 분석 결과

3. **통보**
   - 보안팀 (security@example.com)
   - CISO (ciso@example.com)
   - 법무팀 (legal@example.com) - GDPR/CCPA 해당 시

### 악성 파일 다운로드 의심 시

```python
# 자동 격리 기능
QUARANTINE_DIR = "/var/quarantine"

async def quarantine_file(file_path: str, reason: str):
    """파일 자동 격리"""
    import shutil
    import datetime
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantine_name = f"{timestamp}_{os.path.basename(file_path)}"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
    
    # 격리 디렉토리로 이동
    shutil.move(file_path, quarantine_path)
    
    # 권한 제한
    os.chmod(quarantine_path, 0o400)  # 읽기 전용
    
    # 알림
    security_logger.critical(
        f"QUARANTINE: file={quarantine_path}, reason={reason}"
    )
```
