# HWPShield 백엔드 실행 가이드

## 🚀 실행 방법

### 1. 기본 설정 (최초 1회만)

```bash
# 1. 백엔드 폴더로 이동
cd d:\school_project\HWPShield\backend

# 2. 가상환경 활성화
call venv\Scripts\activate.bat

# 3. 의존성 설치
pip install -r requirements.txt

# 4. 필요한 추가 패키지 설치
pip install numpy scipy scikit-learn psutil
```

### 2. 서버 실행

#### 방법 1: Simple Server (기본)
```bash
# 가상환경 활성화된 상태에서
python simple_server.py
```

#### 방법 2: FastAPI Server (권장)
```bash
# 가상환경 활성화된 상태에서
python main.py
```

#### 방법 3: Uvicorn으로 FastAPI 실행
```bash
# 가상환경 활성화된 상태에서
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. 실행 확인

서버가 정상적으로 실행되면 다음과 같은 메시지가 표시됩니다:

```
╔════════════════════════════════════════════════════════════╗
║     Enhanced HWP/HWPX Scanner Server v2.0                ║
╠════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:8000/                  ║
║  API endpoint:      http://localhost:8000/api/analyze       ║
║  Health check:     http://localhost:8000/api/health         ║
╚════════════════════════════════════════════════════════════╝
```

### 4. API 엔드포인트

#### 주요 엔드포인트
- **POST /api/analyze** - HWP 파일 분석
- **GET /api/health** - 서버 상태 확인
- **GET /api/status** - 엔진 상태 정보

#### 분석 요청 예시
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test.hwp"
```

### 5. 포트 변경

#### Simple Server
```bash
python simple_server.py 9090
```

#### FastAPI
```bash
uvicorn main:app --host 0.0.0.0 --port 9090 --reload
```

### 6. 문제 해결

#### 의존성 오류 시
```bash
# numpy, scipy 설치
pip install numpy scipy scikit-learn

# psutil 설치 (메모리 모니터링)
pip install psutil

# python-magic 설치 (Windows)
# 1. https://github.com/gsauthof/python-magic/releases 다운로드
# 2. magic-64bit.dll을 Python/Lib/site-packages/ 에 복사
# 3. pip install python-magic-bin
```

#### 포트 충돌 시
```bash
# 사용 중인 포트 확인
netstat -ano | findstr :8000

# 다른 포트로 실행
python simple_server.py 8080
```

#### 모듈 임포트 오류 시
```bash
# PYTHONPATH 설정
set PYTHONPATH=%PYTHONPATH%;d:\school_project\HWPShield\backend

# 또는 직접 실행
python -c "import sys; sys.path.append('.'); from simple_server import run_server; run_server()"
```

### 7. 프로덕션 환경 실행

#### Docker 사용 (권장)
```bash
# Docker 이미지 빌드
docker build -t hwpshield-backend .

# 컨테이너 실행
docker run -p 8000:8000 hwpshield-backend
```

#### Windows 서비스 등록
```bash
# NSSM (Non-Sucking Service Manager) 설치 후
nssm install HWPShieldBackend python "d:\school_project\HWPShield\backend\main.py"
nssm start HWPShieldBackend
```

### 8. 모니터링

#### 로그 확인
```bash
# 로그 파일 위치
type logs\hwpshield_*.log

# 실시간 로그 보기
tail -f logs\hwpshield_$(date +%Y-%m-%d).log
```

#### 성능 모니터링
```bash
# API 상태 확인
curl http://localhost:8000/api/status

# 엔진 상태 확인
curl http://localhost:8000/api/engine/status
```

---

## 🎯 추천 실행 방법

### 개발 환경
```bash
cd d:\school_project\HWPShield\backend
call venv\Scripts\activate.bat
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 프로덕션 환경
```bash
cd d:\school_project\HWPShield\backend
call venv\Scripts\activate.bat
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 테스트 환경
```bash
cd d:\school_project\HWPShield\backend
call venv\Scripts\activate.bat
python simple_server.py
```

---

## 📝 실행 체크리스트

- [ ] 가상환경 활성화
- [ ] 의존성 설치 완료
- [ ] 포트 8000 사용 가능 확인
- [ ] 방화벽 설정 확인
- [ ] 로그 디렉토리 생성
- [ ] 테스트 파일 준비

---

## 🔗 연결 정보

- **서버 주소**: http://localhost:8000
- **API 문서**: http://localhost:8000/docs (FastAPI만 해당)
- **상태 확인**: http://localhost:8000/api/health
- **분석 API**: http://localhost:8000/api/analyze
