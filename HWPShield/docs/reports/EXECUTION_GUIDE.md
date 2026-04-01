# HWPShield 백엔드 & 프론트엔드 실행 가이드
## Quick Start Guide

---

## 🚀 1. 백엔드 실행 (3가지 방법)

### 방법 1: 간단한 검색엔진 (권장 - 가장 안정적)

```bash
# 1. 백엔드 폴더로 이동
cd d:\school_project\HWPShield\backend

# 2. 가상환경 활성화
call venv\Scripts\activate.bat

# 3. 간단한 검색엔진 실행
python simple_scanner.py

# 4. 다른 포트로 실행 (선택)
python simple_scanner.py 8080
```

**접속 주소**: http://localhost:8000

**특징**:
- ✅ 의존성 최소화
- ✅ 가장 안정적
- ✅ 웹 인터페이스 내장
- ✅ 파일 업로드/분석 가능

---

### 방법 2: 고급 검색엔진 (full features)

```bash
# 1. 백엔드 폴더로 이동
cd d:\school_project\HWPShield\backend

# 2. 가상환경 활성화
call venv\Scripts\activate.bat

# 3. 의존성 설치 (최초 1회)
pip install fastapi uvicorn python-multipart python-magic numpy

# 4. 고급 검색엔진 실행
python simple_server.py

# 또는 FastAPI 모드
python main.py

# 또는 Uvicorn으로 실행
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**접속 주소**: http://localhost:8000

**특징**:
- ✅ 고급 위협 탐지
- ✅ ML 보조 분석
- ✅ API 엔드포인트
- ⚠️ 의존성 다소 많음

---

### 방법 3: 최소 실행 (테스트용)

```bash
# 1. 백엔드 폴더로 이동
cd d:\school_project\HWPShield\backend

# 2. 가상환경 활성화
call venv\Scripts\activate.bat

# 3. 테스트 스크립트 실행
python quick_test.py

# 또는
python simple_pe_test.py
```

**특징**:
- ✅ CLI 기반 테스트
- ✅ 즉시 결과 확인
- ✅ 개발/디버깅용

---

## 🎨 2. 프론트엔드 실행

### React 프론트엔드 실행

```bash
# 1. 프론트엔드 폴더로 이동
cd d:\school_project\HWPShield\frontend

# 2. Node.js 의존성 설치 (최초 1회)
npm install

# 3. 개발 서버 실행
npm start

# 4. 또는 빌드 후 실행
npm run build
serve -s build -p 3000
```

**접속 주소**: http://localhost:3000

**백엔드 연결 설정**:
- 프론트엔드는 기본적으로 `http://localhost:8000`에 연결
- `src/config/api.ts`에서 API 주소 변경 가능

---

## 🔧 3. 통합 실행 (백엔드 + 프론트엔드)

### 동시 실행 스크립트

```bash
# 1. 루트 폴더에서

# 백엔드 실행 (터미널 1)
cd backend
call venv\Scripts\activate.bat
python simple_scanner.py

# 프론트엔드 실행 (터미널 2)
cd frontend
npm start
```

### Docker로 한번에 실행

```bash
# Docker 이미지 빌드
docker build -t hwpshield .

# 컨테이너 실행 (백엔드 + 프론트엔드)
docker run -p 8000:8000 -p 3000:3000 hwpshield
```

---

## 🌐 4. 실행 확인 및 테스트

### 백엔드 상태 확인

```bash
# 1. Health Check
curl http://localhost:8000/api/health

# 2. 상태 페이지 접속
# 브라우저에서 http://localhost:8000 접속

# 3. 파일 분석 테스트 (CLI)
curl -X POST -F "file=@test.hwp" http://localhost:8000/scan
```

### 프론트엔드 상태 확인

```bash
# 1. 개발 서버 확인
curl http://localhost:3000

# 2. 브라우저에서 확인
# http://localhost:3000 접속 후 HWP 파일 업로드 테스트
```

---

## ⚠️ 5. 문제 해결

### 오류 1: "No module named 'xxx'"

```bash
# 의존성 재설치
pip install -r requirements.txt

# 또는 특정 패키지만 설치
pip install fastapi uvicorn python-magic numpy scipy
```

### 오류 2: "Port already in use"

```bash
# 포트 확인
netstat -ano | findstr :8000

# 다른 포트 사용
python simple_scanner.py 8080

# 또는 프로세스 종료
taskkill /PID <PID> /F
```

### 오류 3: SyntaxError / ImportError

```bash
# PYTHONPATH 설정
set PYTHONPATH=%PYTHONPATH%;d:\school_project\HWPShield\backend

# 또는 직접 실행
python -c "import sys; sys.path.append('.'); from simple_scanner import run_server; run_server()"
```

### 오류 4: 프론트엔드 빌드 실패

```bash
# node_modules 삭제 후 재설치
rm -rf node_modules
rm package-lock.json
npm install
npm start
```

---

## 📊 6. 실행 모드별 비교

| 실행 모드 | 명령어 | 속도 | 안정성 | 기능 | 사용 시나리오 |
|-----------|--------|------|--------|------|---------------|
| **간단 모드** | `simple_scanner.py` | ⚡ 빠름 | ⭐⭐⭐⭐⭐ | 기본 | 일반 사용자, 테스트 |
| **고급 모드** | `simple_server.py` | 🔄 보통 | ⭐⭐⭐⭐ | 풍부 | 전문 분석, API 사용 |
| **FastAPI** | `main.py` | ⚡ 빠름 | ⭐⭐⭐⭐ | 풍부 | 프로덕션, 고성능 |
| **테스트** | `quick_test.py` | ⚡⚡ 매우 빠름 | ⭐⭐⭐ | 최소 | 개발, 디버깅 |

---

## 🎯 7. 권장 실행 시나리오

### 시나리오 1: 일반 사용자
```bash
# 간단 모드 사용
python simple_scanner.py
# → 브라우저에서 http://localhost:8000 접속
```

### 시나리오 2: 개발자
```bash
# 백엔드 (터미널 1)
python simple_server.py

# 프론트엔드 (터미널 2)
npm start
```

### 시나리오 3: 프로덕션
```bash
# 고급 모드 with 다중 워커
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

# 프론트엔드 정적 파일 서빙
serve -s build -l 3000
```

### 시나리오 4: API 전용
```bash
# FastAPI 모드
python main.py
# → API 문서: http://localhost:8000/docs
```

---

## 📝 8. 환경 설정

### 환경 변수 설정

```bash
# Windows
set HWPSHIELD_PORT=8000
set HWPSHIELD_DEBUG=true
set PYTHONPATH=d:\school_project\HWPShield\backend

# Linux/Mac
export HWPSHIELD_PORT=8000
export HWPSHIELD_DEBUG=true
```

### 설정 파일 (config.json)

```json
{
  "backend": {
    "port": 8000,
    "host": "0.0.0.0",
    "debug": false,
    "max_file_size": 52428800,
    "enable_ml": true
  },
  "frontend": {
    "port": 3000,
    "api_url": "http://localhost:8000"
  }
}
```

---

## 🎉 9. 성공 확인 체크리스트

- [ ] 백엔드 서버 시작 (http://localhost:8000)
- [ ] Health Check 성공 (`{"status": "ok"}`)
- [ ] 파일 업로드 테스트 성공
- [ ] 분석 결과 정상 수신
- [ ] 프론트엔드 서버 시작 (http://localhost:3000)
- [ ] 웹 인터페이스 정상 표시
- [ ] 파일 업로드/분석 플로우 완료

---

## 🔗 10. 유용한 링크

- **백엔드 API 문서**: http://localhost:8000/docs (FastAPI 모드)
- **백엔드 상태**: http://localhost:8000/api/health
- **프론트엔드**: http://localhost:3000
- **테스트 파일**: `d:\school_project\HWPShield\backend\*.hwp`

---

**빠른 시작 요약**:
```bash
cd d:\school_project\HWPShield\backend
call venv\Scripts\activate.bat
python simple_scanner.py
# → http://localhost:8000 접속
```
