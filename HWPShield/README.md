# HWPShield

한글 문서(.hwp) 악성코드 분석 웹 애플리케이션

## 빠른 시작

### Docker로 실행

```bash
# 프로젝트 클론
git clone <repository>
cd HWPShield

# Docker Compose로 실행
docker-compose up --build

# 접속
# Frontend: http://localhost:3000
# API: http://localhost:8000/api
```

### 로컬 개발 환경

**백엔드:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

**프론트엔드:**
```bash
cd frontend
npm install
npm run dev
```

## 기능

- **EPS/PostScript 탐지**: CVE-2017-8291 (GhostButt) 취약점 탐지
- **OLE 객체 탐지**: 임베디드 OLE 객체 및 실행 파일 탐지
- **스크립트 분석**: JavaScript 매크로 및 VBS 쉘코드 탐지
- **IOC 추출**: URL, IP, 레지스트리 경로 등 자동 추출
- **스테가노그래피 탐지**: 이미지 내부 숨겨진 PE 파일 탐지
- **구조 분석**: 메타데이터 이상 및 파일 구조 분석

## 시스템 아키텍처

```
Frontend (React + TypeScript + Tailwind)
              ↓ POST /api/analyze
Backend (FastAPI + Python)
              ↓
HWP Parser (olefile + zlib)
              ↓
Detection Modules (6개 모듈)
              ↓
Risk Scoring → JSON Response
```

## API 엔드포인트

| 메서드 | 엔드포인트 | 설명 |
|--------|-----------|------|
| POST | `/api/analyze` | 파일 분석 |
| GET | `/api/health` | 헬스 체크 |
| GET | `/api/version` | 버전 정보 |

## 보안

- 정적 분석만 수행 (파일 절대 실행 안 함)
- 임시 파일 즉시 삭제
- IP당 시간당 10회 요청 제한
- 50MB 파일 크기 제한
- Docker 보안 설정 (read-only, no-new-privileges)

## 라이선스

MIT License
