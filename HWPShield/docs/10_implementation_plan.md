# 10. 구현 계획 및 일정 (Implementation Plan)

## 개발 단계

### Phase 1: 프로젝트 스캐폴딩 (1일)

#### 작업 목록

| ID | 작업 | 소요 시간 | 산출물 |
|-----|------|----------|--------|
| 1.1 | 디렉토리 구조 생성 | 30분 | 폴더 트리 |
| 1.2 | Git 저장소 초기화 | 15분 | .git/ |
| 1.3 | .gitignore 작성 | 15분 | .gitignore |
| 1.4 | 기본 README 작성 | 30분 | README.md |

#### 생성될 구조

```
HWPShield/
├── backend/
│   ├── analyzer/
│   │   └── __init__.py
│   ├── utils/
│   │   └── __init__.py
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── api.ts
│   │   ├── types.ts
│   │   └── App.tsx
│   ├── public/
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── Dockerfile
├── docs/
│   └── (이미 작성됨)
├── docker-compose.yml
└── .gitignore
```

---

### Phase 2: 백엔드 핵심 모듈 (3일)

#### Day 1: 파서 및 기반 모듈

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 2.1 | requirements.txt 작성 | 15분 | HIGH |
| 2.2 | hwp_parser.py 구현 | 3시간 | HIGH |
| 2.3 | hash_calc.py 구현 | 30분 | MEDIUM |
| 2.4 | file_handler.py 구현 | 1시간 | HIGH |
| 2.5 | validators.py 구현 | 30분 | MEDIUM |

#### Day 2: 탐지 모듈 (상)

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 2.6 | eps_detector.py 구현 | 3시간 | HIGH |
| 2.7 | ole_detector.py 구현 | 2시간 | HIGH |
| 2.8 | ioc_extractor.py 구현 | 2시간 | HIGH |

#### Day 3: 탐지 모듈 (하) 및 스코어링

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 2.9 | script_detector.py 구현 | 2시간 | HIGH |
| 2.10 | steg_detector.py 구현 | 1.5시간 | HIGH |
| 2.11 | structural_analyzer.py 구현 | 1시간 | MEDIUM |
| 2.12 | scorer.py 구현 | 1.5시간 | HIGH |
| 2.13 | 파이프라인 통합 | 1시간 | HIGH |

---

### Phase 3: FastAPI 서버 (1일)

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 3.1 | Pydantic 모델 정의 | 1시간 | HIGH |
| 3.2 | FastAPI 앱 구조 | 30분 | HIGH |
| 3.3 | /api/analyze 엔드포인트 | 2시간 | HIGH |
| 3.4 | /api/health 엔드포인트 | 15분 | LOW |
| 3.5 | /api/version 엔드포인트 | 15분 | LOW |
| 3.6 | 에러 핸들러 구현 | 30분 | MEDIUM |
| 3.7 | CORS 미들웨어 | 15분 | MEDIUM |
| 3.8 | Rate limiting | 30분 | HIGH |
| 3.9 | 로깅 설정 | 30분 | MEDIUM |

---

### Phase 4: 프론트엔드 설정 (1일)

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 4.1 | React + TypeScript 프로젝트 생성 | 15분 | HIGH |
| 4.2 | Tailwind CSS 설정 | 30분 | HIGH |
| 4.3 | 폴더 구조 설정 | 15분 | MEDIUM |
| 4.4 | types.ts 정의 | 30분 | HIGH |
| 4.5 | api.ts 구현 | 30분 | HIGH |
| 4.6 | 테마/언어 Context | 1시간 | MEDIUM |

---

### Phase 5: 프론트엔드 컴포넌트 (2일)

#### Day 1: 핵심 컴포넌트

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 5.1 | FileUpload 컴포넌트 | 2시간 | HIGH |
| 5.2 | FileDropZone 컴포넌트 | 1시간 | HIGH |
| 5.3 | ProgressBar 컴포넌트 | 1시간 | MEDIUM |
| 5.4 | RiskBadge 컴포넌트 | 30분 | HIGH |
| 5.5 | ScoreMeter 컴포넌트 | 1시간 | HIGH |

#### Day 2: 결과 컴포넌트

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 5.6 | ModuleAccordion 컴포넌트 | 2시간 | HIGH |
| 5.7 | IocTable 컴포넌트 | 1시간 | MEDIUM |
| 5.8 | RawStringsViewer 컴포넌트 | 1시간 | LOW |
| 5.9 | Home 페이지 조립 | 1시간 | HIGH |
| 5.10 | Header/Footer | 30분 | LOW |

---

### Phase 6: 통합 및 배포 (1일)

| ID | 작업 | 소요 시간 | 우선순순위 |
|-----|------|----------|----------|
| 6.1 | Backend Dockerfile 작성 | 30분 | HIGH |
| 6.2 | Frontend Dockerfile 작성 | 30분 | HIGH |
| 6.3 | docker-compose.yml 작성 | 30분 | HIGH |
| 6.4 | 통합 테스트 | 1시간 | HIGH |
| 6.5 | 버그 수정 | 2시간 | HIGH |

---

### Phase 7: 테스트 및 문서화 (1일)

| ID | 작업 | 소요 시간 | 우선순위 |
|-----|------|----------|----------|
| 7.1 | 단위 테스트 작성 | 2시간 | MEDIUM |
| 7.2 | 테스트 샘플 수집 | 1시간 | MEDIUM |
| 7.3 | 통합 테스트 | 1시간 | HIGH |
| 7.4 | 성능 테스트 | 1시간 | LOW |
| 7.5 | 최종 문서화 | 1시간 | MEDIUM |

---

## 총 일정

```
Day 1: Phase 1 (스캐폴딩) + Phase 2 시작
Day 2: Phase 2 (백엔드 핵심)
Day 3: Phase 2 완료 + Phase 3 (FastAPI)
Day 4: Phase 4 (프론트엔드 설정) + Phase 5 시작
Day 5: Phase 5 완료 (프론트엔드 컴포넌트)
Day 6: Phase 6 (통합 및 배포)
Day 7: Phase 7 (테스트 및 문서화)
```

**총 소요 시간: 7일**

---

## 우선순위 매트릭스

### MoSCoW 분석

| 우선순위 | 기능 | 이유 |
|---------|------|------|
| **Must** | EPS 탐지 | GhostButt 탐지 핵심 |
| **Must** | OLE 탐지 | 최신 공격 대응 |
| **Must** | IOC 추출 | 공통 IOC 수집 |
| **Must** | 파일 업로드 | 기본 기능 |
| **Must** | 리스크 스코어링 | 결과 표시 |
| **Must** | 리포트 UI | 사용자 피드백 |
| **Should** | 스크립트 탐지 | VBS 공격 대응 |
| **Should** | 스테가노그래피 | M2RAT 탐지 |
| **Should** | 다크모드 | 사용자 경험 |
| **Could** | 구조적 분석 | 보조 탐지 |
| **Could** | 다국어 | 영어 지원 |
| **Won't** | 동적 분석 | 샌드박스 (범위 외) |
| **Won't** | 클라우드 스케일링 | 단일 인스턴스 |

---

## 리스크 관리

### 식별된 리스크

| 리스크 | 영향 | 가능성 | 대응 방안 |
|--------|------|--------|----------|
| OLE 파싱 복잡성 | 중간 | 높음 | olefile 라이브러리 사용 |
| zlib 해제 실패 | 중간 | 중간 | 예외 처리, fallback |
| 큰 파일 처리 | 낮음 | 중간 | 스트리밍 처리 |
| 오탐 발생 | 중간 | 중간 | 화이트리스트, 임계값 조정 |
| 누락 탐지 | 높음 | 낮음 | 다중 모듈, 테스트 샘플 |
| 보안 취약점 | 높음 | 낮음 | 코드 리뷰, 정적 분석만 |

### 완화 전략

1. **파싱 실패**
   - 여러 zlib 옵션 시도 (wbits)
   - 손상된 파일은 별도 플래그

2. **성능 문제**
   - 비동기 처리
   - 타임아웃 설정
   - 큐잉 고려

3. **보안**
   - 정적 분석만 수행
   - 파일 즉시 삭제
   - 임시 디렉토리 격리

---

## 개발 환경

### 로컬 개발

```bash
# 백엔드
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn main:app --reload

# 프론트엔드
cd frontend
npm install
npm run dev
```

### Docker 개발

```bash
# 전체 스택
docker-compose up --build

# 개별 서비스
docker-compose up backend
docker-compose up frontend
```

---

## 품질 기준

### 코드 품질

- TypeScript strict mode
- Python type hints
- ESLint/Prettier (frontend)
- flake8/black (backend)

### 테스트 커버리지

| 컴포넌트 | 목표 커버리지 |
|---------|-------------|
| hwp_parser | 80%+ |
| 탐지 모듈 | 70%+ |
| scorer | 90%+ |
| API 엔드포인트 | 60%+ |

### 성능 목표

| 지표 | 목표값 |
|------|--------|
| 분석 시간 (10MB) | < 5초 |
| 분석 시간 (50MB) | < 30초 |
| 메모리 사용 | < 512MB |
| 동시 요청 | 10/hour/IP |

---

## 완료 기준 (Definition of Done)

### 기능 완료 체크리스트

- [ ] 코드 작성 완료
- [ ] 단위 테스트 통과
- [ ] 통합 테스트 통과
- [ ] 코드 리뷰 완료
- [ ] 문서화 완료
- [ ] Docker 빌드 성공
- [ ] 수동 테스트 완료

### 릴리즈 기준

- [ ] 모든 단계 테스트 통과
- [ ] 성능 벤치마크 달성
- [ ] 보안 검토 완료
- [ ] 문서 완성
- [ ] README 업데이트
- [ ] Git 태그 생성 (v1.0.0)
