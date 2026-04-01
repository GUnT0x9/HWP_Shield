# 06. 프론트엔드 UI 요구사항 (Frontend UI Specification)

## 기술 스택

| 기술 | 버전 | 용도 |
|------|------|------|
| React | 18.x | UI 프레임워크 |
| TypeScript | 5.x | 타입 안전성 |
| Tailwind CSS | 3.x | 유틸리티 우선 스타일링 |
| Axios | 1.x | HTTP 클라이언트 |
| Lucide React | - | 아이콘 라이브러리 |

---

## 전체 레이아웃 구조

```
┌─────────────────────────────────────────────────────────────┐
│  Header                                                    │
│  ├── Logo (HWPShield)                                       │
│  ├── 언어 토글 (한국어/영어)                                  │
│  └── 테마 토글 (라이트/다크)                                  │
├─────────────────────────────────────────────────────────────┤
│                                                            │
│  Main Content                                              │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  파일 업로드 섹션                                     │  │
│  │  ├── 드래그앤드롭 영역                                │  │
│  │  ├── 파일 정보 표시                                   │  │
│  │  └── 업로드 버튼                                      │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  분석 진행 상태 (숨겨짐 → 업로드 후 표시)              │  │
│  │  ├── 프로그레스바                                     │  │
│  │  └── 현재 단계 라벨                                   │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  결과 대시보드 (숨겨짐 → 분석 완료 후 표시)             │  │
│  │  ├── 리스크 배지 + 점수 미터                          │  │
│  │  ├── 모듈별 아코디언                                  │  │
│  │  ├── IOC 테이블                                      │  │
│  │  └── 원본 문자열 뷰어                                │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                            │
├─────────────────────────────────────────────────────────────┤
│  Footer                                                    │
│  └── © 2024 HWPShield - 문서 보안 분석 도구                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 컴포넌트 상세

### 1. 파일 업로드 섹션 (UploadSection)

#### 기능
- 파일 선택 (클릭)
- 드래그앤드롭 지원
- 파일 유효성 검사 (magic bytes)
- 크기 표시 (50MB 제한)

#### UI 상태

```
┌───────────────────────────────────────────────────────────────┐
│                                                                │
│                     ┌──────────────┐                          │
│                     │              │                          │
│                     │   📄         │                          │
│                     │   아이콘      │                          │
│                     │              │                          │
│                     └──────────────┘                          │
│                                                                │
│           HWP 파일을 드래그하거나 클릭하여 선택하세요              │
│                  (.hwp, .hwpx 파일 지원)                       │
│                                                                │
│              [파일 선택]                                        │
│                                                                │
└───────────────────────────────────────────────────────────────┘
```

#### 파일 선택 후

```
┌───────────────────────────────────────────────────────────────┐
│  선택된 파일:                                                  │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ 📄 정부문서_견적서.hwp                                 │   │
│  │ 크기: 2.5 MB                                          │   │
│  │ Magic: D0 CF 11 E0 (✓ 유효한 HWP 파일)                │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│              [분석 시작]  [다른 파일 선택]                       │
└───────────────────────────────────────────────────────────────┘
```

#### Props 인터페이스

```typescript
interface UploadSectionProps {
  onFileSelect: (file: File) => void;
  onUpload: (file: File) => void;
  selectedFile: File | null;
  isUploading: boolean;
}

interface FileInfoProps {
  file: File;
  isValid: boolean;
  magicBytes?: string;
}
```

---

### 2. 분석 진행 상태 (AnalysisProgress)

#### 분석 단계

| 순서 | ID | 한국어 라벨 | 영어 라벨 |
|------|-----|------------|----------|
| 1 | `parsing` | 구조 파싱 중... | Parsing structure... |
| 2 | `eps` | EPS 스트림 검사... | Analyzing EPS streams... |
| 3 | `ole` | OLE 개체 검사... | Scanning OLE objects... |
| 4 | `script` | 스크립트 분석... | Analyzing scripts... |
| 5 | `ioc` | IOC 추출... | Extracting IOCs... |
| 6 | `report` | 리포트 생성 중... | Generating report... |

#### UI 상태

```
분석 진행 중...

████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  35%

[✓] 구조 파싱 중...
[✓] EPS 스트림 검사...
[▶] OLE 개체 검사...
[ ] 스크립트 분석...
[ ] IOC 추출...
[ ] 리포트 생성 중...
```

#### Props 인터페이스

```typescript
interface AnalysisProgressProps {
  currentStep: number;  // 0-5
  totalSteps: number;   // 6
  stepLabels: {
    ko: string[];
    en: string[];
  };
  isComplete: boolean;
}
```

---

### 3. 리스크 배지 (RiskBadge)

#### 등급별 디자인

| 등급 | 배경색 | 텍스트색 | 아이콘 |
|------|--------|----------|--------|
| CLEAN | bg-green-500 | text-white | ✓ |
| SUSPICIOUS | bg-yellow-500 | text-black | ⚠ |
| HIGH_RISK | bg-orange-500 | text-white | ⚠⚠ |
| MALICIOUS | bg-red-600 | text-white | 🚫 |

#### UI

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    🟢 CLEAN                                  │
│              안전한 문서로 판단됩니다                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    🟡 SUSPICIOUS                             │
│              의심스러운 요소가 발견되었습니다                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    🟠 HIGH RISK                                │
│              높은 위험이 탐지되었습니다                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                                                              │
│                    🔴 MALICIOUS                                │
│              악성 코드가 탐지되었습니다                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Props 인터페이스

```typescript
interface RiskBadgeProps {
  level: 'CLEAN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'MALICIOUS';
  score: number;
  recommendation: string;
}
```

---

### 4. 점수 미터 (ScoreMeter)

#### 시각화

```
위험 점수: 55 / 100

0    10   20   30   40   50   60   70   80   90   100
|----|----|----|----|----|----|----|----|----|----|
     🟡    🟠        🔴

███████████████████████████████████████████████████░░░░░░░░░░░
                    ↑
                  현재 점수

HIGH RISK - 높은 위험
```

#### 색상 매핑

```javascript
const getScoreColor = (score: number): string => {
  if (score <= 14) return 'bg-green-500';      // CLEAN
  if (score <= 34) return 'bg-yellow-500';   // SUSPICIOUS
  if (score <= 59) return 'bg-orange-500';   // HIGH_RISK
  return 'bg-red-600';                       // MALICIOUS
};
```

#### Props 인터페이스

```typescript
interface ScoreMeterProps {
  score: number;        // 0-100
  maxScore: number;     // 100
  riskLevel: string;
}
```

---

### 5. 모듈별 아코디언 (ModuleAccordion)

#### 접힌 상태

```
┌─────────────────────────────────────────────────────────────┐
│ ▶  🟢 EPS/PostScript 탐지                점수: +0          │
├─────────────────────────────────────────────────────────────┤
│ ▶  🟢 OLE 객체 탐지                      점수: +0          │
├─────────────────────────────────────────────────────────────┤
│ ▶  🟡 스크립트 분석                      점수: +15         │
├─────────────────────────────────────────────────────────────┤
│ ▷  🟠 IOC 추출                           점수: +25         │
│     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━       │
│     • URL: http://example.com/payload  (high)              │
│     • IP: 192.168.1.100  (medium)                          │
│     • 경로: %TEMP%\\dropper.exe  (high)                    │
└─────────────────────────────────────────────────────────────┘
```

#### 펼친 상태 상세

```
┌─────────────────────────────────────────────────────────────┐
│ ▼  🟠 IOC 추출                           점수: +25           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  발견된 지표:                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🔴 URL_SUSPICIOUS                                     │ │
│  │ 값: http://evil-site.com/payload.exe                    │ │
│  │ 심각도: HIGH (+20점)                                    │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🟡 IP_PUBLIC                                          │ │
│  │ 값: 185.220.101.42                                     │ │
│  │ 심각도: MEDIUM (+15점)                                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  총 지표 수: 2개                                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Props 인터페이스

```typescript
interface ModuleAccordionProps {
  modules: ModuleResult[];
}

interface ModuleResult {
  id: string;
  name: string;
  nameEn: string;
  status: 'CLEAN' | 'SUSPICIOUS' | 'DETECTED';
  score: number;
  indicators: Indicator[];
}

interface Indicator {
  type: string;
  value: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  score: number;
}
```

---

### 6. IOC 테이블 (IocTable)

#### UI

```
┌─────────────────────────────────────────────────────────────┐
│ IOC (Indicators of Compromise)                    [전체 복사] │
├─────────────────────────────────────────────────────────────┤
│  유형    │  값                           │  심각도  │  복사   │
├──────────┼───────────────────────────────┼──────────┼─────────┤
│  URL     │ http://evil.com/payload       │  HIGH    │  [📋]   │
├──────────┼───────────────────────────────┼──────────┼─────────┤
│  IP      │ 185.220.101.42               │  MEDIUM  │  [📋]   │
├──────────┼───────────────────────────────┼──────────┼─────────┤
│  경로    │ %TEMP%\\malicious.exe         │  HIGH    │  [📋]   │
├──────────┼───────────────────────────────┼──────────┼─────────┤
│  레지스트리│ HKCU\\Software\\Malware      │  HIGH    │  [📋]   │
└──────────┴───────────────────────────────┴──────────┴─────────┘
```

#### 기능
- 개별 항목 복사
- 전체 목록 복사 (JSON/CSV)
- 정렬/필터링
- 중복 제거 표시

#### Props 인터페이스

```typescript
interface IocTableProps {
  iocs: IOC[];
  onCopy: (value: string) => void;
  onCopyAll: () => void;
}

interface IOC {
  type: 'url' | 'ip' | 'path' | 'registry' | 'hash';
  value: string;
  severity: string;
}
```

---

### 7. 원본 문자열 뷰어 (RawStringsViewer)

#### UI

```
┌─────────────────────────────────────────────────────────────┐
│ 원본 추출 문자열                                    [펼치기 ▼] │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  (텍스트 영역 - 스크롤 가능)                                   │
│  ───────────────────────────────────────────────             │
│  H\x00W\x00P\x00 \x00D\x00o\x00c\x00u\x00m...              │
│  %!PS-Adobe-3.0 EPSF-3.0                                     │
│  http://example.com/payload                                  │
│  %TEMP%\\dropper.exe                                         │
│  CreateFileA                                                 │
│  ...                                                         │
│  ───────────────────────────────────────────────             │
│                                                              │
│  표시: 전체 1,247개 중 처음 100개                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Props 인터페이스

```typescript
interface RawStringsViewerProps {
  strings: string[];
  maxDisplay?: number;  // 기본값: 100
}
```

---

## 테마 시스템

### 다크모드 색상 팔레트

```css
/* Tailwind CSS 다크모드 클래스 */
.dark {
  --bg-primary: #0f172a;      /* slate-900 */
  --bg-secondary: #1e293b;    /* slate-800 */
  --bg-tertiary: #334155;     /* slate-700 */
  --text-primary: #f8fafc;    /* slate-50 */
  --text-secondary: #cbd5e1;  /* slate-300 */
  --border-color: #475569;    /* slate-600 */
}
```

### 컴포넌트별 다크모드 스타일

```
Light Mode:
┌─────────────────────────────────────────────────────────────┐
│  배경: white                                                │
│  카드: white (shadow)                                       │
│  텍스트: gray-900                                           │
│  테두리: gray-200                                           │
└─────────────────────────────────────────────────────────────┘

Dark Mode:
┌─────────────────────────────────────────────────────────────┐
│  배경: slate-900 (#0f172a)                                  │
│  카드: slate-800 (#1e293b)                                  │
│  텍스트: slate-50 (#f8fafc)                                 │
│  테두리: slate-700 (#334155)                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 다국어 지원 (i18n)

### 언어 파일 구조

```typescript
// ko.json
{
  "header": {
    "title": "HWPShield",
    "subtitle": "한글 문서 악성코드 분석 도구"
  },
  "upload": {
    "dropzone": "HWP 파일을 드래그하거나 클릭하여 선택하세요",
    "filetypes": "(.hwp, .hwpx 파일 지원)",
    "select": "파일 선택",
    "analyze": "분석 시작"
  },
  "progress": {
    "title": "분석 진행 중...",
    "steps": [
      "구조 파싱 중...",
      "EPS 스트림 검사...",
      "OLE 개체 검사...",
      "스크립트 분석...",
      "IOC 추출...",
      "리포트 생성 중..."
    ]
  },
  "result": {
    "risk": {
      "CLEAN": "안전",
      "SUSPICIOUS": "주의",
      "HIGH_RISK": "위험",
      "MALICIOUS": "악성"
    },
    "score": "위험 점수",
    "modules": "모듈별 결과",
    "iocs": "IOC 목록",
    "rawStrings": "원본 문자열"
  }
}

// en.json
{
  "header": {
    "title": "HWPShield",
    "subtitle": "HWP Document Malware Analysis Tool"
  },
  "upload": {
    "dropzone": "Drag and drop an HWP file or click to select",
    "filetypes": "(.hwp, .hwpx files supported)",
    "select": "Select File",
    "analyze": "Start Analysis"
  },
  "progress": {
    "title": "Analysis in progress...",
    "steps": [
      "Parsing structure...",
      "Analyzing EPS streams...",
      "Scanning OLE objects...",
      "Analyzing scripts...",
      "Extracting IOCs...",
      "Generating report..."
    ]
  },
  "result": {
    "risk": {
      "CLEAN": "Clean",
      "SUSPICIOUS": "Suspicious",
      "HIGH_RISK": "High Risk",
      "MALICIOUS": "Malicious"
    },
    "score": "Risk Score",
    "modules": "Module Results",
    "iocs": "IOC List",
    "rawStrings": "Raw Strings"
  }
}
```

---

## 반응형 디자인

### 브레이크포인트

| 디바이스 | 너비 | 레이아웃 |
|----------|------|----------|
| 모바일 | < 640px | 단일 컬럼, 축소된 패딩 |
| 태블릿 | 640px - 1024px | 단일 컬럼, 확장된 패딩 |
| 데스크탑 | > 1024px | 중앙 정렬, 최대 너비 1200px |

### 모바일 최적화

```
모바일 (< 640px):
┌─────────────────────────┐
│  Header                 │
├─────────────────────────┤
│                         │
│  [드래그앤드롭 영역]     │
│                         │
├─────────────────────────┤
│  분석 진행...            │
│  ▓▓▓░░ 50%             │
├─────────────────────────┤
│  결과                    │
│  🟠 HIGH RISK           │
│  점수: 55               │
├─────────────────────────┤
│  [모듈 1]              │
│  [모듈 2] ▼            │
│   - 지표 1             │
│   - 지표 2             │
├─────────────────────────┤
│  Footer                │
└─────────────────────────┘
```

---

## 상태 관리

### React Context 구조

```typescript
interface AppState {
  // 테마
  theme: 'light' | 'dark';
  toggleTheme: () => void;
  
  // 언어
  locale: 'ko' | 'en';
  setLocale: (locale: 'ko' | 'en') => void;
  t: (key: string) => string;  // 번역 함수
  
  // 파일
  selectedFile: File | null;
  setSelectedFile: (file: File | null) => void;
  
  // 분석
  analysisStatus: 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';
  currentStep: number;
  
  // 결과
  report: AnalysisReport | null;
  
  // 액션
  startAnalysis: (file: File) => Promise<void>;
  resetAnalysis: () => void;
}
```

---

## 접근성 (Accessibility)

### ARIA 레이블

```tsx
// RiskBadge 컴포넌트
<div 
  role="alert"
  aria-live="polite"
  className={`risk-badge risk-${level.toLowerCase()}`}
>
  <span className="sr-only">Risk Level:</span>
  {level}
</div>

// ScoreMeter 컴포넌트
<div 
  role="progressbar"
  aria-valuenow={score}
  aria-valuemin={0}
  aria-valuemax={100}
  aria-label={`Risk score: ${score} out of 100`}
>
  {/* ... */}
</div>

// ModuleAccordion 컴포넌트
<button
  aria-expanded={isOpen}
  aria-controls={`module-content-${moduleId}`}
  id={`module-header-${moduleId}`}
>
  {moduleName}
</button>
<div
  role="region"
  aria-labelledby={`module-header-${moduleId}`}
  id={`module-content-${moduleId}`}
  hidden={!isOpen}
>
  {/* ... */}
</div>
```

### 키보드 네비게이션

- `Tab`: 컴포넌트 간 이동
- `Enter`/`Space`: 버튼/아코디언 활성화
- `Escape`: 모달/드롭다운 닫기
- 화살표 키: 테이블/목록 탐색

### 색상 대비

- 모든 텍스트는 WCAG 4.5:1 대비율 준수
- 위험 등급 색상은 색각 이상자도 구분 가능
  (모양/텍스트 추가 사용: ✓, ⚠, 🚫)
