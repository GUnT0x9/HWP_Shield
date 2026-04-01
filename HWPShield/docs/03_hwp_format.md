# 03. HWP 파일 형식 분석 (HWP File Format)

## OLE2 (Compound Document) 형식

HWP 파일은 Microsoft의 **OLE2(Object Linking and Embedding 2)** 형식을 사용합니다. 이는 이전 MS Word(.doc)와 동일한 바이너리 구조입니다.

### 파일 시그니처

| 바이트 위치 | 값 (Hex) | 설명 |
|------------|----------|------|
| 0-7 | `D0 CF 11 E0 A1 B1 1A E1` | OLE2 매직 바이트 |
| 512+ | 가변 | 파일 헤더 및 스트림 데이터 |

```python
# 매직 바이트 검증 코드
OLE_MAGIC = b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1'

def verify_hwp(file_path: str) -> bool:
    with open(file_path, 'rb') as f:
        header = f.read(8)
        return header == OLE_MAGIC
```

---

## 내부 스트림 구조

HWP 파일은 여러 개의 **스트림(Streams)**으로 구성됩니다. 각 스트림은 이름을 가지고 있으며, 압축되어 저장됩니다.

### 주요 스트림 목록

| 스트림 이름 | 설명 | 필수 | 압축 |
|------------|------|------|------|
| `FileHeader` | HWP 파일 메타정보 | O | X |
| `DocInfo` | 문서 설정 정보 | O | O |
| `BodyText` | 본문 텍스트 | O | O |
| `Scripts/DefaultJScript` | 자바스크립트 매크로 | △ | O |
| `Scripts/JScriptVersion` | 스크립트 버전 | △ | O |
| `BinData/Bin####` | 바이너리 데이터 (EPS, 이미지 등) | △ | O |
| `PrvText` | 미리보기 텍스트 | X | O |
| `PrvImage` | 미리보기 이미지 | X | O |
| `DocOptions` | 문서 옵션 | X | O |
| `Signature` | 전자서명 | X | O |

### 스트림 구조 다이어그램

```
HWP File (OLE2 Container)
├── FileHeader (압축 안됨)
│   ├── 시그니처: "HWP Document File"
│   ├── 버전 정보
│   ├── 암호화 플래그
│   └── 한글 버전
│
├── DocInfo (zlib 압축)
│   ├── 문서 속성
│   ├── 글꼴 정보
│   ├── 스타일 정보
│   └── 문서 설정
│
├── BodyText (zlib 압축)
│   ├── 문단 1
│   ├── 문단 2
│   └── ... (텍스트 본문)
│
├── Scripts/ (zlib 압축)
│   ├── DefaultJScript
│   └── JScriptVersion
│
├── BinData/ (zlib 압축)
│   ├── Bin0000 (EPS 이미지)
│   ├── Bin0001 (JPEG)
│   ├── Bin0002 (OLE 객체)
│   └── ...
│
└── PrvText (zlib 압축)
    └── 미리보기 텍스트
```

---

## FileHeader 상세

### 구조 (36 바이트 고정)

| 오프셋 | 크기 | 타입 | 필드명 | 설명 |
|--------|------|------|--------|------|
| 0 | 16 | char[] | Signature | "HWP Document File" + null |
| 16 | 4 | uint32 | Version | 0x00050001 = 5.0.1 |
| 20 | 4 | uint32 | Flags | 비트 플래그 |
| 24 | 4 | uint32 | Reserved | 0 |
| 28 | 4 | uint32 | License | 라이선스 정보 |
| 32 | 4 | uint32 | Reserved2 | 0 |

### 버전 필드

```
0x00050001 → Major=5, Minor=0, Build=1
0x00040000 → HWP 4.0 (레거시)
0x00030000 → HWP 3.0 (플랫 바이너리, OLE 아님)
```

### Flags 비트 마스크

| 비트 | 값 | 의미 |
|------|-----|------|
| 0 | 0x00000001 | 암호화된 문서 |
| 1 | 0x00000002 | 배포용 문서 |
| 2 | 0x00000004 | 스크립트 포함 |
| 3 | 0x00000008 | DRM 문서 |
| 4 | 0x00000010 | XML 버전 스토리지 |
| 5 | 0x00000020 | VCS 관리 문서 |

---

## zlib 압축 해제

HWP의 모든 스트림(FileHeader 제외)은 **zlib**으로 압축됩니다.

### 압축 방식

- **Compression**: zlib (default)
- **wbits**: -15 (raw deflate, 헤더 없음)
- **Window Size**: 32KB

### 파이썬 구현

```python
import zlib

def decompress_stream(compressed_data: bytes) -> bytes:
    """
    HWP 스트림 압축 해제
    wbits=-15: raw deflate (zlib 헤더/푸터 없음)
    """
    try:
        decompressor = zlib.decompressobj(wbits=-15)
        return decompressor.decompress(compressed_data)
    except zlib.error as e:
        # 압축되지 않은 데이터일 수 있음
        return compressed_data

def compress_stream(data: bytes) -> bytes:
    """HWP 스트림 압축"""
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(data) + compressor.flush()
```

---

## BinData 스트림 분석

### BinData 항목 구조

```
BinData/Bin0000
├── [압축 해제]
│
├── 파일 형식 식별:
│   ├── %!PS-Adobe → EPS 파일
│   ├── D0 CF 11 E0 → OLE 객체
│   ├── FF D8 FF → JPEG
│   ├── 89 50 4E 47 → PNG
│   └── 4D 5A → 실행 파일 (PE)
│
└── 내용 분석 → 탐지 모듈로 전달
```

### BinData 이름 규칙

```
BinData/Bin0000  → 첫 번째 바이너리
BinData/Bin0001  → 두 번째 바이너리
BinData/Bin####  → 최대 9999개 (Bin9999)
```

---

## EPS 파일 구조

### EPS (Encapsulated PostScript) 시그니처

| 형식 | 시그니처 | 설명 |
|------|----------|------|
| Standard | `%!PS-Adobe-3.0 EPSF-3.0` | 일반 EPS |
| Binary | `C5 D0 D3 C6` + 4바이트 오프셋 | 바이너리 EPS 헤더 |
| Minimal | `%!PS` | 최소 PostScript |

### PostScript 명령어 구조

```postscript
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
%%EndComments

% --- 악성코드 패턴 시작 ---
/.eqproc {  % CVE-2017-8291 취약점 트리거
    dup length dict begin
    { 1 index /FID ne
      { def }
      { pop pop }
      ifelse
    } forall
    currentdict end
} bind def

% --- 16진수 쉘코드 ---
<4D5A90000300000004000000FFFF0000B8000000...>

%%EOF
```

---

## OLE 객체 내장 구조

### 중첩 OLE 식별

```python
OLE_MAGIC = b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1'

def find_nested_ole(data: bytes) -> list:
    """바이너리 데이터 내 OLE 객체 검색"""
    positions = []
    pos = 0
    while True:
        pos = data.find(OLE_MAGIC, pos)
        if pos == -1:
            break
        positions.append(pos)
        pos += 1
    return positions
```

### 임베디드 OLE 타입

| CLSID (Class ID) | 설명 | 위험도 |
|------------------|------|--------|
| `00020906-0000-0000-C000-000000000046` | Microsoft Word | 중간 |
| `00020900-0000-0000-C000-000000000046` | Microsoft Excel | 중간 |
| `00020908-0000-0000-C000-000000000046` | Microsoft PowerPoint | 중간 |
| `00020905-0000-0000-C000-000000000046` | Microsoft Equation (EQNEDT32) | **높음** |

---

## 스크립트 스트림 구조

### DefaultJScript 형식

```javascript
// 한글 매크로 스크립트 예시
function OnDocumentOpen() {
    var shell = new ActiveXObject("WScript.Shell");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    
    // 의심 패턴 1: 파일 시스템 접근
    var tempPath = shell.ExpandEnvironmentStrings("%TEMP%");
    var file = fso.CreateTextFile(tempPath + "\\malicious.vbs", true);
    
    // 의심 패턴 2: Base64 디코딩
    var encoded = "TVqQAAMAAAAEAAAA...";  // PE 파일 Base64
    var decoded = base64Decode(encoded);
    
    // 의심 패턴 3: 프로세스 실행
    shell.Run("powershell -enc " + encoded, 0, false);
}
```

### 스크립트 탐지 포인트

| 패턴 | 정규식 예시 | 설명 |
|------|------------|------|
| CreateObject | `CreateXObject\\s*\\(\\s*["']([^"']+)["']` | COM 객체 생성 |
| 파일 접근 | `FileSystemObject|OpenTextFile|CreateTextFile` | 파일 시스템 조작 |
| 네트워크 | `XMLHTTP|WinHttp|InternetExplorer` | HTTP 통신 |
| 실행 | `\\.Run\\s*\\(|\\.Exec\\s*\\(|Shell\\s*\\(` | 명령 실행 |

---

## 파싱 파이프라인

### 단계별 파싱 프로세스

```
┌─────────────────────────────────────────────────────────────┐
│ 1. 파일 열기 및 검증                                         │
│    ├── OLE 매직 확인: D0 CF 11 E0                           │
│    └── olefile.OleFileIO로 로드                              │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. 스트림 열거                                              │
│    ├── olefile.listdir()로 모든 스트림 목록화                 │
│    └── 스트림 타입 분류 (FileHeader, DocInfo, BinData 등)    │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. 스트림 추출 및 압축 해제                                   │
│    ├── FileHeader: 그대로 읽기                               │
│    └── 나머지: zlib.decompress(wbits=-15)                   │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. 콘텐츠 분석                                              │
│    ├── BinData: 파일 시그니처로 타입 식별                     │
│    ├── Scripts: JavaScript 파싱                             │
│    └── BodyText: 문자열 추출 (IOC 검색용)                     │
└────────────────────────┬────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. 결과 반환                                                │
│    ├── 각 스트림의 원본 데이터                               │
│    ├── 추출된 파일/객체 목록                                 │
│    └── 메타데이터 (버전, 암호화 여부 등)                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 참고: HWP 3.0 (레거시)

HWP 3.0은 OLE2 형식을 사용하지 않는 플랫 바이너리 형식입니다.

### HWP 3.0 시그니처

```
파일 시작: "\\x00H\\x00W\\x00P\\x00 \\x00D\\x00o\\x00c\\x00u\\x00m\\x00e\\x00n\\x00t\\x00 \\x00F\\x00i\\x00l\\x00e\\x00" (UTF-16LE)
```

### 현재 프로젝트 범위

- **HWP 5.0+** (OLE2 기반): **지원**
- **HWP 3.0** (레거시): **미지원** (추후 고려)
- **HWPX** (XML 기반): **추후 지원**

---

## 파싱 에러 처리

| 에러 유형 | 원인 | 대응 |
|----------|------|------|
| `NotOLEFileError` | OLE 형식 아님 | HWP 3.0 여부 확인 |
| `zlib.error` | 압축 해제 실패 | 손상된 파일 또는 미압축 |
| `KeyError` | 스트림 없음 | 선택적 스트림이므로 무시 |
| `UnicodeDecodeError` | 인코딩 문제 | Latin-1로 fallback |
