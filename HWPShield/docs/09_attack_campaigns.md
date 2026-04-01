# 09. 참고 공격 캠페인 (Attack Campaigns)

## 개요

이 문서는 HWPShield가 탐지해야 하는 주요 APT 공격 캠페인에 대해 설명합니다. 각 캠페인의 특징, 사용된 취약점, 탐지 방법을 정리합니다.

---

## 1. GhostButt (CVE-2017-8291)

### 개요

| 항목 | 내용 |
|------|------|
| **별칭** | GhostButt |
| **CVE** | CVE-2017-8291 |
| **대상 SW** | GhostScript 9.21 이하 |
| **사용 APT** | APT37 (ScarCruft), APT38, Kimsuky |
| **활동 기간** | 2017년 ~ 현재 (7년+) |

### 공격 메커니즘

```
1. HWP 문서 (양식.hwp)
   └── BinData/Bin0000 (EPS 이미지)
       └── PostScript 코드
           ├── .eqproc 정의  ← 취약점 트리거
           ├── 16진수 쉘코드
           └── Win32 API 문자열
               
2. 사용자가 문서 열기
   
3. 한글에서 EPS 렌더링 요청
   → GhostScript 호출
   
4. .eqproc 취약점 트리거
   → 타입 혼란(type confusion)
   → 임의 코드 실행
   
5. 쉘코드 실행
   → PE 로더 동작
   → RAT 설치
```

### 탐지 패턴

```python
GHOSTBUTT_PATTERNS = {
    # EPS 시그니처
    'eps_signature': b'%!PS-Adobe-3.0 EPSF-3.0',
    
    # CVE 트리거
    'cve_trigger': b'.eqproc',
    
    # 16진수 쉘코드 (긴 hex 문자열)
    'hex_shellcode': rb'<[0-9A-Fa-f]{200,}>',
    
    # Win32 API (PE 로더에서 사용)
    'win32_apis': [
        b'CreateFileA', b'CreateFileW',
        b'GetTempPath', b'GetTempPathA',
        b'WinExec', b'ShellExecuteA',
        b'VirtualAlloc', b'VirtualProtect',
        b'WriteFile', b'ReadFile',
        b'LoadLibraryA', b'GetProcAddress',
        b'CreateProcessA',
    ],
    
    # 난독화 패턴
    'obfuscation': [
        rb'\\\\d{3}',           # octal escape
        rb'<[0-9A-Fa-f]+>',       # hex string
    ],
    
    # PostScript 스택 조작
    'stack_manipulation': [
        b'currentfile', b'eexec',
        b'dup', b'exch', b'pop',
    ]
}
```

### 실제 샘플 특징

```postscript
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
%%EndComments

% .eqproc 취약점 트리거
/.eqproc {
    dup length dict begin
    { 1 index /FID ne
      { def }
      { pop pop }
      ifelse
    } forall
    currentdict end
} bind def

% 16진수 인코딩된 쉘코드 (PE 로더)
<4D5A90000300000004000000FFFF0000>
<7C0000000000000040000000000000>
<000000000000000000000000000000>
<000000000000000000000000000000>
...

% 함수 포인터 덮어쓰기
<AAAAAAAAAAAAAAAA>  % 가짜 객체
```

### 탐지 우선순위

| 우선순위 | 패턴 | 위험도 | 점수 |
|---------|------|--------|------|
| 1 | `.eqproc` 발견 | CRITICAL | +30 |
| 2 | 16진수 쉘코드 (>200자) | HIGH | +20 |
| 3 | Win32 API 문자열 | CRITICAL | +25 |
| 4 | PE 로더 패턴 | HIGH | +20 |
| 5 | EPS + 난독화 | MEDIUM | +10 |

---

## 2. OLE 객체 임베드 (Post-2019)

### 개요

| 항목 | 내용 |
|------|------|
| **시작 시점** | 2019년 (EPS 보안 업데이트 후) |
| **공격 방식** | OLE 객체 임베드 |
| **대상** | 한글 2018 이후 버전 |
| **사용 APT** | Kimsuky, Lazarus |

### 공격 메커니즘

```
1. HWP 문서
   └── BinData/Bin0000
       └── OLE 객체 (D0 CF 11 E0)
           ├── 내부 OLE 구조
           ├── 임베디드 실행 파일
           └── 자동 실행 매크로
           
2. 사용자가 문서 열기
   
3. OLE 객체 활성화 (더블클릭)
   또는 자동 실행
   
4. 페이로드 실행
   → 악성코드 다운로드
   → RAT 설치
```

### OLE 임베드 유형

| 유형 | 설명 | 위험도 |
|------|------|--------|
| 임베디드 PE | .exe, .dll 직접 포함 | CRITICAL |
| 임베디드 스크립트 | .vbs, .ps1, .bat 포함 | HIGH |
| 원격 OLE | UNC 경로 (\\\\server\\share) | HIGH |
| 자동 실행 | auto_open, document_open | CRITICAL |

### 탐지 패턴

```python
OLE_INJECTION_PATTERNS = {
    # OLE 매직 (중첩)
    'ole_magic': b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1',
    
    # CLSID (COM 클래스 ID)
    'suspicious_clsid': [
        '00020906-0000-0000-C000-000000000046',  # Word
        '00020900-0000-0000-C000-000000000046',  # Excel
        '00020908-0000-0000-C000-000000000046',  # PowerPoint
        '00020905-0000-0000-C000-000000000046',  # Equation (EQNEDT32)
    ],
    
    # 셸 명령어
    'shell_commands': [
        b'cmd.exe', b'powershell', b'powershell.exe',
        b'wscript', b'cscript',
        b'rundll32', b'mshta',
        b'-enc', b'-encodedcommand',  # PowerShell 인코딩
        b'IEX', b'Invoke-Expression',
    ],
    
    # UNC 경로 (원격 파일)
    'unc_path': rb'\\\\\\\\[\\\\w.-]+\\\\[\\\\w.-]+',
    
    # 자동 실행
    'auto_exec': [
        b'auto_open', b'autoexec',
        b'workbook_open', b'document_open',
        b'startup',
    ],
    
    # 파일 확장자
    'exec_extensions': [
        b'.exe', b'.dll', b'.scr',
        b'.bat', b'.cmd',
        b'.vbs', b'.vbe', b'.js',
        b'.ps1', b'.wsf', b'.hta',
    ]
}
```

### 탐지 우선순위

| 우선순위 | 패턴 | 위험도 | 점수 |
|---------|------|--------|------|
| 1 | OLE 객체 포함 | HIGH | +20 |
| 2 | 셸 명령어 | CRITICAL | +35 |
| 3 | UNC 경로 | HIGH | +25 |
| 4 | 자동 실행 | CRITICAL | +30 |
| 5 | 실행 파일 확장자 | CRITICAL | +30 |

---

## 3. M2RAT (RedEyes/APT37, 2023)

### 개요

| 항목 | 내용 |
|------|------|
| **악성코드** | M2RAT |
| **사용 APT** | RedEyes (APT37의 하위 그룹) |
| **발견 시점** | 2023년 1월 |
| **특징** | 스테가노그래피 + 레지스트리 지속성 |

### 공격 메커니즘 (풀 체인)

```
1. 스피어피싱 이메일
   └── 양식.hwp 첨부
       
2. 문서 열기
   └── BinData (EPS)
       └── CVE-2017-8291 익스플로잇
       
3. 쉘코드 실행
   └── HTTP 요청
       └── JPEG 이미지 다운로드 (from C2)
       
4. 스테가노그래피 추출
   └── JPEG 내부에서 PE 파일 추출
       └── M2RAT 실행 파일
       
5. RAT 설치
   ├── 프로세스 주입
   ├── 키로깅
   ├── 스크린샷 캡처
   └── 파일 탈취
   
6. 지속성 설정
   └── 레지스트리: HKCU\\Software\\OneDriver
       (OneDrive로 위장)
       
7. C2 통신
   ├── MAC 주소 XOR 인코딩으로 봇 식별
   └── AES 암호화 통신
```

### 탐지 포인트

| 단계 | 탐지 모듈 | 패턴 |
|------|----------|------|
| 1 | EPS 탐지 | `.eqproc` |
| 2 | IOC 추출 | C2 URL (JPEG 다운로드) |
| 3 | 스테가노그래피 | JPEG에 PE 헤더 |
| 4 | IOC 추출 | 레지스트리 경로 |
| 5 | IOC 추출 | 의심 프로세스명 |
| 6 | IOC 추출 | `HKCU\\Software\\OneDriver` |
| 7 | IOC 추출 | XOR 패턴 (MAC 주소) |

### 스테가노그래피 패턴

```python
M2RAT_STEG_PATTERNS = {
    # JPEG 시그니처
    'jpeg_soi': b'\\xff\\xd8',
    'jpeg_eoi': b'\\xff\\xd9',
    
    # PE 매직 (스테가노그래피 대상)
    'pe_magic': b'MZ',
    'pe_signature': b'PE\\x00\\x00',
    
    # 검사 지점
    'check_points': [
        'after_eoi',      # EOI 마커 이후
        'trailing_data',  # 파일 끝 트레일링 데이터
        'entropy_check',  # 엔트로피 분석
    ]
}
```

### M2RAT 특징 IOC

```
레지스트리:
- HKCU\\Software\\OneDriver
- HKCU\\Software\\OneDriver\\uid

파일 경로:
- %TEMP%\\[난수].tmp
- %APPDATA%\\Microsoft\\Windows\\[난수]

C2 식별:
- MAC 주소를 XOR하여 봇 ID 생성
- 예: MAC "AA:BB:CC:DD:EE:FF" XOR key = bot ID
```

---

## 4. VBE/VBS 매크로 체인

### 개요

| 항목 | 내용 |
|------|------|
| **타입** | 스크립트 기반 공격 |
| **언어** | VBScript (VBE/VBS) |
| **사용 APT** | Kimsuky, Lazarus |
| **특징** | 다단계 난독화 체인 |

### 공격 메커니즘

```
1. HWP 문서
   └── Scripts/DefaultJScript
       └── JavaScript 매크로
           └── VBE 파일 드롭
               
2. VBE 파일 (Visual Basic Encoded)
   └── VBScript 코드
       └── URL 인코딩된 페이로드
       
3. VBS 파일 생성
   └── 난독화된 PowerShell
       └── Download cradle
       
4. PowerShell 실행
   └── 악성 파일 다운로드/실행
```

### 난독화 패턴

| 단계 | 인코딩 | 예시 |
|------|--------|------|
| 1 | VBE 인코딩 | `#@~^` 시작 |
| 2 | URL 인코딩 | `%48%65%6C%6C%6F` |
| 3 | Base64 | `SGVsbG8gV29ybGQ=` |
| 4 | 문자열 연결 | `"He" & "ll" & "o"` |
| 5 | 변수 분할 | `cmd = "cm" + "d"` |

### 탐지 패턴

```python
VBS_MACRO_PATTERNS = {
    # VBE 시그니처
    'vbe_signature': b'#@~^',
    
    # 스크립트 실행
    'script_exec': [
        b'WScript.Shell',
        b'wscript.shell',
        b'Shell.Application',
        b'CreateObject',
        b'GetObject',
    ],
    
    # 파일 드롭
    'file_drop': [
        b'ADODB.Stream',
        b'SaveToFile',
        b'WriteText',
        b'OpenTextFile',
        b'CreateTextFile',
    ],
    
    # 난독화 패턴
    'obfuscation': [
        rb'&[\\s]*&',           # 문자열 연결
        rb'"[^"]*"[\\s]*\\+[\\s]*"',  # concat
        rb'%[0-9A-Fa-f]{2}',     # URL encoding
        rb'Chr\\s*\\(\\s*\\d+\\s*\\)',  # chr() obfuscation
        rb'\\b\\d+\\b[\\s]*\\+[\\s]*',  # 숫자 연결
    ],
    
    # PowerShell 인디케이터
    'powershell': [
        b'powershell',
        b'-enc',
        b'-encodedcommand',
        b'IEX',
        b'Invoke-Expression',
        b'Net.WebClient',
        b'DownloadString',
        b'DownloadFile',
    ]
}
```

### 탐지 우선순위

| 우선순위 | 패턴 | 위험도 | 점수 |
|---------|------|--------|------|
| 1 | VBE 파일 드롭 | HIGH | +25 |
| 2 | PowerShell 실행 | CRITICAL | +30 |
| 3 | 다운로드 cradle | HIGH | +25 |
| 4 | 문자열 난독화 | MEDIUM | +15 |
| 5 | URL 인코딩 | MEDIUM | +10 |

---

## 5. APT37 (ScarCruft) 전술

### TTP (Tactics, Techniques, Procedures)

| MITRE ATT&CK ID | 기술 | 설명 |
|----------------|------|------|
| T1566.001 | 스피어피싱 첨부파일 | HWP 문서 사용 |
| T1203 | 취약점 익스플로잇 | CVE-2017-8291 |
| T1059.005 | Visual Basic | VBS 매크로 |
| T1027 | 난독화 파일 | 인코딩된 페이로드 |
| T1071 | C2 통신 | HTTP/HTTPS |
| T1105 | 도구 전송 | 다운로더 |
| T1547.001 | 레지스트리 실행 | 지속성 |

### 공격 시간대

| 기간 | 주요 활동 |
|------|----------|
| 2017-2018 | CVE-2017-8291 초기 활용 |
| 2019-2020 | OLE 객체 전환 |
| 2021-2022 | 다중 스테이지 페이로드 |
| 2023-현재 | M2RAT, 레지스트리 지속성 |

---

## 6. Kimsuky 전술

### 특징

| 특징 | 설명 |
|------|------|
| **타겟** | 한국 정부, 연구기관, 전문가 |
| **유인** | 정부 문서, 정책 파일 위장 |
| **스타일** | 고품질 스피어피싱 |
| **도구** | HWP, PDF, ISO 파일 |

### HWP 공격 유형

1. **양식 위장**
   - "정부청_입력양식.hwp"
   - "정책_설문조사.hwp"
   - "회의록_초안.hwp"

2. **긴급성 활용**
   - "긴급_공지사항.hwp"
   - "당일까지_제출.hwp"
   - "회신요망.hwp"

3. **공신력 위장**
   - 정부 기관 로고 삽입
   - 실제 담당자 이름 사용
   - 정확한 연락처 정보

---

## 7. 탐지 테스트 케이스

### 테스트 샘플 구조

```
test_samples/
├── ghostbutt/
│   ├── sample_001_eqproc_only.hwp      # 기본 .eqproc
│   ├── sample_002_with_shellcode.hwp   # 쉘코드 포함
│   ├── sample_003_full_exploit.hwp     # 완전 익스플로잇
│   └── sample_004_obfuscated.hwp       # 난독화 버전
│
├── ole_injection/
│   ├── sample_001_embedded_exe.hwp     # PE 포함
│   ├── sample_002_embedded_vbs.hwp     # VBS 포함
│   ├── sample_003_unc_path.hwp         # 원격 OLE
│   └── sample_004_auto_exec.hwp        # 자동 실행
│
├── steganography/
│   ├── sample_001_jpeg_with_pe.hwp     # PE 숨김
│   ├── sample_002_high_entropy.hwp     # 높은 엔트로피
│   └── sample_003_eof_anomaly.hwp      # EOF 이상
│
└── benign/
    ├── normal_001_empty.hwp            # 빈 문서
    ├── normal_002_with_image.hwp       # 이미지 포함
    ├── normal_003_with_table.hwp       # 표 포함
    └── normal_004_with_macro_legit.hwp # 정상 매크로
```

### 탐지 기준

| 샘플 유형 | 기대 결과 | 최소 점수 |
|-----------|----------|----------|
| ghostbutt_001 | DETECTED | 30+ |
| ghostbutt_002 | DETECTED | 50+ |
| ghostbutt_003 | MALICIOUS | 70+ |
| ole_001 | HIGH_RISK | 50+ |
| ole_002 | HIGH_RISK | 40+ |
| steg_001 | HIGH_RISK | 30+ |
| benign_* | CLEAN | < 15 |

---

## 8. 참고 자료

### 보고서 및 분석

1. **FireEye GhostButt Analysis**
   - URL: https://www.fireeye.com/blog/threat-research/2017/05/ghostbutt.html
   - 내용: CVE-2017-8291 최초 분석

2. **ESTsecurity RedEyes M2RAT**
   - 2023년 1월 보고서
   - 스테가노그래피 기법 상세

3. **AhnLab APT37 보고서**
   - 한국 APT 그룹 분석
   - HWP 공격 추이

4. **KISA 보안 공지**
   - 한국인터넷진흥원 HWP 보안 권고
   - CVE-2017-8291 대응 방안

### MITRE ATT&CK 매핑

| APT 그룹 | ID | 참고 |
|----------|-----|------|
| APT37 | G0067 | https://attack.mitre.org/groups/G0067/ |
| APT38 | G0082 | https://attack.mitre.org/groups/G0082/ |
| Kimsuky | G0094 | https://attack.mitre.org/groups/G0094/ |
| Lazarus | G0032 | https://attack.mitre.org/groups/G0032/ |

### CVE 정보

| CVE | CVSS | 설명 |
|-----|------|------|
| CVE-2017-8291 | 7.8 | GhostScript .eqproc 취약점 |
| CVE-2018-16509 | 9.8 | GhostScript RCE |
| CVE-2023-36664 | 9.8 | GhostScript pipeline 처리 |
