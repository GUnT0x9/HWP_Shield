# 04. 탐지 모듈 상세 (Detection Modules)

## 모듈 개요

HWPShield는 6개의 독립적인 탐지 모듈로 구성됩니다. 각 모듈은 특정 공격 벡터를 전문적으로 탐지합니다.

```
┌─────────────────────────────────────────────────────────────┐
│                      탐지 모듈 아키텍처                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              HWP 파서 (hwp_parser.py)                │   │
│  │         OLE 파싱 → 스트림 추출 → zlib 해제           │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │              모듈 파이프라인 (병렬 실행)              │   │
│  │                                                      │   │
│  │   ┌──────────┐   ┌──────────┐   ┌──────────┐       │   │
│  │   │ EPS      │   │ OLE      │   │ Script   │       │   │
│  │   │ Detector │   │ Detector │   │ Detector │       │   │
│  │   │ (eps_*)  │   │ (ole_*)  │   │(script_*)│       │   │
│  │   └──────────┘   └──────────┘   └──────────┘       │   │
│  │         │               │               │          │   │
│  │         └───────────────┼───────────────┘          │   │
│  │                         │                          │   │
│  │   ┌──────────┐   ┌──────────┐   ┌──────────┐       │   │
│  │   │ IOC      │   │ Steg     │   │ Structure│       │   │
│  │   │ Extractor│   │ Detector │   │ Analyzer │       │   │
│  │   │ (ioc_*)  │   │ (steg_*) │   │(struct_*)│      │   │
│  │   └──────────┘   └──────────┘   └──────────┘       │   │
│  │                                                      │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────────────┐   │
│  │              리스크 스코어링 (scorer.py)                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Module 1: EPS/PostScript 탐지 (CVE-2017-8291)

### 개요

**CVE-2017-8291**은 GhostScript의 `.eqproc` 취약점으로, EPS 파일 처리 중 타입 혼란(type confusion)을 이용해 임의 코드를 실행할 수 있습니다.

- **별칭**: GhostButt
- **사용 APT**: APT37/ScarCruft, APT38, Kimsuky
- **활동 기간**: 2017년 ~ 2023년+ (현재까지 지속)

### 탐지 로직

```python
class EPSDetector:
    def __init__(self):
        self.patterns = {
            'eps_signature': [b'%!PS-Adobe', b'%!PS'],
            'cve_trigger': b'.eqproc',
            'hex_shellcode': rb'<[0-9A-Fa-f]{100,}>',  # 100+ hex chars
            'win32_apis': [
                b'CreateFileA', b'CreateFileW',
                b'GetTempPath', b'GetTempPathA',
                b'WinExec', b'ShellExecuteA',
                b'VirtualAlloc', b'VirtualProtect',
                b'WriteFile', b'ReadFile',
                b'LoadLibraryA', b'GetProcAddress',
                b'URLDownloadToFile', b'InternetOpen',
            ],
            'obfuscation': [
                rb'\\\\d{3}',           # octal escape (\\101)
                rb'\\\\[0-7]{1,3}',     # octal pattern
                rb'<[0-9A-Fa-f]+>',       # hex string
                rb'\\\\(x[0-9A-Fa-f]{2})+',  # hex escape
            ],
            'suspicious_tokens': [
                b'currentfile', b'eexec', b'def', b'exec',
                b'stack', b'pop', b'dup', b'exch',
                b'readstring', b'filter',
            ]
        }
    
    def analyze(self, bindata_streams: list) -> DetectionResult:
        result = DetectionResult(module_id='eps', name='EPS/PostScript 탐지')
        
        for stream_name, stream_data in bindata_streams:
            # 1. EPS 파일 시그니처 확인
            if self._is_eps(stream_data):
                result.add_indicator('EPS_STREAM', stream_name, 'medium')
                
                # 2. CVE-2017-8291 트리거 검색
                if self._has_cve_trigger(stream_data):
                    result.add_indicator('CVE-2017-8291', '.eqproc 발견', 'critical')
                
                # 3. 16진수 쉘코드 패턴 검색
                hex_patterns = self._find_hex_shellcode(stream_data)
                if hex_patterns:
                    result.add_indicator('HEX_SHELLCODE', 
                        f'{len(hex_patterns)}개 패턴 발견', 'high')
                
                # 4. Win32 API 문자열 검색
                apis_found = self._find_win32_apis(stream_data)
                if apis_found:
                    result.add_indicator('WIN32_APIS', 
                        f'발견: {apis_found}', 'critical')
                
                # 5. 난독화 패턴 검색
                obf = self._find_obfuscation(stream_data)
                if obf:
                    result.add_indicator('OBFUSCATION', 
                        f'{len(obf)}개 난독화 패턴', 'medium')
        
        return result
    
    def _is_eps(self, data: bytes) -> bool:
        # EPS 시그니처 확인
        return (data.startswith(b'%!PS-Adobe') or 
                data.startswith(b'%!PS') or
                data.startswith(b'\\xc5\\xd0\\xc3\\xc6'))  # Binary EPS
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| EPS 스트림 존재 | +10 | BinData에 EPS 파일 포함 |
| CVE-2017-8291 패턴 | +30 | `.eqproc` 발견 |
| Win32 API 문자열 | +25 | `CreateFileA`, `WinExec` 등 |
| 16진수 쉘코드 | +20 | 100자 이상 연속 16진수 |
| 난독화 패턴 | +10 | octal/hex escape 사용 |

### 실제 공격 샘플 패턴

```postscript
% APT37 GhostButt 샘플에서 발췌
/.eqproc {
    dup length dict begin
    { 1 index /FID ne
        { def }
        { pop pop }
        ifelse
    } forall
    currentdict end
} bind def

% 16진수 쉘코드 (일부)
<4D5A90000300000004000000FFFF0000B8000000
0000000040000000000000000000000000000000
0000000000000000000000000000000000000000
E8000000005B8B9BBA001000008DB3A7120000>

% WinExec 호출 (hex 인코딩됨)
<57696E45786563>  % "WinExec" in hex
```

---

## Module 2: OLE 객체 탐지

### 개요

2019년 이후 HWP 공격은 EPS가 차단되면서 **OLE(Object Linking and Embedding)** 객체를 임베드하는 방식으로 전환되었습니다.

- **대상**: 한글 2018 이후 버전 (EPS 보안 업데이트 후)
- **공격 방식**: BinData에 OLE 객체 포함 → 클릭 시 실행

### 탐지 로직

```python
class OLEDetector:
    def __init__(self):
        self.patterns = {
            'ole_magic': b'\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1',
            'shell_commands': [
                b'cmd.exe', b'powershell', b'powershell.exe',
                b'wscript', b'cscript', b'wscript.exe', b'cscript.exe',
                b'rundll32', b'rundll32.exe',
                b'mshta', b'mshta.exe',
            ],
            'unc_paths': rb'\\\\\\\\[\\\\w\\\\.]+\\\\[\\\\w\\\\.]+',  # \\\\server\\share
            'file_extensions': [
                b'.exe', b'.dll', b'.bat', b'.cmd',
                b'.ps1', b'.vbs', b'.vbe', b'.js',
                b'.wsf', b'.hta', b'.scr',
            ],
            'auto_exec': [
                b'auto_open', b'autoexec', b'workbook_open',
                b'document_open', b'startup',
            ]
        }
    
    def analyze(self, bindata_streams: list) -> DetectionResult:
        result = DetectionResult(module_id='ole', name='OLE 객체 탐지')
        
        for stream_name, stream_data in bindata_streams:
            # 1. OLE 매직 바이트 검색
            ole_positions = self._find_ole_objects(stream_data)
            
            for pos in ole_positions:
                result.add_indicator('EMBEDDED_OLE', 
                    f'{stream_name} @ offset {pos}', 'high')
                
                # 2. 내부 OLE 분석
                inner_ole = stream_data[pos:pos+4096]  # 헤더만 검사
                
                # 3. CLSID 확인
                clsid = self._extract_clsid(inner_ole)
                if clsid:
                    result.add_indicator('OLE_CLSID', 
                        f'CLSID: {clsid}', 'medium')
                
                # 4. 셸 명령어 검색
                shell_cmds = self._find_shell_commands(stream_data)
                if shell_cmds:
                    result.add_indicator('SHELL_COMMAND', 
                        f'발견: {shell_cmds}', 'critical')
                
                # 5. UNC 경로 검색
                unc_paths = self._find_unc_paths(stream_data)
                if unc_paths:
                    result.add_indicator('UNC_PATH', 
                        f'원격 경로: {unc_paths}', 'high')
        
        return result
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| OLE 객체 임베드 | +20 | BinData 내 OLE 매직 발견 |
| 셸 명령어 | +35 | `cmd`, `powershell` 등 |
| UNC 경로 | +25 | 원격 공유 폴더 참조 |
| 자동 실행 | +30 | `auto_open` 등 |
| 실행 파일 | +30 | `.exe`, `.dll` 참조 |

---

## Module 3: 스크립트 분석

### 개요

HWP는 **DefaultJScript** 스트림을 통해 JavaScript 기반 매크로를 지원합니다. 이는 VBA 매크로와 유사하게 문서 열림/닫힘 이벤트에 코드를 실행할 수 있습니다.

### 탐지 로직

```python
class ScriptDetector:
    def __init__(self):
        self.patterns = {
            'com_objects': [
                b'WScript.Shell', b'Scripting.FileSystemObject',
                b'ADODB.Stream', b'Microsoft.XMLHTTP',
                b'WinHttp.WinHttpRequest',
                b'InternetExplorer.Application',
                b'Shell.Application', b'WMIObject',
            ],
            'file_operations': [
                b'CreateTextFile', b'OpenTextFile',
                b'WriteLine', b'Write',
                b'SaveToFile', b'LoadFromFile',
            ],
            'network_operations': [
                b'XMLHTTP', b'Send', b'ResponseBody',
                b'Open', b'GET', b'POST',
                b'User-Agent', b'Referer',
            ],
            'execution': [
                rb'\\.Run\\s*\\(', rb'\\.Exec\\s*\\(', 
                rb'Shell\\s*\\(',
                b'eval(', b'exec(', b'Execute',
                b'ProcessCreate',
            ],
            'obfuscation': [
                rb'fromCharCode',              % chr() obfuscation
                rb'\\w+\\s*\\+\\s*\\w+\\s*\\+',   % string concatenation
                rb'%[0-9A-Fa-f]{2}',           % URL encoding
                rb'\\\\u[0-9A-Fa-f]{4}',         % Unicode escape
                rb'\\\\x[0-9A-Fa-f]{2}',         % Hex escape
            ],
            'base64': [
                rb'atob\\s*\\(', rb'Base64.decode',
                rb'btoa\\s*\\(', rb'Base64.encode',
                rb'[A-Za-z0-9+/]{50,}={0,2}',  % Base64-like strings
            ]
        }
    
    def analyze(self, script_streams: dict) -> DetectionResult:
        result = DetectionResult(module_id='script', name='스크립트 분석')
        
        if 'Scripts/DefaultJScript' not in script_streams:
            return result  # 스크립트 없음
        
        script_data = script_streams['Scripts/DefaultJScript']
        
        # 1. COM 객체 생성 검사
        com_objects = self._find_com_objects(script_data)
        for obj in com_objects:
            severity = self._get_com_severity(obj)
            result.add_indicator('COM_OBJECT', obj, severity)
        
        # 2. 파일 시스템 접근 검사
        file_ops = self._find_file_operations(script_data)
        if file_ops:
            result.add_indicator('FILE_ACCESS', 
                f'{len(file_ops)}개 파일 작업', 'high')
        
        # 3. 네트워크 접근 검사
        net_ops = self._find_network_operations(script_data)
        if net_ops:
            result.add_indicator('NETWORK_ACCESS', 
                f'{len(net_ops)}개 네트워크 작업', 'high')
        
        # 4. 프로세스 실행 검사
        exec_ops = self._find_execution(script_data)
        for op in exec_ops:
            result.add_indicator('PROCESS_EXECUTION', op, 'critical')
        
        # 5. 난독화 검사
        obf = self._find_obfuscation(script_data)
        if obf:
            result.add_indicator('JAVASCRIPT_OBFUSCATION', 
                f'{len(obf)}개 패턴', 'medium')
        
        # 6. Base64 인코딩 검사
        b64 = self._find_base64(script_data)
        if b64:
            result.add_indicator('BASE64_PAYLOAD', 
                f'{len(b64)}개 의심 문자열', 'high')
        
        return result
    
    def _get_com_severity(self, obj: str) -> str:
        critical = ['WScript.Shell', 'ADODB.Stream']
        high = ['FileSystemObject', 'XMLHTTP']
        medium = ['InternetExplorer.Application']
        
        if any(c in obj for c in critical):
            return 'critical'
        elif any(h in obj for h in high):
            return 'high'
        return 'medium'
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| 매크로 스크립트 존재 | +15 | DefaultJScript 스트림 있음 |
| WScript.Shell | +25 | 셸 접근 |
| FileSystemObject | +20 | 파일 시스템 접근 |
| XMLHTTP | +15 | HTTP 통신 |
| Process 실행 | +30 | `Run()`, `Exec()` |
| Base64 페이로드 | +20 | 인코딩된 데이터 |

---

## Module 4: IOC 추출

### 개요

IOC(Indicators of Compromise)는 악성코드 분석에서 발견된 공격의 흔적입니다. HWP 파일에서 URL, IP 주소, 파일 경로 등을 추출합니다.

### 탐지 로직

```python
class IOCExtractor:
    def __init__(self):
        self.patterns = {
            'url': re.compile(
                rb'https?://[\\\\w\\\\-\\\\.]+[^\\\\s\\\\\"<>{}|\\\\^`\\\\[\\\\]]*',
                re.IGNORECASE
            ),
            'ip': re.compile(
                rb'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
            ),
            'email': re.compile(
                rb'[\\\\w\\\\.+-]+@[\\\\w\\\\.-]+\\.[\\\\w\\\\.]+'
            ),
            'file_path': re.compile(
                rb'%[A-Z_0-9]+%\\\\[^\\\\s]+|C:\\\\[^\\\\s]+|\\\\\\\\[^\\\\s]+'
            ),
            'registry': re.compile(
                rb'HK(EY_)?(LM|CU|CR|U|CC)\\\\[^\\\\s]+|HKEY_[A-Z_]+\\\\[^\\\\s]+'
            ),
            'md5': re.compile(rb'\\b[a-f0-9]{32}\\b'),
            'sha1': re.compile(rb'\\b[a-f0-9]{40}\\b'),
            'sha256': re.compile(rb'\\b[a-f0-9]{64}\\b'),
        }
        
        # 악성 도메인 TLD 패턴 (APT 캠페인에서 자주 사용)
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  % 무료 도메인
            '.top', '.xyz', '.club', '.online', % 의심 TLD
        ]
    
    def analyze(self, all_streams: dict) -> DetectionResult:
        result = DetectionResult(module_id='ioc', name='IOC 추출')
        iocs = []
        
        # 모든 스트림에서 문자열 추출
        combined_data = b''.join(all_streams.values())
        
        # 1. URL 추출
        urls = self._extract_urls(combined_data)
        for url in urls:
            ioc_type = 'url'
            severity = self._assess_url_severity(url)
            iocs.append({'type': ioc_type, 'value': url, 'severity': severity})
        
        # 2. IP 주소 추출
        ips = self._extract_ips(combined_data)
        for ip in ips:
            if not self._is_private_ip(ip):
                iocs.append({'type': 'ip', 'value': ip, 'severity': 'high'})
            else:
                iocs.append({'type': 'ip', 'value': ip, 'severity': 'low'})
        
        # 3. 파일 경로 추출
        paths = self._extract_paths(combined_data)
        for path in paths:
            severity = self._assess_path_severity(path)
            iocs.append({'type': 'path', 'value': path, 'severity': severity})
        
        # 4. 레지스트리 경로 추출
        reg_paths = self._extract_registry(combined_data)
        for reg in reg_paths:
            iocs.append({'type': 'registry', 'value': reg, 'severity': 'high'})
        
        # 5. 해시 추출
        hashes = self._extract_hashes(combined_data)
        for h in hashes:
            iocs.append({'type': 'hash', 'value': h, 'severity': 'info'})
        
        # 중복 제거 및 정렬
        unique_iocs = self._deduplicate_iocs(iocs)
        
        for ioc in unique_iocs:
            result.add_indicator(ioc['type'].upper(), 
                f"{ioc['value']}", ioc['severity'])
        
        return result
    
    def _assess_url_severity(self, url: str) -> str:
        """URL의 위험도 평가"""
        suspicious_domains = ['pastebin', 'githubusercontent', 'drive.google']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.top', '.xyz']
        
        url_lower = url.lower()
        
        for domain in suspicious_domains:
            if domain in url_lower:
                return 'high'
        
        for tld in suspicious_tlds:
            if tld in url_lower:
                return 'medium'
        
        if any(x in url_lower for x in ['.exe', '.dll', '.zip', '.rar']):
            return 'medium'
        
        return 'low'
    
    def _is_private_ip(self, ip: str) -> bool:
        """사설 IP 주소 확인"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        first, second = int(parts[0]), int(parts[1])
        
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        
        return False
    
    def _assess_path_severity(self, path: str) -> str:
        """파일 경로의 위험도 평가"""
        critical_paths = ['%TEMP%', '%APPDATA%', '%LOCALAPPDATA%', 
                         '\\\Windows\\\System32', '\\\Windows\\\SysWOW64']
        suspicious_names = ['svchost', 'csrss', 'lsass', 'winlogon']
        
        path_upper = path.upper()
        
        for cp in critical_paths:
            if cp.upper() in path_upper:
                return 'high'
        
        for sn in suspicious_names:
            if sn in path.lower():
                return 'high'
        
        if path.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs')):
            return 'medium'
        
        return 'low'
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| 외부 URL | +15 | HTTP/HTTPS 링크 |
| 공인 IP | +15 | 비사설 IP 주소 |
| TEMP/APPDATA 경로 | +20 | 시스템 경로 참조 |
| 레지스트리 경로 | +15 | HKLM/HKCU 경로 |
| 의심 도메인 | +20 | 무료 TLD, 파일 호스팅 |
| 실행 파일 경로 | +15 | .exe/.dll 참조 |

---

## Module 5: 스테가노그래피 탐지

### 개요

**스테가노그래피(Steganography)**는 이미지 파일 내부에 다른 파일을 숨기는 기법입니다. RedEyes/APT37의 2023년 M2RAT 캠페인에서 사용되었습니다.

### 공격 체인 (M2RAT)

```
양식.hwp 
    ↓
EPS CVE-2017-8291 exploit
    ↓
Shellcode 실행
    ↓
JPEG 이미지 다운로드 (from C2)
    ↓
스테가노그래피로 숨겨진 PE 추출
    ↓
M2RAT RAT 설치
    ↓
HKCU\\Software\\OneDriver (레지스트리 지속성)
```

### 탐지 로직

```python
class StegDetector:
    def __init__(self):
        self.image_signatures = {
            b'\\xff\\xd8\\xff': 'JPEG',
            b'\\x89PNG': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'BM': 'BMP',
        }
        self.pe_magic = b'MZ'
        self.pe_header_offset = b'PE\\x00\\x00'
    
    def analyze(self, bindata_streams: list) -> DetectionResult:
        result = DetectionResult(module_id='steg', name='스테가노그래피 탐지')
        
        for stream_name, stream_data in bindata_streams:
            # 1. 이미지 파일 식별
            image_type = self._identify_image(stream_data)
            if not image_type:
                continue
            
            result.add_indicator('IMAGE_FOUND', 
                f'{stream_name}: {image_type}', 'info')
            
            # 2. 파일 크기 검증
            expected_size = self._get_image_data_size(stream_data, image_type)
            actual_size = len(stream_data)
            
            if actual_size > expected_size * 1.5:
                result.add_indicator('OVERSIZED_IMAGE',
                    f'예상: {expected_size}, 실제: {actual_size}', 'medium')
            
            # 3. PE 헤더 검색 (이미지 데이터 이후)
            image_end = self._find_image_end(stream_data, image_type)
            if image_end < len(stream_data):
                trailing_data = stream_data[image_end:]
                
                # MZ 헤더 검색
                if trailing_data.startswith(b'MZ'):
                    result.add_indicator('PE_IN_IMAGE',
                        '이미지 뒤에 PE 실행 파일 발견', 'critical')
                
                # PE 시그니처 검색
                pe_offset = trailing_data.find(b'PE\\x00\\x00')
                if pe_offset != -1:
                    result.add_indicator('PE_SIGNATURE',
                        f'PE 시그니처 @ offset {image_end + pe_offset}', 'critical')
                
                # 엔트로피 분석 (암호화/압축된 데이터)
                entropy = self._calculate_entropy(trailing_data)
                if entropy > 7.5:
                    result.add_indicator('HIGH_ENTROPY',
                        f'엔트로피: {entropy:.2f} (의심)', 'high')
            
            # 4. EOF 마커 검사
            if image_type == 'JPEG':
                if not stream_data.rstrip(b'\\x00').endswith(b'\\xff\\xd9'):
                    result.add_indicator('JPEG_EOF_ANOMALY',
                        'JPEG EOF 마커 후 데이터 존재', 'high')
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Shannon 엔트로피 계산 (0-8)"""
        if not data:
            return 0.0
        
        from math import log2
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * log2(p_x)
        
        return entropy
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| 과대 크기 이미지 | +10 | 예상 크기 대비 150%+ |
| PE 헤더 (MZ) | +30 | 이미지에 실행 파일 포함 |
| PE 시그니처 | +20 | PE\\x00\\x00 발견 |
| 높은 엔트로피 | +15 | > 7.5 (암호화/압축된 데이터) |
| EOF 이상 | +10 | JPEG 종료 후 추가 데이터 |

---

## Module 6: 구조적 이상 탐지

### 개요

파일의 구조적 특성을 분석하여 비정상적인 패턴을 탐지합니다. 메타데이터 위조, 크기 불일치 등을 검사합니다.

### 탐지 로직

```python
class StructuralAnalyzer:
    def __init__(self):
        self.suspicious_authors = [
            b'admin', b'user', b'test', b'sample',
            b'windows', b'unknown', b'null', b'',
        ]
        self.machine_patterns = [
            rb'DESKTOP-[A-Z0-9]{7}',
            rb'LAPTOP-[A-Z0-9]{7}',
            rb'PC-[0-9]+',
            rb'WIN-[A-Z0-9]+',
        ]
    
    def analyze(self, file_header: dict, 
                doc_info: bytes, 
                body_text: bytes, 
                bindata_size: int) -> DetectionResult:
        result = DetectionResult(module_id='structural', name='구조적 이상 탐지')
        
        # 1. 작성자 메타데이터 검사
        author = file_header.get('author', '')
        if not author or author.lower() in ['', 'admin', 'user']:
            result.add_indicator('SUSPICIOUS_AUTHOR',
                f'작성자: "{author}"', 'medium')
        
        # 2. 작성자 패턴 검사
        for pattern in self.machine_patterns:
            if re.search(pattern, author.encode()):
                result.add_indicator('MACHINE_AUTHOR',
                    '기본 머신명 작성자', 'medium')
                break
        
        # 3. 문서 버전 검사
        version = file_header.get('version', '')
        if version.startswith('3.') or version.startswith('4.'):
            result.add_indicator('LEGACY_VERSION',
                f'레거시 버전: {version}', 'low')
        
        # 4. 암호화 플래그 검사
        if file_header.get('encrypted', False):
            result.add_indicator('ENCRYPTED_DOCUMENT',
                '암호화된 문서 - 수동 검사 필요', 'high')
        
        # 5. 본문/바이너리 비율 검사
        body_size = len(body_text)
        if body_size > 0:
            ratio = bindata_size / body_size
            if ratio > 10:  # 바이너리가 본문의 10배 이상
                result.add_indicator('CONTENT_MISMATCH',
                    f'BinData/BodyText 비율: {ratio:.1f}', 'medium')
        elif bindata_size > 1000:
            result.add_indicator('NO_BODY_TEXT',
                '본문 없음, 바이너리만 존재', 'high')
        
        # 6. 타임스탬프 검사
        created = file_header.get('created', None)
        modified = file_header.get('modified', None)
        
        if created and modified:
            if modified < created:
                result.add_indicator('TIMESTAMP_ANOMALY',
                    '수정일이 생성일보다 이전', 'medium')
        
        # 7. 매우 작은 문서 검사
        if bindata_size + body_size < 100:
            result.add_indicator('TINY_DOCUMENT',
                '비정상적으로 작은 문서', 'medium')
        
        # 8. 스크립트 플래그 검사
        if file_header.get('has_script', False):
            result.add_indicator('SCRIPT_FLAG',
                '문서에 스크립트 포함 플래그', 'medium')
        
        return result
```

### 리스크 점수

| 지표 | 점수 | 조건 |
|------|------|------|
| 의심 작성자 | +10 | 'admin', 'user', 공백 등 |
| 기계명 작성자 | +10 | DESKTOP-XXXXXX |
| 암호화 문서 | +20 | 분석 불가, 수동 검사 필요 |
| 콘텐츠 불일치 | +15 | BinData/BodyText 비율 10:1 이상 |
| 본문 없음 | +20 | 바이너리만 존재 |
| 타임스탬프 이상 | +10 | 수정 < 생성 |
| 매우 작음 | +10 | 전체 크기 < 100바이트 |
| 스크립트 플래그 | +10 | 스크립트 포함 표시 |
| 레거시 버전 | +5 | HWP 3.0/4.0 |

---

## 모듈 통합 인터페이스

### 통합 실행 코드

```python
from analyzer.eps_detector import EPSDetector
from analyzer.ole_detector import OLEDetector
from analyzer.script_detector import ScriptDetector
from analyzer.ioc_extractor import IOCExtractor
from analyzer.steg_detector import StegDetector
from analyzer.structural_analyzer import StructuralAnalyzer

class AnalysisPipeline:
    def __init__(self):
        self.modules = [
            EPSDetector(),
            OLEDetector(),
            ScriptDetector(),
            IOCExtractor(),
            StegDetector(),
            StructuralAnalyzer(),
        ]
    
    async def run_analysis(self, hwp_data: dict) -> dict:
        """모든 모듈 병렬 실행"""
        import asyncio
        
        # 각 모듈에 필요한 데이터 준비
        results = await asyncio.gather(
            self.modules[0].analyze(hwp_data['bindata']),      # EPS
            self.modules[1].analyze(hwp_data['bindata']),      # OLE
            self.modules[2].analyze(hwp_data['scripts']),      # Script
            self.modules[3].analyze(hwp_data['all_streams']),  # IOC
            self.modules[4].analyze(hwp_data['bindata']),      # Steg
            self.modules[5].analyze(                           # Structural
                hwp_data['file_header'],
                hwp_data['doc_info'],
                hwp_data['body_text'],
                sum(len(d) for _, d in hwp_data['bindata'])
            ),
        )
        
        return {
            'modules': results,
            'timestamp': datetime.utcnow().isoformat(),
        }
```
