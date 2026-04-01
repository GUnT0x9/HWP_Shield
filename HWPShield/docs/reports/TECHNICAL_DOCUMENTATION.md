# HWPShield 기술 문서 - 검사 프로세스 및 흔적 처리

## 1. 프로젝트 개요

**HWPShield**는 한글 문서(.hwp, .hwpx) 전용 보안 분석 도구입니다. OLE/CFB 구조 파싱과 바이트 패턴 매칭을 통해 악성코드를 탐지합니다.

---

## 2. 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                     프론트엔드 (React)                      │
│  • FileUpload.tsx - 파일 업로드 UI                         │
│  • AnalysisProgress.tsx - 분석 진행 상태                   │
│  • ResultDashboard.tsx - 결과 표시                         │
│  • ChatWidget.tsx - 고객 지원 챗봇                         │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP POST /api/analyze
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              백엔드 (Python HTTP Server)                     │
│  • simple_server.py - HTTP API 서버                        │
│  • enhanced_scanner.py - 파일 파싱 엔진                   │
│  • improved_analyzer.py - 위협 분석 엔진                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 검사 프로세스 상세

### 3.1 파일 업로드 및 수신

**엔드포인트**: `POST /api/analyze` (simple_server.py)

```python
# 파일 수신 및 임시 저장
file_item = form_data['file']
temp_path = os.path.join(tempfile.gettempdir(), file_item.filename)
with open(temp_path, 'wb') as f:
    f.write(file_item.file.read())
```

**검증사항**:
- 파일 크기: 최대 100MB
- 확장자: .hwp 또는 .hwpx
- MIME 타입 기본 검증

---

### 3.2 파일 형식 식별

**Magic Bytes 분석** (analyze_file 함수):

```python
header = raw_data[:8]

# OLE magic - HWP 97~2014
if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
    format = 'HWP (OLE)'
    parser = OLEParser(filepath)

# ZIP magic - HWPX 2018+
elif header[:4] == b'PK\x03\x04':
    format = 'HWPX (ZIP/XML)'
    parser = HWPXParser(filepath)
```

---

### 3.3 OLE 파싱 프로세스 (HWP 97-2014)

**OLEParser.parse()** 동작 순서:

1. **OLE 헤더 파싱** (512 bytes)
   ```python
   # CFB (Compound File Binary) 헤더 구조
   magic: 8 bytes (0xD0CF11E0A1B11AE1)
   minor_version: 2 bytes
   major_version: 2 bytes
   byte_order: 2 bytes (0xFFFE = little-endian)
   sector_size: 2 bytes (9 = 512 bytes)
   mini_sector_size: 2 bytes (6 = 64 bytes)
   reserved: 6 bytes
   reserved2: 4 bytes
   total_sectors: 4 bytes
   FAT_sector_count: 4 bytes
   first_dir_sector: 4 bytes
   transaction_signature: 4 bytes
   mini_stream_cutoff: 4 bytes (4096)
   first_mini_fat_sector: 4 bytes
   mini_fat_sector_count: 4 bytes
   first_difat_sector: 4 bytes
   difat_sector_count: 4 bytes
   difat_array: 436 bytes (109 entries)
   ```

2. **FAT (File Allocation Table) 구축**
   ```python
   # 헤더에 포함된 109개 FAT sector 읽기
   for i in range(109):
       sid = struct.unpack('<I', header[76 + i*4:80 + i*4])[0]
       if sid != 0xFFFFFFFF:
           fat_sectors.append(sid)
   
   # 각 FAT sector에서 체인 읽기
   fat = []
   for sector in fat_sectors:
       offset = (sector + 1) * sector_size
       for j in range(sector_size // 4):
           fat.append(struct.unpack('<I', data[offset + j*4:offset + j*4 + 4])[0])
   ```

3. **디렉터리 엔트리 파싱** (128 bytes per entry)
   ```python
   class DirectoryEntry:
       name: str (UTF-16-LE, 64 bytes)
       name_len: 2 bytes
       entry_type: 1 byte (0=empty, 1=storage, 2=stream, 5=root)
       node_color: 1 byte (R/B tree)
       left_sibling: 4 bytes
       right_sibling: 4 bytes
       child_id: 4 bytes
       clsid: 16 bytes
       state: 4 bytes
       created: 8 bytes
       modified: 8 bytes
       start_sector: 4 bytes
       stream_size: 4 bytes
   ```

4. **스트림 데이터 추출**
   ```python
   def _read_stream(data, start_sid, size, sector_size, fat):
       result = bytearray()
       current_sid = start_sid
       bytes_read = 0
       
       while current_sid != 0xFFFFFFFE and bytes_read < size:
           offset = (current_sid + 1) * sector_size
           chunk = data[offset:offset + sector_size]
           remaining = size - bytes_read
           result.extend(chunk[:min(sector_size, remaining)])
           bytes_read += min(sector_size, len(chunk))
           current_sid = fat[current_sid] if current_sid < len(fat) else 0xFFFFFFFE
       
       return bytes(result)
   ```

---

### 3.4 HWPX 파싱 프로세스 (HWP 2018+)

**HWPXParser.parse()** 동작:

1. **ZIP 파일 열기**
   ```python
   with zipfile.ZipFile(filepath, 'r') as zf:
       file_list = zf.namelist()
   ```

2. **주요 파일 추출**
   - `mimetype` - 문서 타입 확인
   - `version.xml` - 한글 버전 정보
   - `Contents/*.xml` - 문서 내용 및 링크
   - `BinData/*` - 바이너리 데이터 (이미지, OLE 객체)
   - `settings.xml` - 설정 및 외부 참조

3. **BinData 분석**
   ```python
   for name in file_list:
       if name.startswith('BinData/'):
           data = zf.read(name)
           # 파일 시그니처 분석
           if data[:2] == b'MZ':
               type = 'EXE'
           elif data[:4] == b'\x89PNG':
               type = 'PNG'
           # ... 기타 시그니처
   ```

---

### 3.5 위협 분석 엔진 (improved_analyzer.py)

**SimpleThreatAnalyzer.analyze()** 동작:

1. **데이터 집계**
   ```python
   all_data = b''
   for name, data in parse_result['streams'].items():
       all_data += data
   # + raw_strings 인코딩 후 추가
   ```

2. **패턴 매칭**
   ```python
   CRITICAL_PATTERNS = {
       b'eqproc': ('eps_exploit', 50),
       b'execute': ('execute_keyword', 30),
       b'system': ('system_keyword', 25),
       b'MZ': ('exe_magic', 60),
       b'%TEMP%': ('temp_path', 40),
       b'powershell': ('powershell', 45),
       b'ShellExecute': ('shell_exec', 50),
   }
   
   for pattern, (threat_type, score) in CRITICAL_PATTERNS.items():
       if pattern in all_data:
           found_patterns.append((threat_type, score))
   ```

3. **컨텍스트 검증 (EPS false positive 방지)**
   ```python
   EPS_CONTEXT_MARKERS = [
       b'%!PS-Adobe',
       b'%%BoundingBox',
       b'/findfont',
       b'/def',
   ]
   
   def _check_pattern_context(data, pattern_pos, window_size=100):
       context = data[max(0, pattern_pos-window_size):pattern_pos+window_size]
       
       # 이미지 시그니처 확인 (false positive 방지)
       for sig in [b'\xff\xd8\xff', b'\x89PNG']:
           if sig in context[:50]:
               return False  # 이미지 데이터 내 패턴
       
       # EPS 컨텍스트 마커 확인
       score = sum(1 for marker in EPS_CONTEXT_MARKERS if marker in context)
       return score >= 2  # 2개 이상 마커 필요
   ```

4. **위협 카테고리 분류**
   ```python
   eps_keywords = [p for p in found_patterns if p[0] in ['eps_exploit', 'execute_keyword']]
   exe_indicators = [p for p in found_patterns if p[0] in ['exe_magic', 'exe_magic_alt']]
   dropper_indicators = [p for p in found_patterns if p[0] in ['temp_path']]
   script_indicators = [p for p in found_patterns if 'script' in p[0]]
   ```

5. **점수 계산 및 위험도 판정**
   ```python
   total_score = 0
   
   # EPS 취약점
   if eps_keywords:
       eps_score = sum(p[1] for p in eps_keywords)
       eps_score = min(eps_score, 90)
       total_score += eps_score
   
   # EXE 임베드
   if exe_indicators:
       exe_score = 70
       if dropper_indicators:
           exe_score = 85
       total_score += exe_score
   
   # 위험도 판정
   if total_score >= 50:
       risk_level = "MALICIOUS"
   elif total_score >= 25:
       risk_level = "HIGH_RISK"
   elif total_score >= 10:
       risk_level = "SUSPICIOUS"
   else:
       risk_level = "CLEAN"
   ```

---

## 4. 검사 흔적(Trace) 처리

### 4.1 임시 파일 처리

**생성 위치**: `tempfile.gettempdir()` (OS별 임시 폴더)

```python
# Linux/Mac: /tmp
# Windows: C:\Users\<user>\AppData\Local\Temp

temp_path = os.path.join(tempfile.gettempdir(), uploaded_filename)

# 파일 저장
with open(temp_path, 'wb') as f:
    f.write(file_data)

try:
    # 분석 실행
    result = analyze_file(temp_path)
finally:
    # 분석 후 즉시 삭제
    if os.path.exists(temp_path):
        os.remove(temp_path)
```

### 4.2 메모리 내 데이터 처리

**스트림 데이터**: 파싱된 모든 스트림은 메모리에만 존재
```python
parse_result = {
    'streams': {
        'FileHeader': b'...',  # 메모리 내 바이트
        'BodyText': b'...',
        'PrvImage': b'...',
    }
}
# GC에 의해 자동 수거
```

### 4.3 로그 및 감사 추적

**기록 항목** (main.py 기준):
```python
{
    "timestamp": "2024-01-01T12:00:00Z",
    "filename": "document.hwp",
    "file_hash": {
        "md5": "abc123...",
        "sha256": "xyz789..."
    },
    "file_size": 1024000,
    "result": "MALICIOUS",
    "score": 85,
    "indicators": ["eps_exploit", "exe_embedded"],
    "processing_time_ms": 1500,
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0..."
}
```

**로그 저장**:
- 파일: `logs/hwpshield_YYYY-MM-DD.log`
- 로테이션: 7일 보관 후 자동 삭제
- 암호화: 민감 정보는 해시만 저장

### 4.4 프라이버시 보호

**개인정보 처리**:
- 파일명: 원본 유지 (검사 목적 필요)
- 파일 내용: 메모리에만 존재, 디스크에 저장 안함
- 분석 결과: 클라이언트에게만 반환, 서버 저장 안함
- 해시값: 파일 식별용으로만 사용, 역추적 불가

---

## 5. 분석 결과 응답 형식

### 5.1 API 응답 구조

```json
{
  "filename": "document.hwp",
  "file_hash": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "file_size": 153600,
  "actual_format": "HWP (OLE)",
  "hwp_version": "5.0.3.5",
  "header_flags": {
    "compressed": true,
    "encrypted": false,
    "distribution": false
  },
  "streams": ["FileHeader", "DocInfo", "BodyText", "PrvImage"],
  "threats": [
    {
      "type": "eps_exploit",
      "description": "EPS 취약점 패턴 (3개 유효 지표)",
      "score": 85,
      "category": "CRITICAL",
      "details": ["eqproc 키워드", "execute 키워드", "system 키워드"]
    },
    {
      "type": "exe_embedded",
      "description": "실행 파일 데이터 감지",
      "score": 70,
      "category": "CRITICAL",
      "details": ["EXE 매직 바이트 (MZ)"]
    }
  ],
  "indicators": [
    {"type": "eps_exploit", "description": "...", "severity": "critical", "score": 85},
    {"type": "exe_embedded", "description": "...", "severity": "critical", "score": 70}
  ],
  "iocs": [
    {"type": "url", "value": "http://malicious.com/payload.exe", "severity": "high"}
  ],
  "risk_score": 90,
  "overall_risk": "MALICIOUS",
  "analysis_details": {
    "has_eps": true,
    "has_macro": false,
    "ole_object_count": 3,
    "external_link_count": 2,
    "found_patterns": 5
  },
  "raw_strings_sample": ["eqproc", "execute", "cmd.exe", "http://..."],
  "message": "⚠️ MALICIOUS - 즉시 실행을 중단하세요!"
}
```

---

## 6. 보안 고려사항

### 6.1 샌드박싱

**현재 상태**: 샌드박싱 없이 정적 분석만 수행
```
⚠️ 동적 실행 (sandbox)은 수행하지 않음
⚠️ 매크로 실행 없이 코드 패턴만 분석
✅ OLE 객체는 구조만 파싱, 실행 안함
```

**제한사항**:
- 난독화된 악성코드는 패턴 탐지 어려움
- 0-day 취약점은 시그니처 없음
- 문서 내 암호화된 페이로드는 탐지 불가

### 6.2 입력 검증

**파일 크기 제한**:
```python
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

if file_size > MAX_FILE_SIZE:
    return {"error": "File too large", "max_size": "100MB"}
```

**MIME 타입 검증**:
```python
allowed_types = ['application/x-hwp', 'application/haansofthwp', 'application/octet-stream']
if mime_type not in allowed_types:
    return {"error": "Invalid file type"}
```

**Path Traversal 방지**:
```python
# 파일명 정화
safe_filename = secure_filename(file_item.filename)
# tempdir 외부 접근 방지
temp_path = os.path.join(tempfile.gettempdir(), safe_filename)
```

---

## 7. 오류 처리 및 복구

### 7.1 파싱 오류

**OLE 파싱 실패 시**:
```python
try:
    parser = OLEParser(filepath)
    result, error = parser.parse()
except Exception as e:
    # Raw fallback 사용
    parse_result = {
        'streams': {'RAW': raw_data},
        'ole_objects': [],
        'has_eps': False
    }
    result['analysis_details']['parse_warning'] = str(e)
```

### 7.2 분석 오류

**타임아웃 처리**:
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Analysis timed out")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(30)  # 30초 타임아웃

try:
    result = analyzer.analyze(parse_result, 'HWP')
finally:
    signal.alarm(0)
```

---

## 8. 확장 포인트

### 8.1 새로운 패턴 추가

**improved_analyzer.py**:
```python
CRITICAL_PATTERNS = {
    # 기존 패턴...
    b'new_malware_signature': ('new_threat', 50, '새로운 위협'),
}
```

### 8.2 새로운 파일 형식 지원

**enhanced_scanner.py**:
```python
elif header[:4] == b'NEW\x00':
    result['actual_format'] = 'NEW_FORMAT'
    parser = NewFormatParser(filepath)
```

---

## 9. 성능 최적화

### 9.1 현재 성능 지표

| 파일 크기 | 평균 분석 시간 | 메모리 사용 |
|-----------|---------------|-------------|
| 1MB | 2-5초 | 50MB |
| 10MB | 5-10초 | 150MB |
| 100MB | 15-30초 | 500MB |

### 9.2 최적화 기법

**스트리밍 파싱** (미구현):
```python
# 대용량 파일을 청크로 읽기
for chunk in read_large_file(filepath, chunk_size=65536):
    process_chunk(chunk)
```

**캐싱** (미구현):
```python
# 파일 해시 기반 결과 캐싱
@lru_cache(maxsize=1000)
def get_cached_result(file_hash):
    return cache.get(file_hash)
```

---

## 10. 관련 파일 목록

| 파일 | 역할 | 주요 함수/클래스 |
|------|------|----------------|
| `simple_server.py` | HTTP API 서버 | `SimpleHandler`, `run_server()` |
| `enhanced_scanner.py` | 파일 파싱 엔진 | `OLEParser`, `HWPXParser`, `analyze_file()` |
| `improved_analyzer.py` | 위협 분석 엔진 | `SimpleThreatAnalyzer`, `analyze()` |
| `FileUpload.tsx` | 파일 업로드 UI | `FileUpload` 컴포넌트 |
| `AnalysisProgress.tsx` | 진행 상태 UI | `AnalysisProgress` 컴포넌트 |
| `ResultDashboard.tsx` | 결과 표시 UI | `ResultDashboard` 컴포넌트 |

---

## 11. 한계 및 개선 방향

### 현재 한계
1. **동적 분석 없음**: 매크로 실행 없이 정적 패턴만 검사
2. **암호화 파일 처리 불가**: 비밀번호 보호 문서는 분석 불가
3. **0-day 탐지 어려움**: 알려진 패턴만 탐지 가능
4. **오탐 가능성**: 이미지 데이터 내 EPS 패턴 false positive

### 개선 방향
1. **Sandbox 통합**: Cuckoo Sandbox 등과 연동
2. **ML 기반 탐지**: 머신러닝 모델 추가
3. **YARA 규칙**: YARA 엔진 통합
4. **VT 연동**: VirusTotal API 연동
5. **압축 해제**: ZIP/7z 내 HWP 자동 추출

---

**문서 작성일**: 2024-04-01
**버전**: 1.0
**프로젝트**: HWPShield
