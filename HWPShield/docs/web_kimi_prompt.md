## Web Kimi에게 보낼 프롬프트 (샘플 악성 HWP 파일 생성 요청)

아래 내용을 그대로 복사해서 Web Kimi에게 보내세요:

---

### 🎯 목표
HWPShield 악성코드 스캐너 테스트용 **안전한 샘플 HWP 파일** 2개를 생성해주세요.

⚠️ **중요**: 실제 악성코드가 아닌, 스캐너 감지 테스트용 패턴만 포함한 파일입니다. EICAR 테스트 파일과 같은 원리입니다.

---

### 📋 요구사항

#### 파일 1: `sample_eps_exploit.hwp` (EPS 취약점 테스트)
- **OLE2/CFB 형식**의 한글 파일 구조
- **EPS 스트림** 포함 (BIN0001.eps 또는 유사 이름)
- EPS 내용에 다음 키워드 포함:
  ```
  %!PS-Adobe-3.1 EPSF-3.0
  %%BoundingBox: 0 0 100 100
  eqproc
  test_execute
  system
  ```
- **헤더**: OLE Magic `D0 CF 11 E0 A1 B1 1A E1`
- **크기**: 약 2-3KB

#### 파일 2: `sample_exe_dropper.hwp` (EXE 드로퍼 테스트)
- **OLE2/CFB 형식**
- **Ole10Native 스트림** 포함
- Ole10Native 내용:
  - 시작 부분: `MZ` (Windows EXE 매직 바이트, 가짜)
  - 중간에 `%TEMP%\test.txt` 문자열 포함
  - 실제 실행 코드는 없고 문자열만
- **크기**: 약 3-4KB

---

### 🔧 기술 상세사항

#### OLE 파일 구조 요구사항:
```
[Header: 512 bytes]
- Offset 0x00: D0 CF 11 E0 A1 B1 1A E1 (OLE Magic)
- Offset 0x30: 3E 00 (Minor version)
- Offset 0x32: 03 00 (Major version)
- Offset 0x44: 01 00 00 00 (FAT sector count = 1)
- Offset 0x48: 00 00 00 00 (First directory sector)

[FAT: 512 bytes]
- Sector chain pointers

[Directory: 512 bytes]
- 128 bytes per entry
- Entry 0: Root Entry
- Entry 1: FileHeader stream or Ole10Native

[Data Streams]
- FileHeader stream (HWP signature)
- EPS or Ole10Native stream
```

#### UTF-16-LE 인코딩 예시:
- "Root Entry" → `52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00`
- "BIN0001.eps" → `42 00 49 00 4E 00 30 00 30 00 30 00 31 00 2E 00 65 00 70 00 73 00`

---

### 📝 출력 형식

파이썬 코드로 생성하거나, 직접 바이너리 파일을 생성해서 **Base64 인코딩**하여 제공해주세요.

예시 출력:
```python
# 파일 1: sample_eps_exploit.hwp
file1_data = bytes([
    0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,  # OLE Magic
    # ... (나머지 바이트)
])

# 파일 2: sample_exe_dropper.hwp  
file2_data = bytes([
    0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,
    # ... (나머지 바이트)
])
```

또는 Base64:
```
# sample_eps_exploit.hwp (Base64)
0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA...

# sample_exe_dropper.hwp (Base64)
0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA...
```

---

### ✅ 검증 기준
생성된 파일은 다음 조건을 만족해야 합니다:

1. **파일 1 (EPS)**:
   - `file` 명령어 실행 시 "Microsoft Compound Document File" 출력
   - `strings` 명령어 실행 시 "%!PS-Adobe"와 "eqproc" 발견
   - OLE 파싱 시 BIN0001.eps 스트림 존재

2. **파일 2 (EXE 드로퍼)**:
   - `file` 명령어 실행 시 "Microsoft Compound Document File" 출력
   - `strings` 명령어 실행 시 "MZ"와 "%TEMP%" 발견
   - Ole10Native 스트림 존재

---

### ⚠️ 안전 고지
- 이 파일들은 **실제 악성코드가 아닙니다**
- 실제 exploit 코드는 포함하지 마세요
- 단순히 스캐너의 패턴 매칭을 테스트하기 위한 "시그니처"만 포함
- 실제 시스템에서 실행해도 해를 끼치지 않음

---

생성 완료 후 바이너리 데이터 또는 Base64 인코딩된 문자열을 제공해주세요.
