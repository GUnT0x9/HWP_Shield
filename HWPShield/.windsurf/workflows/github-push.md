# HWPShield GitHub Push 가이드

## 처음 push 하는 경우 (init 필요)

```bash
cd /mnt/d/school_project/HWPShield

# 1. git 초기화
git init

# 2. 사용자 설정 (처음 한번만)
git config user.name "Your Name"
git config user.email "your.email@example.com"

# 3. 모든 파일 추가
git add .

# 4. 커밋
git commit -m "feat: HWPShield 한글 문서 보안 분석 도구

- OLE/HWPX 파일 파싱 엔진
- EPS 취약점 탐지 (CVE-2017-8291)
- OLE 객체 분석 (이미지/EXE 구분)
- 155+ 키워드 패턴 매칭
- React 기반 웹 UI
- 실시간 분석 결과 표시"

# 5. GitHub remote 연결
git remote add origin https://github.com/GUnT0x9/HWPShield.git

# 6. push (로그인 필요)
git push -u origin main
```

---

## 이미 init 되어 있는 경우

```bash
cd /mnt/d/school_project/HWPShield

git add .
git commit -m "update: 기능 개선 및 버그 수정"
git push origin main
```

---

## 로그인 방법

### 방법 1: GitHub CLI (권장)
```bash
# 설치되어 있으면
gh auth login

# 브라우저에서 로그인 후
git push -u origin main
```

### 방법 2: HTTPS + 토큰
```bash
# GitHub에서 Personal Access Token 생성
# https://github.com/settings/tokens

git push https://<TOKEN>@github.com/GUnT0x9/HWPShield.git main
```

### 방법 3: SSH (설정 필요)
```bash
# SSH key 생성 (처음 한번)
ssh-keygen -t ed25519 -C "your.email@example.com"
cat ~/.ssh/id_ed25519.pub

# GitHub에 SSH key 등록 후
git remote set-url origin git@github.com:GUnT0x9/HWPShield.git
git push origin main
```

---

## .gitignore 확인 사항

제외되는 항목:
- ✅ `venv/` - Python 가상환경
- ✅ `node_modules/` - npm 패키지
- ✅ `__pycache__/` - Python 캐시
- ✅ `*.log` - 로그 파일
- ✅ `*.hwp`, `*.hwpx` - 테스트 문서
- ✅ `.env` - 환경변수
- ✅ `tmp/`, `temp/` - 임시 파일

포함되는 항목:
- ✅ 소스 코드 (`*.py`, `*.tsx`, `*.ts`)
- ✅ 설정 파일 (`vite.config.ts`, `package.json`)
- ✅ 문서 (`README.md`, `TECHNICAL_DOCUMENTATION.md`)

---

## 에러 해결

### 1. "rejected: non-fast-forward"
```bash
git pull origin main --rebase
git push origin main
```

### 2. "Permission denied"
- GitHub 토큰/권한 확인
- Repository 접근 권한 확인

### 3. "fatal: not a git repository"
```bash
git init
git add .
git commit -m "init"
```

---

## push 후 확인

```bash
# GitHub에서 확인
open https://github.com/GUnT0x9/HWPShield

# 또는 CLI에서 확인
gh repo view GUnT0x9/HWPShield --web
```
