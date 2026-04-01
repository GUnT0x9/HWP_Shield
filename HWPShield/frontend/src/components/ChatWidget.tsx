import { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Bot, User } from 'lucide-react';

interface Message {
  id: string;
  text: string;
  sender: 'user' | 'bot';
  timestamp: Date;
}

interface ChatResponse {
  keywords: string[];
  response: string;
  language: 'ko' | 'en' | 'ja' | 'zh';
}

// Korean only response database - EXTENSIVE VARIETY
const CHAT_RESPONSES = [
  // === 인사/환영 ===
  {
    keywords: ['안녕', '하이', 'hi', 'hello', 'hey', '반가워', '누구', '뭐해', '챗봇', '봇'],
    responses: [
      '안녕하세요! HWPShield 고객센터입니다. 무엇을 도와드릴까요? 🛡️',
      '안녕하세요! 한글 문서 보안 전문가 HWPShield입니다. 어떤 도움이 필요하신가요?',
      '반갑습니다! HWPShield 고객지원팀입니다. 문의사항이 있으신가요?',
      '안녕하세요! 안전한 한글 문서 사용을 도와드리는 챗봇입니다. 무엇을 도와드릴까요?'
    ]
  },
  {
    keywords: ['잘가', '바이', 'bye', '종료', '나가', '끝', '고마웠어', '감사했어'],
    responses: [
      '이용해 주셔서 감사합니다! 안전한 하루 되세요 👋',
      '다음에 또 찾아주세요! 안전한 문서 작업 되세요!',
      '감사합니다! 문서 보안은 HWPShield와 함께!'
    ]
  },

  // === 파일 분석/검사 ===
  {
    keywords: ['분석', '검사', '스캔', '검증', '진단', '체크', '확인', '조사'],
    responses: [
      '파일 분석은 상단의 "파일 선택" 버튼을 클릭하여 HWP 파일을 업로드하시면 됩니다. 분석 결과는 위험도(CLEAN, SUSPICIOUS, HIGH_RISK, MALICIOUS)로 표시됩니다.',
      '검사하려면 파일을 드래그&드롭하거나 "파일 선택" 버튼을 클릭하세요. 약 10-30초 소요됩니다.',
      'HWPShield는 파일 헤더, OLE 구조, 스크립트, 외부 링크 등을 분석합니다. 상단에서 파일을 업로드해주세요!'
    ]
  },
  {
    keywords: ['결과', '위험도', '등급', '판정', 'clean', 'suspicious', 'malicious', '위험'],
    responses: [
      '분석 결과 4단계:\n🟢 CLEAN - 안전\n🟡 SUSPICIOUS - 주의 필요\n🟠 HIGH_RISK - 고위험\n🔴 MALICIOUS - 악성코드 확실\n\nMALICIOUS가 나오면 즉시 파일을 열지 마세요!',
      '위험도 설명:\n• CLEAN: 악성코드 없음\n• SUSPICIOUS: 의심스러운 요소 있음\n• HIGH_RISK: 고위험 요소 발견\n• MALICIOUS: 악성코드 확정\n\nHIGH_RISK 이상이면 신고하세요!'
    ]
  },
  {
    keywords: ['시간', '얼마나', '빨리', '속도', '느려', '빠르', '로딩'],
    responses: [
      '일반적으로 파일 1개당 10-30초 소요됩니다. 파일 크기와 복잡도에 따라 달라집니다.',
      '대부분의 파일은 20초 내외에 분석 완료됩니다. 100MB 이상 큰 파일은 조금 더 걸릴 수 있어요.',
      '분석 속도는 파일 크기와 내부 구조 복잡도에 따라 달라집니다. 잠시만 기다려주세요!'
    ]
  },
  {
    keywords: ['정확', '정밀', '신뢰', '믿을', '정확도', '오탐', '미탐', 'false'],
    responses: [
      'HWPShield는 다중 검사 엔진과 행위 분석을 사용하여 높은 정확도를 제공합니다.\n\n다만 모든 보안 도구처럼 100% 완벽하지는 않을 수 있습니다. 의심스러운 경우 VirusTotal에서 추가 검사를 권장합니다.',
      '저희는 한국형 악성코드에 특화되어 있어 일반 백신보다 높은 검출률을 자랑합니다. 오탐이 의심되시면 보안팀에 문의하세요.'
    ]
  },

  // === 오류/문제 해결 ===
  {
    keywords: ['오류', '에러', '안돼', '실패', '오류', '문제', '에러', '동작', '작동', '안됨', '뭐야', '왜', '오류'],
    responses: [
      '오류가 발생했나요? 다음을 확인해주세요:\n\n1️⃣ 백엔드 서버 실행 확인\n   → python simple_server.py\n\n2️⃣ 파일 크기 확인 (최대 100MB)\n\n3️⃣ HWP/OLE 파일 형식 확인\n\n4️⃣ 브라우저 콘솔(F12) 오류 확인',
      '문제가 있으신가요?\n\n• 백엔드 서버가 켜져 있나요? (port 8000)\n• 프론트엔드 서버는 켜져 있나요? (npm run dev)\n• 파일이 .hwp 또는 .hwpx인가요?',
      '에러 해결 단계:\n1. 서버 재시작\n2. 브라우저 새로고침\n3. 다른 파일로 테스트\n4. 로그 확인 (F12)'
    ]
  },
  {
    keywords: ['연결', '서버', 'backend', 'api', '통신', '네트워크', '연결', '접속', '500', '404', '에러'],
    responses: [
      '백엔드 연결 오류입니다:\n\n1. 터미널에서 "python simple_server.py" 실행\n2. 포트 8000이 사용 가능한지 확인\n3. 방화벽 설정 확인\n\n실행 중인 터미널 창을 닫지 않았는지 확인하세요!',
      '서버 연결 문제 발생!\n\n• simple_server.py가 실행 중인지 확인\n• localhost:8000/api/health 접속 테스트\n• WSL/Windows 방화벽 확인'
    ]
  },
  {
    keywords: ['파일', '크기', '용량', '큰', '100mb', '50mb', '제한', '메가', 'gb'],
    responses: [
      '최대 파일 크기는 100MB입니다. 더 큰 파일은 분할 압축 후 검사하세요.',
      '100MB 이상 파일은 지원하지 않습니다. 큰 파일의 경우:\n1. 이미지 압축 후 재시도\n2. 파일 분할\n3. 대용량 전용 보안 도구 사용'
    ]
  },

  // === 악성코드/위협 대응 ===
  {
    keywords: ['악성', '바이러스', 'malware', 'virus', '감염', '위험', '해킹', 'hacked', '침해'],
    responses: [
      '🚨 악성코드가 탐지되면 즉시 실행 중단!\n\n📋 조치 방법:\n1. 파일 절대 열지 마세요\n2. 보안팀에 즉시 신고\n3. KrCERT/CC (118) 신고\n4. 경찰청 사이버수사국 신고\n5. VirusTotal 추가 검사',
      '⚠️ MALICIOUS 파일 발견 시!\n\n• 컴퓨터 끄거나 네트워크 차단\n• 파일 격리(isolation) 요청\n• KrCERT: https://www.krcert.or.kr\n• 신고전화: 118',
      '위험 파일 대응 프로토콜:\n\n1️⃣ 실행 금지\n2️⃣ 네트워크 차단\n3️⃣ 전문가 상담\n4️⃣ 관련 기관 신고\n5️⃣ 시스템 점검'
    ]
  },
  {
    keywords: ['신고', '제보', 'report', '118', 'krcert', '경찰', '수사', '범죄', '고발'],
    responses: [
      '악성코드 신고 방법:\n\n📞 KrCERT/CC: 118\n🌐 https://www.krcert.or.kr\n\n📞 경찰청: 182 (사이버수사국)\n🌐 https://cyberbureau.police.go.kr\n\n📧 기업 보안팀\n🏢 소속 조직 CSIRT',
      '신고가 필요하신가요?\n\n• KrCERT/CC (118) - 국가 사이버안전센터\n• 경찰청 사이버수사국 (182)\n• 개인정보보호위원회\n• 금융감독원 (금융권 사고 시)'
    ]
  },
  {
    keywords: ['eps', '취약점', 'cve', '취약', '버그', '공격', 'exploit', '취약', '보안패치'],
    responses: [
      'EPS 취약점 (CVE-2017-8291)은 한글 문서에서 가장 위험한 공격 벡터입니다.\n\n• 한글 2018 이상 버전 사용 권장\n• EPS 파일 임베드 금지 정책\n• 정기적인 보안패치 적용',
      '한글 문서 주요 취약점:\n\n1. EPS 취약점 (CVE-2017-8291)\n2. OLE 취약점\n3. 매크로 악용\n4. 외부 링크 연결\n\n최신 버전의 한글 SW 사용을 권장합니다.'
    ]
  },
  {
    keywords: ['ole', 'object', '임베드', '내장', '객체', '첨부', 'linked', 'embedded'],
    responses: [
      'OLE (Object Linking and Embedding) 객체는 악성코드 숨기기에 자주 사용됩니다.\n\n주의사항:\n• 의심스러운 OLE 객체 포함 파일 주의\n• 외부 링크 연결된 객체 확인\n• 실행 파일이 숨겨진 경우 확인',
      'OLE 객체 보안:\n\n✓ 정상: 이미지, 차트, 표\n⚠️ 의심: 실행파일, 스크립트, 외부링크\n\nHWPShield는 OLE 객체를 자동 분석합니다.'
    ]
  },

  // === 설치/환경 설정 ===
  {
    keywords: ['설치', '설정', '시작', '처음', '처음', '입문', 'tutorial', '가이드', 'howto'],
    responses: [
      '📥 설치 방법:\n\n1️⃣ Python 3.11+ 설치\n2️⃣ 가상환경: python -m venv venv\n3️⃣ 패키지: pip install -r requirements.txt\n4️⃣ 백엔드: python simple_server.py\n5️⃣ 프론트: npm run dev\n\nDocker 없이 순수 Python!',
      '빠른 시작 가이드:\n\n[백엔드 터미널]\ncd backend\npython -m venv venv\nsource venv/bin/activate  # Windows: venv\\Scripts\\activate\npip install -r requirements.txt\npython simple_server.py\n\n[프론트엔드 터미널 - 새 창에서]\ncd frontend\nnpm install\nnpm run dev'
    ]
  },
  {
    keywords: ['python', 'venv', '가상', '환경', 'requirements', 'pip', '의존', '라이브러리', '모듈'],
    responses: [
      'Python 환경 설정:\n\npython -m venv venv\nsource venv/bin/activate  # Linux/Mac\n# 또는\nvenv\\Scripts\\activate  # Windows\n\n필수 패키지:\n• flask\n• olefile\n• python-magic\n• pillow\n• requests',
      'Python 환경 설정:\n\npython -m venv venv\nsource venv/bin/activate  # Linux/Mac\n# 또는\nvenv\\Scripts\\activate  # Windows\n\n필수 패키지:\n• flask\n• olefile\n• python-magic\n• pillow\n• requests',
      '가상환경 사용법:\n\n1. 생성: python -m venv venv\n2. 활성화: source venv/bin/activate\n3. 설치: pip install -r requirements.txt\n4. 실행: python simple_server.py\n5. 비활성화: deactivate'
    ]
  },
  {
    keywords: ['npm', 'node', 'node.js', '자바스크립트', 'react', 'vite', '프론트', 'frontend', '빌드'],
    responses: [
      '프론트엔드 설정:\n\ncd frontend\nnpm install\nnpm run dev\n\n기술 스택:\n• React + TypeScript\n• Vite (빌드 도구)\n• Tailwind CSS\n• Lucide Icons',
      'Node.js 환경:\n\n• Node.js 18+ 필요\n• npm install로 의존성 설치\n• npm run dev로 개발서버 실행\n• npm run build로 배포 빌드'
    ]
  },

  // === 지원 포맷/호환성 ===
  {
    keywords: ['지원', '포맷', '형식', '확장자', 'hwp', 'hwpx', 'ole', '한글', 'word', 'doc'],
    responses: [
      '📄 지원 형식:\n\n✅ .hwp (한글 97/2002/2007/2010/2014)\n✅ .hwpx (한글 2018+)\n✅ OLE2 기반 문서\n\n❌ MS Word (.doc, .docx)\n❌ PDF 파일\n\n최대 파일 크기: 100MB',
      'HWPShield는 한글 전용 보안 도구입니다.\n\n지원:\n• 한컴오피스 한글\n• Thinkfree Office\n\n미지원:\n• MS Office\n• LibreOffice\n• Google Docs'
    ]
  },
  {
    keywords: ['버전', 'version', '업데이트', '최신', '구버전', '호환', '한글2014', '한글2018', '한글2020'],
    responses: [
      '버전별 지원:\n\n• 한글 97/2002: .hwp (기본 지원)\n• 한글 2007/2010/2014: .hwp (완벽 지원)\n• 한글 2018+: .hwpx (권장 포맷)\n• 한글 2020/2022: .hwpx (최신 기능)',
      '한글 버전별 보안 권장사항:\n\n✅ 2018+: EPS 취약점 패치됨\n⚠️ 2014 이전: EPS 취약점 존재\n⚠️ 2010 이전: 다수 보안 취약점\n\n최신 버전 사용을 강력 권장!'
    ]
  },

  // === 특수 기능 ===
  {
    keywords: ['압축', 'zip', '압축파일', '압축해제', 'password', '암호', '보호', '암호화'],
    responses: [
      '암호화된 HWP 파일:\n\n• 비밀번호가 설정된 파일은 분석 불가\n• 먼저 암호를 해제 후 업로드하세요\n• 암호 분석은 법적 문제가 있어 지원하지 않습니다.',
      '압축 파일 처리:\n\n1. .zip/.7z/.rar로 압축된 HWP 파일은 먼저 압축 해제\n2. 내부 HWP 파일만 추출하여 업로드\n3. 암호화된 압축 파일은 분석 불가'
    ]
  },
  {
    keywords: ['매크로', 'macro', 'script', '스크립트', 'vbscript', 'javascript', '자동화', 'macro'],
    responses: [
      '한글 매크로 보안:\n\n⚠️ 매크로가 포함된 문서는 주의 필요\n⚠️ .hwp 파일 내 Script 스토리지 확인\n⚠️ 의심스러운 매크로는 실행 금지\n\nHWPShield는 Script 스토리지를 자동 분석합니다.',
      '스크립트 탐지 기능:\n\n• Script 스토리지 존재 여부\n• VBScript/JavaScript 코드 분석\n• 의심스러운 함수 호출 탐지\n• 자동 실행 코드 검사'
    ]
  },
  {
    keywords: ['링크', 'url', '주소', '외부', '연결', 'download', '다운로드', 'hyperlink', 'http', 'https'],
    responses: [
      '외부 링크 보안:\n\n⚠️ 문서 내 하이퍼링크 주의\n⚠️ 의심스러운 URL 클릭 금지\n⚠️ 자동 다운로드 링크 확인\n\nHWPShield는 문서 내 모든 URL을 추출하여 보고합니다.',
      'URL 분석 기능:\n\n• 문서 내 모든 링크 추출\n• 의심스러운 도메인 플래그\n• 다운로드 URL 특별 표시\n• http vs https 구분'
    ]
  },

  // === 피드백/문의 ===
  {
    keywords: ['감사', '고마워', 'thanks', 'thank', '좋아', '멋져', '최고', '칭찬', '잘했어'],
    responses: [
      '감사합니다! 😊 HWPShield가 도움이 되었다니 기쁩니다!\n\n더 나은 서비스를 위해 노력하겠습니다. 안전한 하루 되세요! 🛡️',
      '도움이 되었다니 다행입니다!\n\n추가 질문이 있으시면 언제든지 문의해주세요. 문서 보안, HWPShield와 함께!'
    ]
  },
  {
    keywords: ['불만', '별로', '안좋아', '싫어', '버그', '문제', '개선', '건의', '피드백', '투덜', '투달'],
    responses: [
      '불편을 드려 죄송합니다. 😔\n\n개선을 위해 다음 정보를 알려주세요:\n\n1. 어떤 문제가 있으신가요?\n2. 어떤 파일 형식인가요?\n3. 오류 메시지가 있나요?\n\n개발팀에 전달하여 개선하겠습니다!'
    ]
  },
  {
    keywords: ['연락', 'contact', '이메일', '메일', '전화', 'tel', '상담', '대표', '운영', '회사'],
    responses: [
      'HWPShield 연락처:\n\n📧 support@hwpshield.kr\n🐙 GitHub: github.com/hwpshield\n\n기술 지원: 24시간 챗봇\n긴급 문의: 평일 09:00-18:00',
      '문의 방법:\n\n1. 이 챗봇으로 즉시 상담\n2. 이메일: support@hwpshield.kr\n3. GitHub Issues 등록\n\n빠른 시일 내에 답변드리겠습니다!'
    ]
  },

  // === 정보/소개 ===
  {
    keywords: ['뭐야', '소개', '설명', '누구', '무엇', 'what', '소개', '기능', '특징', '장점'],
    responses: [
      'HWPShield는 한글 문서 전용 보안 분석 도구입니다.\n\n🛡️ 주요 기능:\n• 악성코드 탐지\n• OLE 객체 분석\n• 스크립트 검사\n• 외부 링크 추출\n• 위험도 평가\n\n한글 97부터 2022까지 모두 지원!',
      'HWPShield 특징:\n\n✅ 한글 문서 전용 (HWP/HWPX)\n✅ EPS 취약점 탐지\n✅ OLE 분석\n✅ 실시간 분석\n✅ 오픈소스\n✅ 무료 사용'
    ]
  },
  {
    keywords: ['오픈소스', 'github', 'git', '소스', '코드', '개발', 'contribute', '기여', '라이선스'],
    responses: [
      'HWPShield는 오픈소스 프로젝트입니다!\n\n🌟 GitHub: github.com/hwpshield/hwpshield\n\n기술 스택:\n• Python (백엔드)\n• React + TypeScript (프론트)\n• MIT 라이선스\n\nPR 환영합니다!'
    ]
  },

  // === 기타/기본 ===
  {
    keywords: ['도움', 'help', '도와줘', '살려줘', '힘들어', '어떻게', '방법', '가이드', '매뉴얼'],
    responses: [
      '도움이 필요하신가요? 다음 키워드로 질문해보세요:\n\n🔍 "분석" - 파일 검사 방법\n🔧 "설치" - 설치 가이드\n⚠️ "위험" - 악성코드 대응\n🐛 "오류" - 문제 해결\n📋 "지원" - 지원 형식\n📞 "연락" - 문의 방법',
      '무엇을 도와드릴까요?\n\n• 파일 분석이 처음이신가요? → "분석" 입력\n• 설치에 문제가 있나요? → "설치" 입력\n• 악성코드가 발견되었나요? → "위험" 입력\n• 기타 문의 → 자유롭게 질문해주세요!'
    ]
  }
];

// Default fallback responses - multiple variations
const DEFAULT_RESPONSES = [
  '죄송합니다, 정확히 이해하지 못했습니다. 다음 키워드로 질문해주세요:\n\n🔍 "분석" - 파일 검사 방법\n🔧 "설치" - 설치 가이드\n⚠️ "위험" - 악성코드 대응\n🐛 "오류" - 문제 해결\n📋 "지원" - 지원 형식\n📞 "연락" - 문의 방법',
  '질문을 다르게 표현해주시겠어요? 다음 키워드를 참고해주세요:\n\n• 분석, 검사, 스캔\n• 설치, 설정, 시작\n• 위험, 악성, 바이러스\n• 오류, 에러, 문제\n• 지원, 포맷, 형식\n• 연락, 문의, 도움',
  '챗봇이 이해하지 못했습니다. 더 구체적으로 질문해주세요!\n\n예시:\n• "파일 분석 어떻게 해요?"\n• "설치 방법 알려줘"\n• "악성코드 발견했어"\n• "오류가 나요"\n• "어떤 파일 지원해?"',
  '아래 키워드 중 하나를 입력해보세요:\n\n💬 분석 / 검사 / 스캔\n💬 설치 / 설정 / 시작\n💬 위험 / 악성 / 바이러스\n💬 오류 / 에러 / 문제\n💬 지원 / 포맷 / 형식\n💬 연락 / 문의 / 도움'
];

// Function to get random default response
const getDefaultResponse = (): string => {
  return DEFAULT_RESPONSES[Math.floor(Math.random() * DEFAULT_RESPONSES.length)];
};

export function ChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      text: '안녕하세요! HWPShield 고객센터입니다.\n\n파일 분석, 설치 방법, 오류 해결 등을 도와드립니다.',
      sender: 'bot',
      timestamp: new Date()
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const findResponse = (userText: string): string => {
    const lowerText = userText.toLowerCase();
    
    for (const response of CHAT_RESPONSES) {
      for (const keyword of response.keywords) {
        if (lowerText.includes(keyword.toLowerCase())) {
          // Randomly select one response from the array
          const responses = response.responses;
          return responses[Math.floor(Math.random() * responses.length)];
        }
      }
    }
    
    return getDefaultResponse();
  };

  const handleSend = () => {
    if (!inputText.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      text: inputText,
      sender: 'user',
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputText('');
    setIsTyping(true);

    // Simulate bot thinking
    setTimeout(() => {
      const botResponse = findResponse(userMessage.text);
      
      const botMessage: Message = {
        id: (Date.now() + 1).toString(),
        text: botResponse,
        sender: 'bot',
        timestamp: new Date()
      };

      setMessages(prev => [...prev, botMessage]);
      setIsTyping(false);
    }, 500 + Math.random() * 1000);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([{
      id: 'welcome-reset',
      text: '채팅이 초기화되었습니다. 무엇을 도와드릴까요?',
      sender: 'bot',
      timestamp: new Date()
    }]);
  };

  return (
    <>
      {/* Floating Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 p-4 bg-blue-600 hover:bg-blue-700 text-white rounded-full shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-110"
          aria-label="Open chat"
        >
          <MessageCircle className="w-7 h-7" />
        </button>
      )}

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 w-[500px] max-w-[calc(100vw-3rem)] h-[700px] max-h-[calc(100vh-3rem)] bg-white dark:bg-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden border border-gray-200 dark:border-slate-700">
          {/* Header */}
          <div className="bg-blue-600 text-white p-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bot className="w-6 h-6" />
              <div>
                <h3 className="font-semibold">고객센터</h3>
                <p className="text-xs text-blue-100">AI 상담원</p>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                className="p-2 hover:bg-blue-700 rounded-lg transition-colors text-sm"
                title="Clear chat"
              >
                초기화
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-2 hover:bg-blue-700 rounded-lg transition-colors"
                aria-label="Close chat"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-50 dark:bg-slate-900">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.sender === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[85%] p-3 rounded-2xl ${
                    message.sender === 'user'
                      ? 'bg-blue-600 text-white rounded-br-none'
                      : 'bg-white dark:bg-slate-700 text-gray-800 dark:text-gray-100 rounded-bl-none shadow-sm border border-gray-200 dark:border-slate-600'
                  }`}
                >
                  <div className="flex items-start gap-2">
                    {message.sender === 'bot' && (
                      <Bot className="w-4 h-4 mt-1 flex-shrink-0" />
                    )}
                    <div className="whitespace-pre-line text-sm leading-relaxed">
                      {message.text}
                    </div>
                    {message.sender === 'user' && (
                      <User className="w-4 h-4 mt-1 flex-shrink-0" />
                    )}
                  </div>
                  <div className={`text-xs mt-1 ${
                    message.sender === 'user' ? 'text-blue-100' : 'text-gray-400'
                  }`}>
                    {message.timestamp.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
              </div>
            ))}
            
            {isTyping && (
              <div className="flex justify-start">
                <div className="bg-white dark:bg-slate-700 p-3 rounded-2xl rounded-bl-none shadow-sm border border-gray-200 dark:border-slate-600">
                  <div className="flex items-center gap-1">
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="p-4 bg-white dark:bg-slate-800 border-t border-gray-200 dark:border-slate-700">
            <div className="flex gap-2">
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="메시지를 입력하세요..."
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-gray-50 dark:bg-slate-700 text-gray-800 dark:text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={handleSend}
                disabled={!inputText.trim()}
                className="p-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg transition-colors"
                aria-label="Send message"
              >
                <Send className="w-5 h-5" />
              </button>
            </div>
            <p className="text-xs text-gray-400 mt-2 text-center">
              키워드: 분석, 오류, 위험, 설치, 지원, 안녕
            </p>
          </div>
        </div>
      )}
    </>
  );
}
