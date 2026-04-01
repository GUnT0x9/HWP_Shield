import { Shield, AlertTriangle, AlertCircle, XCircle } from 'lucide-react';
import { RISK_LABELS } from '../types';

interface RiskBadgeProps {
  level: string;
  score: number;
}

export function RiskBadge({ level, score }: RiskBadgeProps) {
  const config = RISK_LABELS[level] || { ko: '알 수 없음', color: 'bg-gray-500' };
  
  const icons = {
    CLEAN: <Shield className="w-6 h-6" />,
    SUSPICIOUS: <AlertCircle className="w-6 h-6" />,
    HIGH_RISK: <AlertTriangle className="w-6 h-6" />,
    MALICIOUS: <XCircle className="w-6 h-6" />,
  };

  const recommendations = {
    CLEAN: '정상 문서로 판단됩니다.',
    SUSPICIOUS: '의심스러운 요소가 발견되었습니다. 출처를 확인하세요.',
    HIGH_RISK: '높은 위험이 탐지되었습니다. 실행하지 말고 보안팀에 문의하세요.',
    MALICIOUS: '악성 코드가 탐지되었습니다. 절대 실행하지 말고 즉시 보안팀에 신고하세요.',
  };

  return (
    <div className={`${config.color} text-white rounded-lg p-4 flex items-center gap-4 min-w-[280px]`}>
      <div className="p-2 bg-white/20 rounded-full">
        {icons[level as keyof typeof icons] || icons.CLEAN}
      </div>
      <div>
        <p className="text-sm opacity-90">위험 등급</p>
        <p className="text-2xl font-bold">{config.ko}</p>
        <p className="text-xs mt-1 opacity-80">{recommendations[level as keyof typeof recommendations]}</p>
      </div>
    </div>
  );
}
