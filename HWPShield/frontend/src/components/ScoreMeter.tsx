import { RISK_LABELS } from '../types';

interface ScoreMeterProps {
  score: number;
  riskLevel: string;
}

export function ScoreMeter({ score, riskLevel }: ScoreMeterProps) {
  const config = RISK_LABELS[riskLevel] || { ko: '알 수 없음', color: 'bg-gray-500' };
  
  // Calculate color based on score
  const getColor = (s: number) => {
    if (s <= 14) return 'bg-green-500';
    if (s <= 34) return 'bg-yellow-500';
    if (s <= 59) return 'bg-orange-500';
    return 'bg-red-600';
  };

  const getGradient = () => {
    if (score <= 14) return 'from-green-500 to-green-600';
    if (score <= 34) return 'from-yellow-500 to-yellow-600';
    if (score <= 59) return 'from-orange-500 to-orange-600';
    return 'from-red-600 to-red-700';
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-gray-900 dark:text-white">위험 점수</h3>
        <span className="text-2xl font-bold text-gray-900 dark:text-white">
          {score} / 100
        </span>
      </div>

      {/* Progress bar with markers */}
      <div className="relative h-4 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden mb-8">
        {/* Progress bar */}
        <div
          className={`h-full bg-gradient-to-r ${getGradient()} transition-all duration-500 relative z-10`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
        
        {/* Threshold markers - positioned absolutely */}
        <div className="absolute top-0 left-0 w-full h-full pointer-events-none">
          <div className="absolute top-0 left-[15%] w-0.5 h-full bg-gray-400/50" />
          <div className="absolute top-0 left-[35%] w-0.5 h-full bg-gray-400/50" />
          <div className="absolute top-0 left-[60%] w-0.5 h-full bg-gray-400/50" />
        </div>
      </div>
      
      {/* Threshold labels */}
      <div className="relative h-6 mb-4">
        <span className="absolute left-0 -translate-x-0 text-xs text-gray-500">0</span>
        <span className="absolute left-[15%] -translate-x-1/2 text-xs text-gray-500">15</span>
        <span className="absolute left-[35%] -translate-x-1/2 text-xs text-gray-500">35</span>
        <span className="absolute left-[60%] -translate-x-1/2 text-xs text-gray-500">60</span>
        <span className="absolute right-0 translate-x-0 text-xs text-gray-500">100</span>
      </div>

      {/* Threshold labels */}
      <div className="flex justify-between mt-4 text-xs">
        <div className="text-center flex-1">
          <div className="w-3 h-3 rounded-full bg-green-500 mx-auto mb-1"></div>
          <span className="text-gray-600 dark:text-gray-400">안전</span>
        </div>
        <div className="text-center flex-1">
          <div className="w-3 h-3 rounded-full bg-yellow-500 mx-auto mb-1"></div>
          <span className="text-gray-600 dark:text-gray-400">주의</span>
        </div>
        <div className="text-center flex-1">
          <div className="w-3 h-3 rounded-full bg-orange-500 mx-auto mb-1"></div>
          <span className="text-gray-600 dark:text-gray-400">위험</span>
        </div>
        <div className="text-center flex-1">
          <div className="w-3 h-3 rounded-full bg-red-600 mx-auto mb-1"></div>
          <span className="text-gray-600 dark:text-gray-400">악성</span>
        </div>
      </div>

      {/* Current level indicator */}
      <div className={`mt-4 p-3 rounded-lg ${config.color} bg-opacity-10 border ${config.color.replace('bg-', 'border-')}`}>
        <p className={`text-sm font-medium ${config.color.replace('bg-', 'text-')}`}>
          현재 등급: {config.ko}
        </p>
      </div>
    </div>
  );
}
