import { Shield, AlertTriangle, CheckCircle, XCircle, Clock } from 'lucide-react';
import { AntivirusScan } from '../types';

interface AntivirusResultProps {
  scan: AntivirusScan;
}

export function AntivirusResultPanel({ scan }: AntivirusResultProps) {
  const getOverallStatusIcon = () => {
    switch (scan.overall_result) {
      case 'CLEAN':
        return <CheckCircle className="w-8 h-8 text-green-500" />;
      case 'MALICIOUS':
        return <XCircle className="w-8 h-8 text-red-500" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="w-8 h-8 text-yellow-500" />;
      case 'ERROR':
      case 'NO_SCAN':
        return <XCircle className="w-8 h-8 text-gray-400" />;
      default:
        return <Shield className="w-8 h-8 text-blue-500" />;
    }
  };

  const getOverallStatusColor = () => {
    switch (scan.overall_result) {
      case 'CLEAN':
        return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
      case 'MALICIOUS':
        return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      case 'SUSPICIOUS':
        return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      default:
        return 'bg-gray-50 dark:bg-slate-800 border-gray-200 dark:border-slate-700';
    }
  };

  const getResultIcon = (result: string) => {
    switch (result) {
      case 'CLEAN':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'INFECTED':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'TIMEOUT':
        return <Clock className="w-4 h-4 text-orange-500" />;
      case 'ERROR':
      default:
        return <XCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getResultBadgeClass = (result: string) => {
    switch (result) {
      case 'CLEAN':
        return 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300';
      case 'INFECTED':
        return 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300';
      case 'SUSPICIOUS':
        return 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-300';
      case 'TIMEOUT':
        return 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300';
      default:
        return 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300';
    }
  };

  // Status messages in Korean
  const statusMessages: Record<string, string> = {
    CLEAN: '악성코드 없음',
    MALICIOUS: '악성코드 탐지',
    SUSPICIOUS: '의심스러운 파일',
    ERROR: '검사 오류',
    NO_SCAN: '검사 미실시',
  };

  return (
    <div className={`rounded-lg shadow-sm border overflow-hidden ${getOverallStatusColor()}`}>
      {/* Header */}
      <div className="p-4 border-b border-inherit">
        <div className="flex items-center gap-4">
          {getOverallStatusIcon()}
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              외부 백신 검사 결과
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {scan.engines_available}개 엔진 중 {scan.scanned_engines}개로 검사
            </p>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getResultBadgeClass(scan.overall_result)}`}>
            {statusMessages[scan.overall_result] || scan.overall_result}
          </span>
        </div>
      </div>

      {/* Engine Details */}
      {scan.details && scan.details.length > 0 && (
        <div className="p-4">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            엔진별 결과
          </h4>
          <div className="space-y-2">
            {scan.details.map((engine, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700"
              >
                <div className="flex items-center gap-3">
                  {getResultIcon(engine.result)}
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">
                      {engine.engine}
                    </p>
                    {engine.version && (
                      <p className="text-xs text-gray-500">
                        버전: {engine.version}
                      </p>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getResultBadgeClass(engine.result)}`}>
                    {engine.result}
                  </span>
                  {engine.threat_name && (
                    <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                      탐지: {engine.threat_name}
                    </p>
                  )}
                  {engine.error && (
                    <p className="text-xs text-gray-500 mt-1">
                      오류: {engine.error}
                    </p>
                  )}
                  <p className="text-xs text-gray-400 mt-1">
                    {engine.scan_time_ms}ms
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {scan.engines_available === 0 && (
        <div className="p-4 text-center">
          <p className="text-sm text-gray-500 dark:text-gray-400">
            외부 백신 엔진이 설치되어 있지 않습니다.<br />
            ClamAV 설치 시 자동으로 연동됩니다.
          </p>
        </div>
      )}
    </div>
  );
}
