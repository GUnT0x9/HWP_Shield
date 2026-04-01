import { Download, RefreshCw, Shield, AlertTriangle, AlertCircle, XCircle, Bug, Skull, ShieldAlert } from 'lucide-react';
import { AnalysisResponse } from '../types';
import { RiskBadge } from './RiskBadge';
import { ScoreMeter } from './ScoreMeter';
import { ModuleAccordion } from './ModuleAccordion';
import { IocTable } from './IocTable';
import { AntivirusResultPanel } from './AntivirusResult';
import { ReportGuidancePanel } from './ReportGuidance';
import { formatFileSize } from '../api';

interface ResultDashboardProps {
  result: AnalysisResponse;
  onReset: () => void;
}

// Extended type to include threats from enhanced scanner
interface ExtendedAnalysisResponse extends AnalysisResponse {
  threats?: Array<{
    type: string;
    description: string;
    score: number;
    category: string;
    details?: string;
  }>;
  actual_format?: string;
  header_flags?: {
    compressed?: boolean;
    encrypted?: boolean;
    distribution?: boolean;
  };
  analysis_details?: {
    has_eps?: boolean;
    has_macro?: boolean;
    ole_object_count?: number;
    external_link_count?: number;
    [key: string]: any;
  };
}

export function ResultDashboard({ result, onReset }: ResultDashboardProps) {
  const extendedResult = result as ExtendedAnalysisResponse;

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis_${result.file_hash.md5}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Get threat icon based on category
  const getThreatIcon = (category: string) => {
    switch (category.toUpperCase()) {
      case 'CRITICAL':
        return <Skull className="w-5 h-5 text-red-600" />;
      case 'HIGH':
        return <ShieldAlert className="w-5 h-5 text-orange-600" />;
      case 'MEDIUM':
        return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
      default:
        return <Bug className="w-5 h-5 text-blue-600" />;
    }
  };

  // Get threat color based on category
  const getThreatColor = (category: string) => {
    switch (category.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      case 'HIGH':
        return 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
      case 'MEDIUM':
        return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      default:
        return 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with Risk Badge */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-1">
            분석 결과
          </h2>
          <p className="text-gray-600 dark:text-gray-400">
            {result.filename} ({formatFileSize(result.file_size)})
          </p>
          {extendedResult.actual_format && (
            <p className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              형식: {extendedResult.actual_format}
            </p>
          )}
        </div>
        <RiskBadge level={result.overall_risk} score={result.risk_score} />
      </div>

      {/* Score Meter */}
      <ScoreMeter score={result.risk_score} riskLevel={result.overall_risk} />

      {/* Detected Threats Section */}
      {extendedResult.threats && extendedResult.threats.length > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
          <div className="p-4 bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/20 border-b border-gray-200 dark:border-slate-700">
            <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Bug className="w-5 h-5 text-red-600" />
              탐지된 위협 ({extendedResult.threats.length}개)
            </h3>
          </div>
          <div className="p-4 space-y-3">
            {extendedResult.threats.map((threat, index) => (
              <div 
                key={index} 
                className={`p-4 rounded-lg border ${getThreatColor(threat.category)}`}
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5">
                    {getThreatIcon(threat.category)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        threat.category === 'CRITICAL' ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' :
                        threat.category === 'HIGH' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300' :
                        threat.category === 'MEDIUM' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' :
                        'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                      }`}>
                        {threat.category}
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        위협 점수: +{threat.score}
                      </span>
                    </div>
                    <h4 className="font-medium text-gray-900 dark:text-white">
                      {threat.description}
                    </h4>
                    {threat.details && (
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        {threat.details}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* File Info & Analysis Stats - Wide Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* File Info - spans 2 columns */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 p-5">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-500" />
            파일 정보
          </h3>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="p-2 bg-gray-50 dark:bg-slate-700/50 rounded">
              <span className="text-gray-500 dark:text-gray-400 block text-xs mb-1">파일명</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium truncate">{result.filename}</span>
            </div>
            <div className="p-2 bg-gray-50 dark:bg-slate-700/50 rounded">
              <span className="text-gray-500 dark:text-gray-400 block text-xs mb-1">크기</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium">{formatFileSize(result.file_size)}</span>
            </div>
            <div className="p-2 bg-gray-50 dark:bg-slate-700/50 rounded">
              <span className="text-gray-500 dark:text-gray-400 block text-xs mb-1">HWP 버전</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium">{result.hwp_version || '알 수 없음'}</span>
            </div>
            <div className="p-2 bg-gray-50 dark:bg-slate-700/50 rounded">
              <span className="text-gray-500 dark:text-gray-400 block text-xs mb-1">MD5</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium font-mono text-xs truncate">{result.file_hash.md5}</span>
            </div>
          </div>
        </div>

        {/* Analysis Statistics - spans 2 columns with 4 stats */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 p-5">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-blue-500" />
            분석 통계
          </h3>
          <div className="grid grid-cols-4 gap-3 text-sm">
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-center">
              <span className="text-blue-600 dark:text-blue-400 block text-xs mb-1">스트림</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium text-lg">{extendedResult.analysis_details?.ole_object_count || extendedResult.modules?.[0]?.streams_analyzed || 0}</span>
            </div>
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-center">
              <span className="text-blue-600 dark:text-blue-400 block text-xs mb-1">패턴</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium text-lg">{extendedResult.modules?.[0]?.patterns_checked || 0}</span>
            </div>
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-center">
              <span className="text-blue-600 dark:text-blue-400 block text-xs mb-1">문자열</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium text-lg">{result.raw_strings_sample?.length || 0}</span>
            </div>
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-center">
              <span className="text-blue-600 dark:text-blue-400 block text-xs mb-1">링크</span>
              <span className="text-gray-900 dark:text-gray-200 font-medium text-lg">{extendedResult.analysis_details?.external_link_count || 0}</span>
            </div>
            {result.file_info?.entropy !== undefined && (
              <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded col-span-4">
                <div className="flex items-center gap-3">
                  <span className="text-blue-600 dark:text-blue-400 text-xs whitespace-nowrap">엔트로피</span>
                  <span className="text-gray-900 dark:text-gray-200 font-medium">{result.file_info.entropy.toFixed(2)}</span>
                  <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${result.file_info.entropy > 7 ? 'bg-red-500' : result.file_info.entropy > 5 ? 'bg-yellow-500' : 'bg-green-500'}`}
                      style={{ width: `${(result.file_info.entropy / 8) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Antivirus Scan Result */}
      {result.antivirus_scan && (
        <AntivirusResultPanel scan={result.antivirus_scan} />
      )}

      {/* Module Results */}
      <ModuleAccordion modules={result.modules} />

      {/* IOCs */}
      {result.iocs && result.iocs.length > 0 && (
        <IocTable iocs={result.iocs} />
      )}

      {/* Report Guidance - for suspicious/malicious files */}
      {result.report_guidance && (
        <ReportGuidancePanel 
          guidance={result.report_guidance} 
          filename={result.filename} 
        />
      )}

      {/* Raw Strings */}
      {result.raw_strings_sample && result.raw_strings_sample.length > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
          <details className="group">
            <summary className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700">
              <span className="font-semibold text-gray-900 dark:text-white">
                원본 추출 문자열 ({result.raw_strings_sample.length}개)
              </span>
              <span className="text-gray-500 group-open:rotate-180 transition-transform">▼</span>
            </summary>
            <div className="border-t border-gray-200 dark:border-slate-700 p-4">
              <div className="bg-gray-100 dark:bg-slate-900 rounded p-3 max-h-64 overflow-y-auto">
                <ul className="space-y-1 text-sm font-mono">
                  {result.raw_strings_sample.map((str, idx) => (
                    <li key={idx} className="text-gray-700 dark:text-gray-300 break-all">
                      {str}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </details>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleDownloadJSON}
          className="flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-600"
        >
          <Download className="w-4 h-4" />
          JSON 다운로드
        </button>
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <RefreshCw className="w-4 h-4" />
          새 파일 분석
        </button>
      </div>

      {/* Timestamp */}
      <p className="text-xs text-gray-400 dark:text-gray-500 text-right">
        분석 시간: {new Date(result.analysis_timestamp).toLocaleString('ko-KR')}
      </p>
    </div>
  );
}
