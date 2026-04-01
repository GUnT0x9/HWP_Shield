import { useState } from 'react';
import { ExternalLink, AlertTriangle, Shield, FileText, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';
import { ReportGuidance } from '../types';

interface ReportGuidanceProps {
  guidance: ReportGuidance;
  filename: string;
}

export function ReportGuidancePanel({ guidance, filename }: ReportGuidanceProps) {
  const [expandedCenters, setExpandedCenters] = useState<string[]>([]);
  const [copiedTemplate, setCopiedTemplate] = useState(false);

  const toggleCenter = (id: string) => {
    setExpandedCenters(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleCopyTemplate = async () => {
    try {
      await navigator.clipboard.writeText(guidance.report_template.content);
      setCopiedTemplate(true);
      setTimeout(() => setCopiedTemplate(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-500 text-white';
      case 'MEDIUM':
        return 'bg-yellow-500 text-black';
      default:
        return 'bg-gray-500 text-white';
    }
  };

  const getActionIcon = (action: string) => {
    if (action.includes('분리') || action.includes('절대')) {
      return <AlertTriangle className="w-4 h-4 text-red-500" />;
    }
    return <Shield className="w-4 h-4 text-blue-500" />;
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border-2 border-red-200 dark:border-red-800 overflow-hidden">
      {/* Header */}
      <div className="bg-red-50 dark:bg-red-900/20 p-4 border-b border-red-200 dark:border-red-800">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-100 dark:bg-red-800 rounded-full">
            <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-300" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-red-900 dark:text-red-100">
              🚨 위협정보 신고 안내
            </h3>
            <p className="text-sm text-red-700 dark:text-red-300">
              악성으로 판단된 파일은 반드시 신고해 주세요
            </p>
          </div>
          <span className={`ml-auto px-3 py-1 rounded-full text-sm font-medium ${getPriorityColor(guidance.priority)}`}>
            {guidance.priority} 우선순위
          </span>
        </div>
      </div>

      {/* Immediate Actions */}
      {guidance.immediate_actions.length > 0 && (
        <div className="p-4 border-b border-gray-200 dark:border-slate-700">
          <h4 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4" />
            즉시 조치사항
          </h4>
          <ul className="space-y-2">
            {guidance.immediate_actions.map((action, idx) => (
              <li key={idx} className="flex items-start gap-3 text-sm text-gray-700 dark:text-gray-300">
                {getActionIcon(action)}
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Reporting Centers */}
      <div className="p-4 border-b border-gray-200 dark:border-slate-700">
        <h4 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
          <ExternalLink className="w-4 h-4" />
          신고 가능한 기관
        </h4>
        <div className="space-y-2">
          {guidance.reporting_centers.map((center) => {
            const isExpanded = expandedCenters.includes(center.id);
            return (
              <div
                key={center.id}
                className="border border-gray-200 dark:border-slate-600 rounded-lg overflow-hidden"
              >
                <button
                  onClick={() => toggleCenter(center.id)}
                  className="w-full flex items-center justify-between p-3 bg-gray-50 dark:bg-slate-700 hover:bg-gray-100 dark:hover:bg-slate-600"
                >
                  <div className="flex items-center gap-3">
                    <span className="font-medium text-gray-900 dark:text-white">{center.name}</span>
                    {center.requires_account && (
                      <span className="text-xs px-2 py-0.5 bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 rounded">
                        회원가입 필요
                      </span>
                    )}
                  </div>
                  {isExpanded ? (
                    <ChevronUp className="w-4 h-4 text-gray-500" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-500" />
                  )}
                </button>
                {isExpanded && (
                  <div className="p-3 bg-white dark:bg-slate-800">
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                      {center.description}
                    </p>
                    <a
                      href={center.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400"
                    >
                      <ExternalLink className="w-4 h-4" />
                      신고 페이지로 이동
                    </a>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Report Template */}
      <div className="p-4">
        <h4 className="font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          신고 템플릿
        </h4>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
          아래 내용을 복사하여 신고 시 첨부하세요
        </p>
        <div className="relative">
          <pre className="bg-gray-100 dark:bg-slate-900 p-3 rounded-lg text-xs text-gray-700 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap">
            {guidance.report_template.content}
          </pre>
          <button
            onClick={handleCopyTemplate}
            className="absolute top-2 right-2 p-2 bg-white dark:bg-slate-700 rounded hover:bg-gray-100 dark:hover:bg-slate-600"
            title="복사"
          >
            {copiedTemplate ? (
              <Check className="w-4 h-4 text-green-500" />
            ) : (
              <Copy className="w-4 h-4 text-gray-500" />
            )}
          </button>
        </div>
      </div>

      {/* Disclaimer */}
      <div className="px-4 pb-4">
        <p className="text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-slate-700 p-2 rounded">
          ℹ️ {guidance.disclaimer}
        </p>
      </div>
    </div>
  );
}
