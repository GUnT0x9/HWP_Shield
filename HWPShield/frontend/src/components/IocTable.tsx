import { useState } from 'react';
import { Copy, Check, Globe, Server, Folder, Database, FileCode } from 'lucide-react';
import { IOC } from '../types';

interface IocTableProps {
  iocs: IOC[];
}

export function IocTable({ iocs }: IocTableProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = async (value: string, index: number) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleCopyAll = async () => {
    const allIocs = iocs.map(ioc => `${ioc.type}: ${ioc.value}`).join('\n');
    try {
      await navigator.clipboard.writeText(allIocs);
    } catch (err) {
      console.error('Failed to copy all:', err);
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'url':
        return <Globe className="w-4 h-4" />;
      case 'ip':
        return <Server className="w-4 h-4" />;
      case 'path':
        return <Folder className="w-4 h-4" />;
      case 'registry':
        return <Database className="w-4 h-4" />;
      case 'hash':
        return <FileCode className="w-4 h-4" />;
      default:
        return <FileCode className="w-4 h-4" />;
    }
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300';
      case 'medium':
        return 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300';
      default:
        return 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300';
    }
  };

  // Group IOCs by type
  const grouped = iocs.reduce((acc, ioc) => {
    if (!acc[ioc.type]) acc[ioc.type] = [];
    acc[ioc.type].push(ioc);
    return acc;
  }, {} as Record<string, IOC[]>);

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
      <div className="p-4 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
        <h3 className="font-semibold text-gray-900 dark:text-white">
          IOC (Indicators of Compromise) - {iocs.length}개
        </h3>
        <button
          onClick={handleCopyAll}
          className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 flex items-center gap-1"
        >
          <Copy className="w-4 h-4" />
          전체 복사
        </button>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-slate-700">
            <tr>
              <th className="px-4 py-3 text-left font-medium text-gray-700 dark:text-gray-300">유형</th>
              <th className="px-4 py-3 text-left font-medium text-gray-700 dark:text-gray-300">값</th>
              <th className="px-4 py-3 text-center font-medium text-gray-700 dark:text-gray-300">심각도</th>
              <th className="px-4 py-3 text-center font-medium text-gray-700 dark:text-gray-300">복사</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-slate-700">
            {iocs.map((ioc, index) => (
              <tr key={index} className="hover:bg-gray-50 dark:hover:bg-slate-700/50">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                    {getIcon(ioc.type)}
                    <span className="capitalize">{ioc.type}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <code className="text-xs font-mono text-gray-700 dark:text-gray-300 break-all">
                    {ioc.value}
                  </code>
                </td>
                <td className="px-4 py-3 text-center">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityClass(ioc.severity)}`}>
                    {ioc.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-center">
                  <button
                    onClick={() => handleCopy(ioc.value, index)}
                    className="p-1 hover:bg-gray-200 dark:hover:bg-slate-600 rounded transition-colors"
                    title="복사"
                  >
                    {copiedIndex === index ? (
                      <Check className="w-4 h-4 text-green-500" />
                    ) : (
                      <Copy className="w-4 h-4 text-gray-400" />
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
