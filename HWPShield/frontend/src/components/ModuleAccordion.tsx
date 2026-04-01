import { useState } from 'react';
import { ChevronDown, CheckCircle, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import { ModuleResult } from '../types';

interface ModuleAccordionProps {
  modules: ModuleResult[];
}

export function ModuleAccordion({ modules }: ModuleAccordionProps) {
  const [openModules, setOpenModules] = useState<string[]>(
    modules.filter(m => m.status !== 'CLEAN').map(m => m.id)
  );

  const toggleModule = (id: string) => {
    setOpenModules(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'CLEAN':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'SUSPICIOUS':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case 'DETECTED':
        return <AlertTriangle className="w-5 h-5 text-red-500" />;
      default:
        return <Info className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusClass = (status: string) => {
    switch (status) {
      case 'CLEAN':
        return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
      case 'SUSPICIOUS':
        return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      case 'DETECTED':
        return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      default:
        return 'bg-gray-50 dark:bg-slate-800 border-gray-200 dark:border-slate-700';
    }
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300';
      case 'high':
        return 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300';
      case 'medium':
        return 'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-300';
      case 'low':
        return 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300';
      default:
        return 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300';
    }
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
      <div className="p-4 border-b border-gray-200 dark:border-slate-700">
        <h3 className="font-semibold text-gray-900 dark:text-white">모듈별 결과</h3>
      </div>
      
      <div className="divide-y divide-gray-200 dark:divide-slate-700">
        {modules.map((module) => {
          const isOpen = openModules.includes(module.id);
          
          return (
            <div key={module.id} className={getStatusClass(module.status)}>
              <button
                onClick={() => toggleModule(module.id)}
                className="w-full flex items-center justify-between p-4 text-left hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
              >
                <div className="flex items-center gap-3">
                  {getStatusIcon(module.status)}
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{module.name}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{module.name_en}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-sm font-medium ${
                    module.score_contribution > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-500 dark:text-gray-400'
                  }`}>
                    {module.score_contribution > 0 ? `+${module.score_contribution}` : '0'}점
                  </span>
                  <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                </div>
              </button>
              
              {isOpen && (
                <div className="px-4 pb-4">
                  <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">{module.details}</p>
                  
                  {module.indicators.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        발견된 지표
                      </p>
                      {module.indicators.map((indicator, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-3 p-3 bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700"
                        >
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityClass(indicator.severity)}`}>
                            {indicator.severity.toUpperCase()}
                          </span>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 dark:text-white">
                              {indicator.type}
                            </p>
                            <p className="text-sm text-gray-600 dark:text-gray-400 break-all">
                              {indicator.value}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
