import { Loader2 } from 'lucide-react';
import { ANALYSIS_STEPS } from '../types';

interface AnalysisProgressProps {
  currentStep: number;
  totalSteps: number;
}

export function AnalysisProgress({ currentStep, totalSteps }: AnalysisProgressProps) {
  const progress = ((currentStep + 1) / totalSteps) * 100;

  return (
    <div className="max-w-2xl mx-auto text-center">
      <div className="flex items-center justify-center gap-3 mb-6">
        <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          분석 진행 중...
        </h2>
      </div>

      {/* Progress Bar */}
      <div className="mb-8">
        <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-600 transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
          {Math.round(progress)}%
        </p>
      </div>

      {/* Steps */}
      <div className="space-y-3">
        {ANALYSIS_STEPS.map((step, index) => {
          const isCompleted = index < currentStep;
          const isCurrent = index === currentStep;
          const isPending = index > currentStep;

          return (
            <div
              key={index}
              className={`flex items-center gap-3 p-3 rounded-lg transition-all ${
                isCompleted
                  ? 'bg-green-50 dark:bg-green-900/20'
                  : isCurrent
                  ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800'
                  : 'bg-gray-50 dark:bg-slate-800'
              }`}
            >
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-sm font-medium ${
                  isCompleted
                    ? 'bg-green-500 text-white'
                    : isCurrent
                    ? 'bg-blue-600 text-white animate-pulse'
                    : 'bg-gray-300 dark:bg-gray-600 text-gray-600 dark:text-gray-400'
                }`}
              >
                {isCompleted ? '✓' : index + 1}
              </div>
              <span
                className={`text-sm ${
                  isCompleted
                    ? 'text-green-700 dark:text-green-400'
                    : isCurrent
                    ? 'text-blue-700 dark:text-blue-400 font-medium'
                    : 'text-gray-500 dark:text-gray-400'
                }`}
              >
                {step}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
