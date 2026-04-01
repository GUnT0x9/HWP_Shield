import { useState, useCallback } from 'react';
import { ShieldCheck, FileSearch } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { AnalysisProgress } from './components/AnalysisProgress';
import { ResultDashboard } from './components/ResultDashboard';
import { ChatWidget } from './components/ChatWidget';
import { analyzeFile, getErrorMessage } from './api';
import { AnalysisResponse, AnalysisStatus, ANALYSIS_STEPS } from './types';

function App() {
  const [status, setStatus] = useState<AnalysisStatus>('idle');
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelect = useCallback((file: File | null) => {
    setSelectedFile(file);
    setError(null);
    setResult(null);
    setStatus('idle');
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!selectedFile) return;

    setStatus('uploading');
    setError(null);
    setResult(null);

    try {
      // Simulate analysis steps
      setStatus('analyzing');
      
      for (let i = 0; i < ANALYSIS_STEPS.length; i++) {
        setCurrentStep(i);
        await new Promise(resolve => setTimeout(resolve, 400));
      }

      const response = await analyzeFile(selectedFile);
      setResult(response);
      setStatus('complete');
    } catch (err) {
      setError(getErrorMessage(err));
      setStatus('error');
    } finally {
      setCurrentStep(0);
    }
  }, [selectedFile]);

  const handleReset = useCallback(() => {
    setSelectedFile(null);
    setResult(null);
    setError(null);
    setStatus('idle');
    setCurrentStep(0);
  }, []);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-slate-900">
      {/* Header */}
      <header className="bg-gradient-to-r from-blue-500 to-indigo-600 shadow-md">
        <div className="px-6 py-6 flex items-center justify-between">
          <button 
            onClick={handleReset}
            className="flex items-center gap-3 hover:opacity-90 transition-opacity cursor-pointer"
          >
            <div className="flex items-center justify-center w-10 h-10 bg-white rounded-lg shadow-lg">
              <FileSearch className="w-6 h-6 text-blue-700" />
            </div>
            <div className="text-left">
              <h1 className="text-2xl font-bold text-white">
                HWPShield
              </h1>
              <p className="text-sm text-blue-100">
                한글 문서 악성코드 분석 도구
              </p>
            </div>
          </button>
          <div className="flex items-center gap-2 text-base text-blue-100">
            <ShieldCheck className="w-4 h-4" />
            <span>안전한 분석</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center px-4 py-8 min-h-[calc(100vh-140px)]">
        {/* File Upload Section */}
        {status === 'idle' || status === 'uploading' ? (
          <div className="w-full max-w-2xl">
            <FileUpload
              selectedFile={selectedFile}
              onFileSelect={handleFileSelect}
              onAnalyze={handleAnalyze}
              isUploading={status === 'uploading'}
            />
          </div>
        ) : null}

        {/* Analysis Progress */}
        {status === 'analyzing' && (
          <AnalysisProgress
            currentStep={currentStep}
            totalSteps={ANALYSIS_STEPS.length}
          />
        )}

        {/* Error Display */}
        {error && (
          <div className="mt-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-red-600 dark:text-red-400">
              {error}
            </p>
            <button
              onClick={handleReset}
              className="mt-3 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
            >
              다시 시도
            </button>
          </div>
        )}

        {/* Results */}
        {result && status === 'complete' && (
          <ResultDashboard
            result={result}
            onReset={handleReset}
          />
        )}
      </main>

      {/* Footer removed */}

      {/* Chat Widget */}
      <ChatWidget />
    </div>
  );
}

export default App;
