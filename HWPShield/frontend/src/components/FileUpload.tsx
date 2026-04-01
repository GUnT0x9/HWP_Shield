import { Upload, File, AlertCircle, CheckCircle } from 'lucide-react';
import { formatFileSize } from '../api';

interface FileUploadProps {
  selectedFile: File | null;
  onFileSelect: (file: File | null) => void;
  onAnalyze: () => void;
  isUploading: boolean;
}

export function FileUpload({ selectedFile, onFileSelect, onAnalyze, isUploading }: FileUploadProps) {
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      validateAndSelect(files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      validateAndSelect(files[0]);
    }
  };

  const validateAndSelect = (file: File) => {
    const ext = file.name.toLowerCase();
    if (!ext.endsWith('.hwp') && !ext.endsWith('.hwpx')) {
      alert('.hwp 또는 .hwpx 파일만 업로드 가능합니다.');
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      alert('파일 크기는 100MB를 초과할 수 없습니다.');
      return;
    }
    onFileSelect(file);
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-8 text-center hover:border-blue-500 dark:hover:border-blue-400 transition-colors"
      >
        {!selectedFile ? (
          <>
            <div className="mx-auto w-16 h-16 mb-4 text-gray-400 dark:text-gray-500">
              <Upload className="w-full h-full" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              HWP 파일을 드래그하거나 클릭하여 선택하세요
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
              (.hwp, .hwpx 파일 지원, 최대 100MB)
            </p>
            <label className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 cursor-pointer transition-colors">
              <span>파일 선택</span>
              <input
                type="file"
                accept=".hwp,.hwpx"
                onChange={handleFileInput}
                className="hidden"
              />
            </label>
          </>
        ) : (
          <div className="text-left">
            <div className="flex items-start gap-4 p-4 bg-gray-50 dark:bg-slate-700 rounded-lg">
              <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded">
                <File className="w-8 h-8 text-blue-600 dark:text-blue-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-gray-900 dark:text-white truncate">
                  {selectedFile.name}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  크기: {formatFileSize(selectedFile.size)}
                </p>
                <div className="flex items-center gap-2 mt-2">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  <span className="text-sm text-green-600 dark:text-green-400">
                    유효한 HWP 파일
                  </span>
                </div>
              </div>
              <button
                onClick={() => onFileSelect(null)}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                ×
              </button>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={onAnalyze}
                disabled={isUploading}
                className="flex-1 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                {isUploading ? '업로드 중...' : '분석 시작'}
              </button>
              <button
                onClick={() => onFileSelect(null)}
                disabled={isUploading}
                className="px-4 py-3 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700 disabled:opacity-50"
              >
                다른 파일
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-start gap-2 text-sm text-gray-500 dark:text-gray-400">
        <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <p>
          분석은 정적 분석만 수행하며 파일이 절대 실행되지 않습니다.
          모든 파일은 분석 후 즉시 삭제됩니다.
        </p>
      </div>
    </div>
  );
}
