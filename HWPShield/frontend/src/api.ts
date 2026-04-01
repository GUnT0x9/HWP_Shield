import axios, { AxiosError } from 'axios';
import { AnalysisResponse, HealthResponse } from './types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  // Don't set Content-Type manually - axios will set it with boundary for FormData
});

export async function analyzeFile(file: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post<AnalysisResponse>('/analyze', formData);
  return response.data;
}

export async function checkHealth(): Promise<HealthResponse> {
  const response = await api.get<HealthResponse>('/health');
  return response.data;
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function getErrorMessage(error: unknown): string {
  if (error instanceof AxiosError) {
    // Network error - backend not running
    if (!error.response) {
      return '백엔드 서버에 연결할 수 없습니다. (http://localhost:8000) 서버가 실행 중인지 확인하세요.';
    }
    
    const data = error.response?.data;
    if (data?.error?.message) {
      return data.error.message;
    }
    if (error.response?.status === 429) {
      return '요청 제한을 초과했습니다. 1시간 후에 다시 시도하세요.';
    }
    if (error.response?.status === 413) {
      return '파일 크기가 너무 큽니다 (최대 50MB).';
    }
    if (error.response?.status === 403) {
      return '보안 정책에 의해 차단되었습니다.';
    }
    return `서버 오류 (${error.response?.status}): ${error.message}`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return '알 수 없는 오류가 발생했습니다.';
}
