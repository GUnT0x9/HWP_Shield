// TypeScript types for HWPShield API

export interface FileHash {
  md5: string;
  sha256: string;
}

export interface Indicator {
  type: string;
  value: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export interface ModuleResult {
  id: string;
  name: string;
  name_en: string;
  status: 'CLEAN' | 'SUSPICIOUS' | 'DETECTED';
  score_contribution: number;
  indicators: Indicator[];
  details: string;
}

export interface IOC {
  type: 'url' | 'ip' | 'path' | 'registry' | 'hash';
  value: string;
  severity: string;
}

export interface AntivirusEngineResult {
  engine: string;
  result: 'CLEAN' | 'INFECTED' | 'SUSPICIOUS' | 'ERROR' | 'TIMEOUT';
  threat_name: string | null;
  scan_time_ms: number;
  version: string | null;
  error: string | null;
}

export interface AntivirusScan {
  scanned_engines: number;
  engines_available: number;
  overall_result: 'CLEAN' | 'MALICIOUS' | 'SUSPICIOUS' | 'ERROR' | 'NO_SCAN';
  details: AntivirusEngineResult[];
}

export interface ReportingCenter {
  id: string;
  name: string;
  name_en: string;
  url: string;
  description: string;
  requires_account: boolean;
}

export interface ReportGuidance {
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  immediate_actions: string[];
  reporting_centers: ReportingCenter[];
  report_template: {
    title: string;
    content: string;
  };
  disclaimer: string;
}

export interface AnalysisResponse {
  filename: string;
  file_hash: FileHash;
  file_size: number;
  hwp_version: string | null;
  analysis_timestamp: string;
  overall_risk: 'CLEAN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'MALICIOUS';
  risk_score: number;
  modules: ModuleResult[];
  iocs: IOC[];
  raw_strings_sample: string[];
  antivirus_scan?: AntivirusScan;
  report_guidance?: ReportGuidance;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  version: string;
  uptime: number;
}

export type AnalysisStatus = 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';

export const ANALYSIS_STEPS = [
  '구조 파싱 중...',
  'EPS 스트림 검사...',
  'OLE 개체 검사...',
  '스크립트 분석...',
  'IOC 추출...',
  '외부 백신 검사...',
  '리포트 생성 중...'
];

export const RISK_LABELS: Record<string, { ko: string; color: string }> = {
  CLEAN: { ko: '안전', color: 'bg-green-500' },
  SUSPICIOUS: { ko: '주의', color: 'bg-yellow-500' },
  HIGH_RISK: { ko: '위험', color: 'bg-orange-500' },
  MALICIOUS: { ko: '악성', color: 'bg-red-600' },
};
