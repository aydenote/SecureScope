const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

export type RiskLevel = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
export type SecurityScanType = 'Pc' | 'Website';

export interface SecurityFinding {
  id: number;
  riskLevel: RiskLevel;
  title: string;
  description: string;
  recommendation: string;
}

export interface SecurityCheckResult {
  id: number;
  name: string;
  category: string;
  passed: boolean;
  riskLevel: RiskLevel;
  summary: string;
  findings: SecurityFinding[];
}

export interface SecurityScanSummary {
  id: number;
  scanType: SecurityScanType;
  target: string;
  score: number;
  overallRisk: RiskLevel;
  scannedAt: string;
  checks: SecurityCheckResult[];
}

export interface PublicDemoConfig {
  pcDemoMode: boolean;
  websiteAllowlistEnforced: boolean;
  websiteAllowedHosts: string[];
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const message =
      typeof body === 'object' &&
      body !== null &&
      'message' in body &&
      typeof body.message === 'string'
        ? body.message
        : typeof body === 'object' &&
            body !== null &&
            'detail' in body &&
            typeof body.detail === 'string'
          ? body.detail
        : `API request failed with ${response.status}`;

    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

export function getPublicDemoConfig() {
  return request<PublicDemoConfig>('/api/config');
}

export function getLatestPcScan() {
  return request<SecurityScanSummary>('/api/pc-scans/latest');
}

export function getLatestWebsiteScan() {
  return request<SecurityScanSummary>('/api/website-scans/latest');
}

export function getRecentScans() {
  return request<SecurityScanSummary[]>('/api/scans/recent');
}

export function startPcScan() {
  return request<SecurityScanSummary>('/api/pc-scans', { method: 'POST' });
}

export function startWebsiteScan(url: string) {
  return request<SecurityScanSummary>('/api/website-scans', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export function getWebsiteScan(id: string) {
  return request<SecurityScanSummary>(`/api/website-scans/${id}`);
}
