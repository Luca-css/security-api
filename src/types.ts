// Security API — Type Definitions
// Interfaces TypeScript para o sistema de segurança

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface Threat {
  id: string;
  ip: string;
  type: string;
  severity: Severity;
  timestamp: string;
  details: string;
  resolved: boolean;
  country?: string;
  attackVector?: string;
}

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  timestamp: string;
  resolved: boolean;
  description?: string;
  affectedHost?: string;
}

export interface Port {
  number: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  banner?: string;
}

export interface Service {
  port: number;
  name: string;
  version?: string;
  product?: string;
}

export interface CVE {
  id: string;
  description: string;
  cvssScore: number;
  severity: Severity;
  references: string[];
}

export interface ScanResult {
  target: string;
  openPorts: Port[];
  services: Service[];
  vulnerabilities: CVE[];
  riskScore: number;
  scannedAt: string;
  duration: number;
}

export interface BlocklistEntry {
  ip: string;
  reason: string;
  addedAt: string;
  expiresAt?: string;
  addedBy?: string;
  hits?: number;
}

export interface SecurityStats {
  totalEvents: number;
  activeAlerts: number;
  monitoredHosts: number;
  securityScore: number;
  criticalThreats: number;
  blockedIPs: number;
  lastUpdated: string;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
  timestamp: string;
}

export interface ScanRequest {
  target: string;
  ports?: number[];
  aggressive?: boolean;
}

export interface BlocklistAddRequest {
  ip: string;
  reason: string;
  expiresAt?: string;
  addedBy?: string;
}
