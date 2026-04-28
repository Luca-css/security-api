import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { createHash } from 'crypto';
import { randomUUID } from 'crypto';

import {
  Threat,
  Alert,
  ScanResult,
  BlocklistEntry,
  SecurityStats,
  ApiError,
  ScanRequest,
  BlocklistAddRequest,
  Port,
  Service,
  CVE,
  Severity,
} from './types';

// ─── In-Memory Store ───────────────────────────────────────────────────────────

const threatStore = new Map<string, Threat>();
const alertStore  = new Map<string, Alert>();
const blocklistStore = new Map<string, BlocklistEntry>();

// ─── Seed Data ─────────────────────────────────────────────────────────────────

const seedThreats: Omit<Threat, 'id'>[] = [
  {
    ip: '185.220.101.47',
    type: 'Brute Force',
    severity: 'Critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    details: 'SSH brute force detected — 847 failed login attempts in 60s from Tor exit node',
    resolved: false,
    country: 'NL',
    attackVector: 'Network',
  },
  {
    ip: '45.142.212.100',
    type: 'Port Scan',
    severity: 'High',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    details: 'SYN scan detected on ports 1-65535 — 12,000 packets/s, likely reconnaissance',
    resolved: false,
    country: 'RU',
    attackVector: 'Network',
  },
  {
    ip: '91.240.118.172',
    type: 'SQL Injection',
    severity: 'Critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    details: "SQLi attempt on /api/login — payload: ' OR 1=1--; UNION SELECT * FROM users--",
    resolved: false,
    country: 'UA',
    attackVector: 'Network',
  },
  {
    ip: '192.168.10.55',
    type: 'Lateral Movement',
    severity: 'High',
    timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    details: 'Internal host performing SMB enumeration across /24 subnet via ADMIN$ share',
    resolved: false,
    country: 'INTERNAL',
    attackVector: 'Adjacent',
  },
  {
    ip: '103.35.74.149',
    type: 'DDoS',
    severity: 'Critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    details: 'HTTP flood attack — 95,000 req/s targeting /api/auth endpoint (volumetric)',
    resolved: false,
    country: 'CN',
    attackVector: 'Network',
  },
  {
    ip: '185.100.87.202',
    type: 'Malware C2',
    severity: 'Critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    details: 'Beacon traffic to known Cobalt Strike C2 server — beacon interval 60s, encrypted',
    resolved: false,
    country: 'IR',
    attackVector: 'Network',
  },
  {
    ip: '77.88.55.66',
    type: 'XSS',
    severity: 'Medium',
    timestamp: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    details: 'Reflected XSS attempt via User-Agent header — <script>document.cookie</script>',
    resolved: true,
    country: 'DE',
    attackVector: 'Network',
  },
  {
    ip: '23.129.64.190',
    type: 'Credential Stuffing',
    severity: 'High',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    details: 'Automated credential stuffing — 2,300 unique user/pass combos from leaked DB',
    resolved: false,
    country: 'US',
    attackVector: 'Network',
  },
];

const seedAlerts: Omit<Alert, 'id'>[] = [
  {
    title: 'RDP Exposed to Internet',
    severity: 'Critical',
    source: 'FIREWALL-01',
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    resolved: false,
    description: 'Port 3389 is reachable from 0.0.0.0/0 — immediate remediation required',
    affectedHost: 'WIN-SRV-PROD-02',
  },
  {
    title: 'SSL Certificate Expiring in 7 Days',
    severity: 'High',
    source: 'CERT-MONITOR',
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    resolved: false,
    description: 'api.trustit.com.br certificate expires 2026-05-01 — renew via Let\'s Encrypt',
    affectedHost: 'NGINX-PROD-01',
  },
  {
    title: 'Unpatched CVE-2024-21413 Detected',
    severity: 'Critical',
    source: 'VULN-SCANNER',
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    resolved: false,
    description: 'Microsoft Outlook RCE vulnerability (CVSS 9.8) — 3 hosts unpatched',
    affectedHost: 'MULTIPLE',
  },
  {
    title: 'Admin Account Login from Unknown IP',
    severity: 'High',
    source: 'SIEM-01',
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    resolved: false,
    description: 'admin@trustit.com.br logged in from 201.18.192.10 (BR, Recife) — unusual',
    affectedHost: 'AD-DC-01',
  },
  {
    title: 'Disk Usage Above 90% Threshold',
    severity: 'Medium',
    source: 'NAGIOS',
    timestamp: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    resolved: false,
    description: 'C:\\ drive at 92% on DB-SRV-01 — clear logs or expand volume',
    affectedHost: 'DB-SRV-01',
  },
  {
    title: 'Failed Backup Job',
    severity: 'Medium',
    source: 'VEEAM',
    timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    resolved: true,
    description: 'Backup job VM-PROD-07 failed — insufficient storage on backup target',
    affectedHost: 'VM-PROD-07',
  },
  {
    title: 'Suspicious PowerShell Execution',
    severity: 'High',
    source: 'EDR-CROWDSTRIKE',
    timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    resolved: false,
    description: 'Encoded PowerShell payload detected: -EncodedCommand <base64> via winword.exe',
    affectedHost: 'WKS-LUCAS-01',
  },
];

const seedBlocklist: BlocklistEntry[] = [
  {
    ip: '185.220.101.47',
    reason: 'Tor exit node — SSH brute force',
    addedAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    addedBy: 'auto-response',
    hits: 847,
  },
  {
    ip: '103.35.74.149',
    reason: 'DDoS source — HTTP flood',
    addedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(),
    addedBy: 'lucas.santos@confiancaetecnologia.com.br',
    hits: 95000,
  },
  {
    ip: '91.240.118.172',
    reason: 'SQL Injection attempts',
    addedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    addedBy: 'waf-auto',
    hits: 34,
  },
  {
    ip: '185.100.87.202',
    reason: 'Cobalt Strike C2 beaconing',
    addedAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    addedBy: 'lucas.santos@confiancaetecnologia.com.br',
    hits: 120,
  },
];

// Populate stores
seedThreats.forEach(t => { const id = randomUUID(); threatStore.set(id, { ...t, id }); });
seedAlerts.forEach(a => { const id = randomUUID(); alertStore.set(id, { ...a, id }); });
seedBlocklist.forEach(b => blocklistStore.set(b.ip, b));

// ─── Helpers ───────────────────────────────────────────────────────────────────

const IPv4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPv6_REGEX = /^([\da-fA-F]{0,4}:){2,7}[\da-fA-F]{0,4}$/;

function isValidIP(ip: string): boolean {
  if (IPv4_REGEX.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }
  return IPv6_REGEX.test(ip);
}

function createApiError(statusCode: number, error: string, message: string): ApiError {
  return { error, message, statusCode, timestamp: new Date().toISOString() };
}

function simulateScan(target: string): ScanResult {
  const hash = createHash('md5').update(target).digest('hex');
  const seed = parseInt(hash.substring(0, 8), 16);
  const pseudo = (n: number) => Math.abs(Math.sin(seed + n));

  const commonPorts = [21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5985, 8080];
  const openPorts: Port[] = commonPorts
    .filter((_, i) => pseudo(i) > 0.65)
    .map(number => ({
      number,
      protocol: 'tcp' as const,
      state: 'open' as const,
      banner: getBanner(number),
    }));

  const services: Service[] = openPorts.map(p => ({
    port: p.number,
    name: getServiceName(p.number),
    version: getServiceVersion(p.number, seed),
  }));

  const vulns: CVE[] = [];
  if (openPorts.some(p => p.number === 445))  vulns.push(KNOWN_CVES.eternalblue);
  if (openPorts.some(p => p.number === 3389)) vulns.push(KNOWN_CVES.bluekeep);
  if (openPorts.some(p => p.number === 21))   vulns.push(KNOWN_CVES.ftpAnon);
  if (openPorts.some(p => p.number === 23))   vulns.push(KNOWN_CVES.telnet);

  const riskScore = Math.min(100, openPorts.length * 8 + vulns.length * 15);

  return {
    target,
    openPorts,
    services,
    vulnerabilities: vulns,
    riskScore,
    scannedAt: new Date().toISOString(),
    duration: Math.floor(pseudo(99) * 4500) + 800,
  };
}

function getBanner(port: number): string {
  const banners: Record<number, string> = {
    21: 'ProFTPD 1.3.5e Server',
    22: 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    23: 'Telnetd',
    25: 'Postfix ESMTP',
    80: 'Apache/2.4.56 (Ubuntu)',
    443: 'nginx/1.24.0',
    1433: 'Microsoft SQL Server 2019',
    3306: '8.0.35-MySQL Community Server',
    3389: 'RDP Protocol: CREDSSP',
    5985: 'WinRM/2.0',
    8080: 'Apache Tomcat/10.1.16',
  };
  return banners[port] ?? `Service on port ${port}`;
}

function getServiceName(port: number): string {
  const names: Record<number, string> = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
    443: 'https', 445: 'microsoft-ds', 1433: 'ms-sql-s',
    3306: 'mysql', 3389: 'ms-wbt-server', 5985: 'wsman', 8080: 'http-proxy',
  };
  return names[port] ?? 'unknown';
}

function getServiceVersion(port: number, seed: number): string {
  const v = (Math.abs(Math.sin(seed * port)) * 10).toFixed(1);
  return `${Math.floor(Math.abs(Math.sin(seed)) * 5) + 1}.${v}`;
}

const KNOWN_CVES: Record<string, CVE> = {
  eternalblue: {
    id: 'CVE-2017-0144',
    description: 'EternalBlue — SMBv1 remote code execution (WannaCry/NotPetya)',
    cvssScore: 9.8,
    severity: 'Critical',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
  },
  bluekeep: {
    id: 'CVE-2019-0708',
    description: 'BlueKeep — RDP pre-auth remote code execution, no interaction required',
    cvssScore: 9.8,
    severity: 'Critical',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-0708'],
  },
  ftpAnon: {
    id: 'CVE-1999-0497',
    description: 'Anonymous FTP login enabled — unauthenticated read/write access',
    cvssScore: 6.4,
    severity: 'Medium',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-1999-0497'],
  },
  telnet: {
    id: 'CVE-2011-4862',
    description: 'Telnet transmits credentials in cleartext — trivial MITM interception',
    cvssScore: 9.3,
    severity: 'Critical',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-4862'],
  },
};

// ─── App Setup ─────────────────────────────────────────────────────────────────

const app = express();

app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: createApiError(429, 'TooManyRequests', 'Rate limit exceeded — max 100 requests/minute per IP'),
});
app.use('/api', limiter);

// ─── Routes ────────────────────────────────────────────────────────────────────

// GET /api/threats
app.get('/api/threats', (_req: Request, res: Response) => {
  const threats = Array.from(threatStore.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
  res.json({ count: threats.length, data: threats });
});

// GET /api/alerts
app.get('/api/alerts', (req: Request, res: Response) => {
  const { severity, resolved } = req.query;
  let alerts = Array.from(alertStore.values());

  if (severity) {
    alerts = alerts.filter(a => a.severity.toLowerCase() === String(severity).toLowerCase());
  }
  if (resolved !== undefined) {
    const isResolved = resolved === 'true';
    alerts = alerts.filter(a => a.resolved === isResolved);
  }

  alerts.sort((a, b) => {
    const order: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });

  res.json({ count: alerts.length, data: alerts });
});

// POST /api/scan
app.post('/api/scan', (req: Request, res: Response) => {
  const body = req.body as ScanRequest;

  if (!body || !body.target) {
    const err = createApiError(400, 'BadRequest', 'Field "target" is required');
    return res.status(400).json(err);
  }

  const target = String(body.target).trim();
  if (!isValidIP(target) && !/^[\w.-]+\.[a-zA-Z]{2,}$/.test(target)) {
    const err = createApiError(400, 'InvalidTarget', 'target must be a valid IPv4, IPv6 or hostname');
    return res.status(400).json(err);
  }

  const result = simulateScan(target);
  return res.status(200).json(result);
});

// GET /api/stats
app.get('/api/stats', (_req: Request, res: Response) => {
  const alerts = Array.from(alertStore.values());
  const threats = Array.from(threatStore.values());
  const criticalThreats = threats.filter(t => t.severity === 'Critical' && !t.resolved).length;
  const activeAlerts = alerts.filter(a => !a.resolved).length;
  const blockedIPs = blocklistStore.size;

  const baseScore = 100;
  const penalty = criticalThreats * 15 + activeAlerts * 5 + blockedIPs * 2;
  const securityScore = Math.max(0, Math.min(100, baseScore - penalty));

  const stats: SecurityStats = {
    totalEvents: threats.length + alerts.length,
    activeAlerts,
    monitoredHosts: 42,
    securityScore,
    criticalThreats,
    blockedIPs,
    lastUpdated: new Date().toISOString(),
  };

  res.json(stats);
});

// GET /api/blocklist
app.get('/api/blocklist', (_req: Request, res: Response) => {
  const entries = Array.from(blocklistStore.values()).sort(
    (a, b) => new Date(b.addedAt).getTime() - new Date(a.addedAt).getTime()
  );
  res.json({ count: entries.length, data: entries });
});

// POST /api/blocklist
app.post('/api/blocklist', (req: Request, res: Response) => {
  const body = req.body as BlocklistAddRequest;

  if (!body || !body.ip || !body.reason) {
    const err = createApiError(400, 'BadRequest', 'Fields "ip" and "reason" are required');
    return res.status(400).json(err);
  }

  const ip = String(body.ip).trim();
  if (!isValidIP(ip)) {
    const err = createApiError(400, 'InvalidIP', `"${ip}" is not a valid IPv4 or IPv6 address`);
    return res.status(400).json(err);
  }

  if (blocklistStore.has(ip)) {
    const err = createApiError(409, 'Conflict', `IP ${ip} is already in the blocklist`);
    return res.status(409).json(err);
  }

  const entry: BlocklistEntry = {
    ip,
    reason: String(body.reason).slice(0, 255),
    addedAt: new Date().toISOString(),
    expiresAt: body.expiresAt,
    addedBy: body.addedBy ?? 'api',
    hits: 0,
  };

  blocklistStore.set(ip, entry);
  return res.status(201).json(entry);
});

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// 404
app.use((_req: Request, res: Response) => {
  res.status(404).json(createApiError(404, 'NotFound', 'Endpoint not found'));
});

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[ERROR]', err.message);
  res.status(500).json(createApiError(500, 'InternalServerError', err.message));
});

// ─── Start ─────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3000', 10);
app.listen(PORT, () => {
  console.log(`\n  Security API v1.0 running on http://localhost:${PORT}`);
  console.log(`  Endpoints:`);
  console.log(`    GET  /api/threats`);
  console.log(`    GET  /api/alerts`);
  console.log(`    POST /api/scan       { "target": "192.168.1.1" }`);
  console.log(`    GET  /api/stats`);
  console.log(`    GET  /api/blocklist`);
  console.log(`    POST /api/blocklist  { "ip": "1.2.3.4", "reason": "..." }`);
  console.log(`    GET  /health\n`);
});

export default app;
