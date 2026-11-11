import type { AlertService } from '../modules/alerts/alert.service.js';
import type { BlocklistService } from '../modules/blocklist/blocklist.service.js';
import type { ThreatService } from '../modules/threats/threat.service.js';

/**
 * Optional demo data (SEED_DEMO_DATA=true). Inserted only when the tables are empty.
 * IPs are public examples; private/loopback ranges are intentionally not blocked so a
 * local developer does not lock themselves out.
 */
export async function seedDemoData(services: {
  threatService: ThreatService;
  alertService: AlertService;
  blocklistService: BlocklistService;
}): Promise<boolean> {
  const { threatService, alertService, blocklistService } = services;
  const existing = await threatService.list({ limit: 1, offset: 0 });
  if (existing.total > 0) return false;

  const actor = 'seed';
  const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

  const threats = [
    {
      sourceIp: '185.220.101.47',
      type: 'Brute Force',
      severity: 'critical',
      country: 'NL',
      detectedAt: minutesAgo(5),
      description: 'SSH brute force: 847 failed logins in 60s from a Tor exit node',
    },
    {
      sourceIp: '45.142.212.100',
      type: 'Port Scan',
      severity: 'high',
      country: 'RU',
      detectedAt: minutesAgo(12),
      description: 'SYN scan across ports 1-65535, likely reconnaissance',
    },
    {
      sourceIp: '91.240.118.172',
      type: 'SQL Injection',
      severity: 'critical',
      country: 'UA',
      detectedAt: minutesAgo(18),
      description: "SQLi attempt on /login with payload ' OR 1=1--",
    },
    {
      sourceIp: '192.168.10.55',
      type: 'Lateral Movement',
      severity: 'high',
      detectedAt: minutesAgo(35),
      description: 'Internal host enumerating SMB shares across the /24 subnet',
      attackVector: 'adjacent',
    },
    {
      sourceIp: '185.100.87.202',
      type: 'Malware C2',
      severity: 'critical',
      country: 'IR',
      detectedAt: minutesAgo(60),
      description: 'Periodic beacon traffic to a known C2 server',
    },
  ] as const;
  for (const t of threats) {
    await threatService.create({ attackVector: 'network', ...t }, actor);
  }

  const alerts = [
    {
      title: 'RDP exposed to the Internet',
      severity: 'critical',
      source: 'FIREWALL-01',
      affectedHost: 'WIN-SRV-PROD-02',
      description: 'Port 3389 reachable from 0.0.0.0/0',
    },
    {
      title: 'TLS certificate expiring in 7 days',
      severity: 'high',
      source: 'CERT-MONITOR',
      affectedHost: 'NGINX-PROD-01',
    },
    {
      title: 'Suspicious encoded PowerShell execution',
      severity: 'high',
      source: 'EDR',
      affectedHost: 'WKS-01',
      description: 'powershell.exe -EncodedCommand spawned by winword.exe',
    },
    {
      title: 'Disk usage above 90%',
      severity: 'medium',
      source: 'MONITORING',
      affectedHost: 'DB-SRV-01',
    },
  ] as const;
  for (const a of alerts) {
    await alertService.create(a, actor);
  }

  await blocklistService.add(
    { cidr: '185.220.101.0/24', reason: 'Tor exit nodes - SSH brute force' },
    actor,
  );
  await blocklistService.add({ cidr: '91.240.118.172', reason: 'SQL injection attempts' }, actor);
  return true;
}
