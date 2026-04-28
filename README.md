# Security API

REST API de segurança em TypeScript + Express para monitoramento de ameaças, alertas, scan de alvos e gerenciamento de blocklist.

## Requisitos

- Node.js 18+
- npm 9+

## Instalação e uso

```bash
cd security-api
npm install
npm run dev        # desenvolvimento com hot-reload
npm run build      # compilar TypeScript
npm start          # produção (após build)
```

A API sobe na porta **3000** por padrão. Defina `PORT=XXXX` para alterar.

---

## Endpoints

### GET /api/threats
Lista todas as ameaças detectadas ordenadas por timestamp.

```bash
curl http://localhost:3000/api/threats
```

Resposta:
```json
{
  "count": 8,
  "data": [
    {
      "id": "uuid",
      "ip": "185.220.101.47",
      "type": "Brute Force",
      "severity": "Critical",
      "timestamp": "2026-04-24T...",
      "details": "SSH brute force detected...",
      "resolved": false,
      "country": "NL",
      "attackVector": "Network"
    }
  ]
}
```

---

### GET /api/alerts
Lista alertas ativos. Suporta filtros por query string.

```bash
curl "http://localhost:3000/api/alerts"
curl "http://localhost:3000/api/alerts?severity=Critical"
curl "http://localhost:3000/api/alerts?resolved=false"
curl "http://localhost:3000/api/alerts?severity=High&resolved=false"
```

---

### POST /api/scan
Executa scan simulado de um alvo (IP ou hostname).

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100"}'
```

Resposta:
```json
{
  "target": "192.168.1.100",
  "openPorts": [
    { "number": 22, "protocol": "tcp", "state": "open", "banner": "OpenSSH_8.9p1" },
    { "number": 3389, "protocol": "tcp", "state": "open", "banner": "RDP Protocol" }
  ],
  "services": [...],
  "vulnerabilities": [
    {
      "id": "CVE-2019-0708",
      "description": "BlueKeep — RDP pre-auth RCE",
      "cvssScore": 9.8,
      "severity": "Critical"
    }
  ],
  "riskScore": 85,
  "scannedAt": "2026-04-24T...",
  "duration": 2340
}
```

---

### GET /api/stats
Retorna estatísticas gerais de segurança.

```bash
curl http://localhost:3000/api/stats
```

Resposta:
```json
{
  "totalEvents": 15,
  "activeAlerts": 6,
  "monitoredHosts": 42,
  "securityScore": 25,
  "criticalThreats": 4,
  "blockedIPs": 4,
  "lastUpdated": "2026-04-24T..."
}
```

---

### GET /api/blocklist
Lista todos os IPs bloqueados.

```bash
curl http://localhost:3000/api/blocklist
```

---

### POST /api/blocklist
Adiciona um IP à blocklist. Valida formato IPv4 e IPv6.

```bash
# IPv4
curl -X POST http://localhost:3000/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "reason": "Port scanning activity",
    "addedBy": "lucas.santos@confiancaetecnologia.com.br"
  }'

# IPv6
curl -X POST http://localhost:3000/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "2001:db8::1", "reason": "C2 beaconing"}'
```

Erros possíveis:
- `400 BadRequest` — campos ausentes
- `400 InvalidIP` — formato de IP inválido
- `409 Conflict` — IP já está na blocklist

---

### GET /health
Health check da API.

```bash
curl http://localhost:3000/health
# {"status":"ok","uptime":42.3,"timestamp":"..."}
```

---

## Rate Limiting

- Máximo **100 requisições por minuto** por IP em todos os endpoints `/api/*`
- Headers de controle: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`

## Segurança

- `helmet` — headers HTTP de segurança (CSP, HSTS, X-Frame-Options, etc.)
- `cors` — Cross-Origin Resource Sharing configurável
- Validação de entrada em todos os endpoints POST
- Error handling centralizado com tipagem forte

## Estrutura

```
security-api/
├── src/
│   ├── server.ts   # servidor principal, rotas, middleware
│   └── types.ts    # interfaces TypeScript
├── package.json
├── tsconfig.json
└── README.md
```
