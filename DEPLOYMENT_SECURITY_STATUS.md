# Advanced Honeypot Platform - Deployment Security Status

## Public Honeypot Services
- HTTP Web Honeypot: 80
- HTTPS Honeypot: 443
- SSH Honeypot: 2222
- FTP Honeypot: 2121
- FTP Passive Ports: 30000-30009
- Grafana Dashboard: 3000

## Dashboard Access
- Grafana URL: http://52.237.90.251:3000
- Access Control: Grafana username/password authentication
- Note: Grafana is currently public for project demonstration access.

## Private Control Services
- FastAPI Collector: 127.0.0.1:8000 only
- PostgreSQL: Docker internal only

## Azure NSG Rules

### Public
- 80/tcp: Web Honeypot
- 443/tcp: HTTPS Honeypot
- 2121/tcp: FTP Honeypot
- 2222/tcp: SSH Honeypot
- 30000-30009/tcp: FTP Passive Ports
- 3000/tcp: Grafana Dashboard

### Restricted
- 22/tcp: Real VM SSH allowed only from trusted IP

### Not Exposed
- 8000/tcp: FastAPI Collector
- 5432/tcp: PostgreSQL

## Security Controls Implemented
- Real SSH management restricted by Azure NSG
- API removed from public exposure
- PostgreSQL removed from public exposure
- Docker log rotation enabled
- PostgreSQL automatic backup enabled
- Daily PDF SOC report enabled
- MITRE ATT&CK mapping enabled
- Incident correlation enabled
- Threat reputation scoring enabled
- SSH session replay enabled
- Malware/file upload analysis enabled
- Honeytoken/deception asset tracking enabled

## Backup Schedule
- PostgreSQL backup: Daily at 6:30 PM IST
- Daily PDF SOC report: Daily at 7:00 PM IST

## Security Recommendation
Grafana is public for project access. Keep a strong password and do not share credentials. After demo/submission, restrict Grafana to a trusted IP or bind it back to localhost.

## Current Project Status
Deployment is complete, monitored, backed up, and hardened for a public honeypot lab environment.
