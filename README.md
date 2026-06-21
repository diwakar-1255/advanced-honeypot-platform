# Advanced Multi-Service Honeypot Platform

## Project Title
Advanced Multi-Service Honeypot with Threat Intelligence, Attacker Profiling and SOC Alerting System

## Services
- SSH Honeypot: Cowrie integration planned
- FTP Honeypot: Python pyftpdlib-based starter
- HTTP Honeypot: FastAPI fake admin/login portal
- HTTPS Honeypot: Nginx reverse proxy + FastAPI
- Database: PostgreSQL
- Detection: Rule-based detection engine
- Alerts: Telegram/email placeholders
- Dashboard: Grafana/Wazuh integration planned

## Safe Lab Ports
- SSH: 2222
- FTP: 2121
- HTTP: 8080
- HTTPS: 8443
- API: 8000
- PostgreSQL: 5432

## Quick Start
```bash
cp .env.example .env
docker compose up --build
```

## Test HTTP Honeypot
```bash
curl -X POST http://localhost:8080/login -d "username=admin&password=' OR '1'='1"
curl "http://localhost:8080/../../etc/passwd"
```

## Test FTP Honeypot
```bash
ftp localhost 2121
```

## Notes
Use this only in a controlled lab. Do not store real passwords, real documents, or malware samples in this project.
