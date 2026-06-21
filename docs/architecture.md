# Architecture Summary

Flow:

Attacker -> SSH/FTP/HTTP/HTTPS Honeypots -> Log Collector -> Normalizer -> Enrichment -> Detection -> Risk Score -> PostgreSQL -> Alerts/Dashboard/Reports

Services:
- SSH: Cowrie
- FTP: pyftpdlib/OpenCanary
- HTTP: FastAPI
- HTTPS: Nginx reverse proxy + FastAPI
