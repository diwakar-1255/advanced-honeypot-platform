# Deployed Access Information

## Public Deployment IP
52.237.90.251

## Public Honeypot Services

| Service | Public Access |
|---|---|
| HTTP Web Honeypot | http://52.237.90.251 |
| HTTPS Honeypot | https://52.237.90.251 |
| SSH Honeypot | ssh root@52.237.90.251 -p 2222 |
| FTP Honeypot | ftp 52.237.90.251 2121 |

## Private Services

| Service | Exposure |
|---|---|
| FastAPI SOC API | 127.0.0.1:8000 only |
| PostgreSQL | Docker internal only |

## Security Note

Real VM SSH on port 22 is restricted by Azure NSG to a trusted IP only.

Do not expose:
- FastAPI port 8000
- PostgreSQL port 5432
- Real SSH port 22 to Any source
