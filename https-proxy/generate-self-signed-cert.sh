#!/usr/bin/env bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/honeypot.key \
  -out certs/honeypot.crt \
  -subj "/C=IN/ST=Lab/L=Lab/O=Honeypot/OU=SOC/CN=localhost"
echo "Self-signed certificate generated in https-proxy/certs/"
