#!/bin/bash
# Generates a self-signed TLS certificate for local development.
# For production, replace cert.pem / key.pem with certs from Let's Encrypt or your CA.

set -e

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

echo "Generating self-signed certificate in $CERT_DIR ..."

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo ""
echo "Done! Files created:"
echo "  Cert : $CERT_DIR/cert.pem"
echo "  Key  : $CERT_DIR/key.pem"
echo ""
echo "Browser will show a security warning for self-signed certs — click 'Advanced' and proceed."
echo "For production, replace these files with real certs (e.g. from Let's Encrypt / certbot)."
