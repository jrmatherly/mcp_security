# SSL/TLS Certificate Configuration Guide

This guide explains how to set up proper SSL certificates for the MCP Security project, replacing self-signed certificates with trusted ones.

## Table of Contents
- [Quick Start](#quick-start)
- [Option 1: mkcert (Recommended for Local Development)](#option-1-mkcert-recommended-for-local-development)
- [Option 2: Trust Existing Self-Signed Certificates](#option-2-trust-existing-self-signed-certificates)
- [Option 3: Let's Encrypt (Production with Real Domain)](#option-3-lets-encrypt-production-with-real-domain)
- [Troubleshooting SSL Issues](#troubleshooting-ssl-issues)
- [Testing Your Setup](#testing-your-setup)

## Quick Start

### Current Issue
When running the OpenAI client with Docker/nginx using HTTPS URLs, you may encounter:
```
httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate
```

### Quick Solutions

**For Local Development (Easiest)**:
```bash
brew install mkcert
task generate-trusted-certs
task docker-restart
task run-openai-client  # Now works with HTTPS!
```

**For Current Setup**:
```bash
task trust-certs  # Adds current self-signed cert to system trust
task docker-restart
```

## Option 1: mkcert (Recommended for Local Development)

`mkcert` is a simple tool that creates locally-trusted certificates. It's perfect for development because:
- Certificates are automatically trusted by your system
- Works with all browsers and applications
- No certificate warnings
- Easy to set up and use

### Installation

**macOS**:
```bash
brew install mkcert
```

**Linux**:
```bash
# Ubuntu/Debian
sudo apt install libnss3-tools
wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64
chmod +x mkcert
sudo mv mkcert /usr/local/bin/
```

### Generate Trusted Certificates

We've created a script that automates the process:

```bash
task generate-trusted-certs
```

Or run the script directly:
```bash
./scripts/generate-local-certs.sh
```

This script will:
1. Install a local Certificate Authority (CA) on your system
2. Generate certificates for localhost, 127.0.0.1, and other local domains
3. Set proper file permissions
4. Make the certificates trusted by your system

### What the Script Does

```bash
#!/bin/bash
# Install local CA
mkcert -install

# Generate certificates for all local domains
cd certificates
mkcert -cert-file server.crt -key-file server.key \
    localhost \
    127.0.0.1 \
    ::1 \
    "*.localhost" \
    "local.dev" \
    "*.local.dev"

# Set proper permissions
chmod 600 server.key
```

## Option 2: Trust Existing Self-Signed Certificates

If you want to keep using your current self-signed certificates, you can add them to your system's trust store.

### Using the Task

```bash
task trust-certs
```

### Manual Process

**macOS**:
```bash
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    certificates/server.crt
```

**Linux**:
```bash
sudo cp certificates/server.crt /usr/local/share/ca-certificates/mcp-local.crt
sudo update-ca-certificates
```

### After Trusting Certificates

1. Restart your browser
2. Restart Docker services: `task docker-restart`
3. Clear browser cache if needed

## Option 3: Let's Encrypt (Production with Real Domain)

For production deployments with a real domain name, Let's Encrypt provides free, trusted SSL certificates.

### Prerequisites

1. A real domain name (e.g., `your-domain.com`)
2. Domain pointing to your server's IP address
3. Ports 80 and 443 accessible from the internet

### Setup Process

1. **Update nginx configuration** with your domain:
   - Edit `nginx/nginx-letsencrypt.conf`
   - Replace `your-domain.com` with your actual domain

2. **Run the initialization script**:
   ```bash
   ./scripts/init-letsencrypt.sh your-domain.com your-email@example.com
   ```

3. **Use the Let's Encrypt Docker Compose**:
   ```bash
   docker-compose -f docker-compose-letsencrypt.yml up -d
   ```

### How It Works

The setup includes:
- **Certbot container**: Handles certificate generation and renewal
- **nginx configuration**: Serves ACME challenges for domain validation
- **Automatic renewal**: Certificates renew every 60-90 days automatically

### Configuration Files

**docker-compose-letsencrypt.yml**: Includes certbot service for certificate management
**nginx/nginx-letsencrypt.conf**: nginx configuration for Let's Encrypt
**scripts/init-letsencrypt.sh**: Initialization script for first-time setup

## Troubleshooting SSL Issues

### Certificate Not Trusted

**Symptoms**:
- Browser shows "Not Secure" warning
- `CERTIFICATE_VERIFY_FAILED` errors in applications

**Solutions**:
1. Use mkcert for local development
2. Add certificate to system trust store
3. Check certificate is valid: `openssl x509 -in certificates/server.crt -text -noout`

### Wrong Certificate Domain

**Symptoms**:
- Certificate is for different domain than you're accessing

**Solutions**:
1. Regenerate certificate with correct domains
2. Access service using the domain in the certificate
3. Add domain to `/etc/hosts` if needed

### Certificate Expired

**Symptoms**:
- `Certificate has expired` errors

**Solutions**:
1. Regenerate certificates: `task generate-certs` or `task generate-trusted-certs`
2. For Let's Encrypt: Check certbot logs

## Testing Your Setup

### Test HTTPS Endpoints

After setting up certificates, test your endpoints:

```bash
# Test OAuth server
curl https://localhost:8443/

# Test with OpenAI client
task run-openai-client

# Check certificate details
openssl s_client -connect localhost:8443 -servername localhost
```

### Environment Configuration

Ensure your `.env` file has the correct HTTPS URLs:

```bash
# Docker/HTTPS Configuration
OAUTH_TOKEN_URL=https://localhost:8443/token
MCP_SERVER_URL=https://localhost:8001/mcp
OAUTH_ISSUER_URL=https://localhost:8443
TLS_CA_CERT_PATH=  # Leave empty to use system trust
```

### Verify Certificate Trust

**macOS**:
```bash
security find-certificate -p -c "localhost" | openssl x509 -text
```

**Linux**:
```bash
ls -la /usr/local/share/ca-certificates/
update-ca-certificates --fresh
```

## HTTP vs HTTPS Access

### HTTPS (via nginx) - Production Mode
- OAuth: `https://localhost:8443`
- MCP: `https://localhost:8001`
- Requires proper SSL certificates or trust configuration

### HTTP (Direct) - Development Mode
- OAuth: `http://localhost:8080`
- MCP: `http://localhost:8000`
- Bypasses nginx, no SSL required
- Good for testing without certificate issues

### Switching Between Modes

To temporarily use HTTP for testing:
```bash
export OAUTH_TOKEN_URL=http://localhost:8080/token
export MCP_SERVER_URL=http://localhost:8000/mcp
task run-openai-client
```

## Summary

1. **For Local Development**: Use mkcert for hassle-free trusted certificates
2. **For Quick Testing**: Use HTTP endpoints to bypass SSL
3. **For Production**: Use Let's Encrypt with a real domain
4. **For Current Setup**: Trust your self-signed certificates

After implementing any of these solutions, your OpenAI client and other HTTPS clients will work without SSL certificate errors.