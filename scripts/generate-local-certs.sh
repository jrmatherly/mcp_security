#!/bin/bash

# Generate locally-trusted certificates using mkcert
# This is perfect for local development

echo "🔐 Generating locally-trusted SSL certificates..."

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "❌ mkcert is not installed. Please install it first:"
    echo "   macOS: brew install mkcert"
    echo "   Linux: https://github.com/FiloSottile/mkcert#installation"
    exit 1
fi

# Install local CA
echo "📋 Installing local Certificate Authority..."
mkcert -install

# Create certificates directory
mkdir -p certificates

# Generate certificates for all our domains
echo "🔑 Generating certificates for localhost and local IPs..."
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

echo "✅ Certificates generated successfully!"
echo "   Certificate: certificates/server.crt"
echo "   Private Key: certificates/server.key"
echo ""
echo "These certificates are trusted by your local system."
echo "No more SSL warnings in browsers or applications!"