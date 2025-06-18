#!/bin/bash

# Add self-signed certificate to macOS trust store
# This will make your current certificates trusted locally

echo "🔐 Adding self-signed certificate to system trust store..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "📱 Detected macOS"
    
    # Add certificate to keychain
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certificates/server.crt
    
    echo "✅ Certificate added to macOS Keychain"
    echo "   You may need to restart your applications"
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "🐧 Detected Linux"
    
    # Copy certificate to system store
    sudo cp certificates/server.crt /usr/local/share/ca-certificates/mcp-local.crt
    sudo update-ca-certificates
    
    echo "✅ Certificate added to Linux trust store"
    
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo ""
echo "🔄 You may need to:"
echo "   1. Restart your browser"
echo "   2. Restart Docker services: task docker-restart"
echo "   3. Clear browser cache"