#!/bin/bash

# Script to run OpenAI client with mkcert certificates
# This sets the SSL environment variables to use our combined CA bundle

echo "🔐 Running OpenAI client with mkcert certificates..."

# Get the system's default CA bundle location
DEFAULT_CA_BUNDLE=$(python3 -c "import ssl; print(ssl.get_default_verify_paths().cafile)")
MKCERT_CA="/Users/richardhightower/Library/Application Support/mkcert/rootCA.pem"

# Create combined CA bundle if it doesn't exist
if [ ! -f "./certificates/ca-bundle.pem" ]; then
    echo "📋 Creating combined CA bundle..."
    echo "   Using system CA bundle: $DEFAULT_CA_BUNDLE"
    echo "   Using mkcert CA: $MKCERT_CA"
    
    # Check if mkcert CA exists
    if [ ! -f "$MKCERT_CA" ]; then
        echo "❌ mkcert CA not found. Please run: mkcert -install"
        exit 1
    fi
    
    # Create certificates directory if it doesn't exist
    mkdir -p ./certificates
    
    # Combine system CA bundle with mkcert CA
    cat "$DEFAULT_CA_BUNDLE" > ./certificates/ca-bundle.pem
    echo "" >> ./certificates/ca-bundle.pem
    echo "# mkcert CA" >> ./certificates/ca-bundle.pem
    cat "$MKCERT_CA" >> ./certificates/ca-bundle.pem
    
    echo "✅ Combined CA bundle created at ./certificates/ca-bundle.pem"
fi

# Set SSL environment variables to use our combined bundle
export SSL_CERT_FILE="$(pwd)/certificates/ca-bundle.pem"
export REQUESTS_CA_BUNDLE="$(pwd)/certificates/ca-bundle.pem"
export CURL_CA_BUNDLE="$(pwd)/certificates/ca-bundle.pem"

echo "📋 Using CA bundle: $SSL_CERT_FILE"

# Verify the bundle contains mkcert CA
if grep -q "mkcert" "$SSL_CERT_FILE"; then
    echo "✅ mkcert CA found in bundle"
else
    echo "⚠️  mkcert CA not found in bundle"
fi

# Run the OpenAI client
task run-openai-client