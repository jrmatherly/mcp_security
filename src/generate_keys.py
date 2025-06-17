"""
Generate RSA key pair for JWT signing and verification.
Creates private key for OAuth server (signing) and public key for MCP server (verification).
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keys():
    """Generate RSA key pair and save to files."""
    
    # Create keys directory if it doesn't exist
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    
    print("🔐 Generating RSA key pair...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save private key
    private_key_path = keys_dir / "private_key.pem"
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    
    # Save public key
    public_key_path = keys_dir / "public_key.pem"
    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    
    # Set appropriate file permissions (readable only by owner)
    os.chmod(private_key_path, 0o600)
    os.chmod(public_key_path, 0o644)
    
    print(f"✅ Private key saved to: {private_key_path}")
    print(f"✅ Public key saved to: {public_key_path}")
    print("🔒 Private key permissions set to 600 (owner read/write only)")
    print("🔓 Public key permissions set to 644 (owner read/write, others read)")
    
    return private_key_path, public_key_path


if __name__ == "__main__":
    try:
        private_path, public_path = generate_rsa_keys()
        print("\n🎉 RSA key pair generation completed successfully!")
        print("\nNext steps:")
        print("1. OAuth server will use private_key.pem to sign JWTs with RS256")
        print("2. MCP server will use public_key.pem to verify JWTs")
        print("3. Run 'task run-oauth' and 'task run-server' to test authentication")
        
    except Exception as e:
        print(f"❌ Error generating keys: {e}")
        exit(1)