#!/usr/bin/env python3
"""
Decryption script for Seed Master encrypted data.
This script helps you decrypt your seed phrase by regenerating the encryption passphrase.
"""

import sys
import subprocess
import base64
import os
from grasp_fallback import GraspFallback


def decrypt_seed_phrase(encrypted_file: str, master_passphrase: str, salt: str = "seedmaster"):
    """
    Decrypt a seed phrase from an encrypted file.
    
    Args:
        encrypted_file: Path to the file containing base64 encoded encrypted data
        master_passphrase: Your master passphrase
        salt: Salt used for passphrase generation (default: "seedmaster")
    """
    try:
        # Read the encrypted data
        with open(encrypted_file, 'r') as f:
            encrypted_base64 = f.read().strip()
        
        print(f"Reading encrypted data from: {encrypted_file}")
        print(f"Encrypted data length: {len(encrypted_base64)} characters")
        
        # Regenerate the encryption passphrase using the same keywords
        print(f"\nRegenerating encryption passphrase...")
        keywords = [master_passphrase, salt]  # Same order as the application
        encryption_passphrase = GraspFallback.generate_passphrase(*keywords)
        print(f"Encryption passphrase: {encryption_passphrase[:20]}...")
        
        # Decode base64 and decrypt
        print(f"\nDecrypting data...")
        encrypted_data = base64.b64decode(encrypted_base64)
        
        # Create a temporary file for the encrypted data
        temp_file = "temp_encrypted.gpg"
        with open(temp_file, 'wb') as f:
            f.write(encrypted_data)
        
        try:
            # Decrypt using GPG
            result = subprocess.run([
                'gpg', '--decrypt', '--batch', '--passphrase', encryption_passphrase,
                temp_file
            ], capture_output=True, text=True, check=True)
            
            decrypted_data = result.stdout.strip()
            print(f"\n✅ Decryption successful!")
            print(f"Decrypted seed phrase:")
            print(f"  {decrypted_data}")
            
            # Validate the decrypted data as BIP-39
            from seed_master import BIP39Validator
            validator = BIP39Validator()
            is_valid, message = validator.validate_seed_phrase(decrypted_data)
            
            if is_valid:
                print(f"\n✅ Valid BIP-39 seed phrase confirmed!")
            else:
                print(f"\n⚠️  Warning: Decrypted data may not be a valid BIP-39 seed phrase")
                print(f"   Validation result: {message}")
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
    except FileNotFoundError:
        print(f"❌ Error: File '{encrypted_file}' not found")
    except subprocess.CalledProcessError as e:
        print(f"❌ Decryption failed: {e.stderr}")
        print("   This could mean:")
        print("   - Wrong master passphrase")
        print("   - Wrong salt")
        print("   - Corrupted encrypted data")
    except Exception as e:
        print(f"❌ Error: {str(e)}")


def main():
    """Main function for command line usage."""
    if len(sys.argv) < 3:
        print("Usage: python decrypt_seed.py <encrypted_file> <master_passphrase> [salt]")
        print("\nExample:")
        print("  python decrypt_seed.py t1.txt 'my-master-passphrase'")
        print("  python decrypt_seed.py t1.txt 'my-master-passphrase' 'custom-salt'")
        sys.exit(1)
    
    encrypted_file = sys.argv[1]
    master_passphrase = sys.argv[2]
    salt = sys.argv[3] if len(sys.argv) > 3 else "seedmaster"
    
    print("Seed Master Decryption Tool")
    print("=" * 50)
    print(f"Encrypted file: {encrypted_file}")
    print(f"Master passphrase: {master_passphrase}")
    print(f"Salt: {salt}")
    print("=" * 50)
    
    decrypt_seed_phrase(encrypted_file, master_passphrase, salt)


if __name__ == "__main__":
    main()
