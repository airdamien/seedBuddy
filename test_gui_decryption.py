#!/usr/bin/env python3
"""
Test script for GUI decryption functionality.
"""

import sys
import os
import tempfile
import subprocess
import base64

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seed_master import GraspPassphraseGenerator, GPGEncryptor, BIP39Validator

def test_gui_decryption():
    """Test that the decryption process works correctly."""
    print("Testing GUI Decryption Functionality")
    print("=" * 50)
    
    # Test data
    master_passphrase = "one two three"
    seed_phrase = "friend confirm mobile early diesel hurt swamp orphan good cruise script crisp"
    
    print(f"Master passphrase: {master_passphrase}")
    print(f"Seed phrase: {seed_phrase}")
    print()
    
    # Step 1: Encrypt (simulate what the GUI does)
    print("1. Encrypting seed phrase...")
    grasp_gen = GraspPassphraseGenerator()
    encryption_passphrase = grasp_gen.generate_passphrase(master_passphrase)
    print(f"   Generated encryption passphrase: {encryption_passphrase[:20]}...")
    
    encryptor = GPGEncryptor()
    encrypted_data = encryptor.encrypt_symmetric(seed_phrase, encryption_passphrase)
    print(f"   Encrypted data length: {len(encrypted_data)} characters")
    
    # Step 2: Save to temporary file (simulate saving from GUI)
    print("\n2. Saving encrypted data to temporary file...")
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    temp_file.write(encrypted_data)
    temp_file.close()
    print(f"   Saved to: {temp_file.name}")
    
    # Step 3: Decrypt (simulate what the GUI decryption tab does)
    print("\n3. Decrypting using the same process as GUI...")
    
    # Read the encrypted data
    with open(temp_file.name, 'r') as f:
        encrypted_base64 = f.read().strip()
    
    # Regenerate the encryption passphrase (same as GUI)
    encryption_passphrase_2 = grasp_gen.generate_passphrase(master_passphrase)
    print(f"   Regenerated passphrase: {encryption_passphrase_2[:20]}...")
    
    # Verify passphrases match
    if encryption_passphrase == encryption_passphrase_2:
        print("   ✓ Passphrases match")
    else:
        print("   ❌ Passphrases don't match!")
        return False
    
    # Decode base64 and decrypt
    encrypted_data_binary = base64.b64decode(encrypted_base64)
    
    # Create a temporary file for the encrypted data
    temp_gpg_file = "temp_encrypted.gpg"
    with open(temp_gpg_file, 'wb') as f:
        f.write(encrypted_data_binary)
    
    try:
        # Decrypt using GPG (same as GUI)
        result = subprocess.run([
            'gpg', '--decrypt', '--batch', '--passphrase', encryption_passphrase_2,
            temp_gpg_file
        ], capture_output=True, text=True, check=True)
        
        decrypted_data = result.stdout.strip()
        print(f"   Decrypted data: {decrypted_data}")
        
        # Validate the decrypted data as BIP-39
        validator = BIP39Validator()
        is_valid, message = validator.validate_seed_phrase(decrypted_data)
        
        if is_valid:
            print("   ✓ Valid BIP-39 seed phrase confirmed")
        else:
            print(f"   ❌ Invalid BIP-39: {message}")
            return False
        
        # Verify the decrypted data matches the original
        if decrypted_data == seed_phrase:
            print("   ✓ Decrypted data matches original")
        else:
            print("   ❌ Decrypted data doesn't match original!")
            return False
            
    finally:
        # Clean up temporary files
        if os.path.exists(temp_gpg_file):
            os.unlink(temp_gpg_file)
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
    
    print("\n✅ GUI Decryption Test PASSED!")
    return True

if __name__ == "__main__":
    success = test_gui_decryption()
    sys.exit(0 if success else 1)
