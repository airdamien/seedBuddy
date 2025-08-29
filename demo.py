#!/usr/bin/env python3
"""
Demo script for Seed Master - shows the complete workflow.
"""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from seed_master import BIP39Validator, GPGEncryptor, GraspPassphraseGenerator, QRCodeGenerator


def demo_workflow():
    """Demonstrate the complete workflow."""
    # Create QApplication for QPixmap support
    app = QApplication(sys.argv)
    
    print("Seed Master Demo")
    print("=" * 50)
    
    # Sample data
    sample_seed_phrase = "friend confirm mobile early diesel hurt swamp orphan good cruise script crisp"
    master_passphrase = "demo master passphrase 123"
    
    print(f"Sample seed phrase: {sample_seed_phrase}")
    print(f"Master passphrase: {master_passphrase}")
    print()
    
    # Step 1: Validate BIP-39 seed phrase
    print("Step 1: Validating BIP-39 seed phrase...")
    validator = BIP39Validator()
    is_valid, message = validator.validate_seed_phrase(sample_seed_phrase)
    
    if is_valid:
        print(f"✅ {message}")
    else:
        print(f"❌ {message}")
        return
    
    # Step 2: Generate encryption passphrase
    print("\nStep 2: Generating encryption passphrase...")
    try:
        generator = GraspPassphraseGenerator()
        encryption_passphrase = generator.generate_passphrase(master_passphrase)
        print(f"✅ Generated passphrase: {encryption_passphrase[:20]}...")
    except Exception as e:
        print(f"❌ Passphrase generation failed: {e}")
        return
    
    # Step 3: Encrypt the seed phrase
    print("\nStep 3: Encrypting seed phrase with GPG...")
    try:
        encryptor = GPGEncryptor()
        encrypted_data = encryptor.encrypt_symmetric(sample_seed_phrase, encryption_passphrase)
        print(f"✅ Encrypted data (base64): {encrypted_data[:50]}...")
        print(f"   Length: {len(encrypted_data)} characters")
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return
    
    # Step 4: Generate QR code
    print("\nStep 4: Generating QR code...")
    try:
        qr_gen = QRCodeGenerator()
        qr_pixmap = qr_gen.generate_qr_code(encrypted_data)
        print(f"✅ QR code generated: {qr_pixmap.width()}x{qr_pixmap.height()} pixels")
        
        # Save QR code for demo
        qr_pixmap.save("demo_qr_code.png")
        print("   Saved as: demo_qr_code.png")
        
    except Exception as e:
        print(f"❌ QR code generation failed: {e}")
        return
    
    # Step 5: Save base64 data
    print("\nStep 5: Saving base64 data...")
    try:
        with open("demo_encrypted_data.txt", "w") as f:
            f.write(encrypted_data)
        print("✅ Saved as: demo_encrypted_data.txt")
    except Exception as e:
        print(f"❌ Failed to save base64 data: {e}")
    
    print("\n" + "=" * 50)
    print("Demo completed successfully!")
    print("\nGenerated files:")
    print("  - demo_qr_code.png (QR code image)")
    print("  - demo_encrypted_data.txt (base64 encoded data)")
    print("\nYou can now:")
    print("  1. Scan the QR code with a QR code reader")
    print("  2. Use the base64 text as a fallback")
    print("  3. Decrypt using GPG with the generated passphrase")


if __name__ == "__main__":
    demo_workflow()
