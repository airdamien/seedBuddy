#!/usr/bin/env python3
"""
Test script for Seed Master functionality.
"""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from seed_master import BIP39Validator, GPGEncryptor, GraspPassphraseGenerator, QRCodeGenerator


def test_bip39_validation():
    """Test BIP-39 validation."""
    print("Testing BIP-39 validation...")
    
    validator = BIP39Validator()
    
    # Valid 12-word seed phrase
    valid_phrase_12 = "friend confirm mobile early diesel hurt swamp orphan good cruise script crisp"
    
    # Valid 24-word seed phrase
    valid_phrase_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    
    is_valid, message = validator.validate_seed_phrase(valid_phrase_12)
    print(f"Valid 12-word phrase test: {is_valid} - {message}")
    
    is_valid, message = validator.validate_seed_phrase(valid_phrase_24)
    print(f"Valid 24-word phrase test: {is_valid} - {message}")
    
    # Invalid phrase (wrong checksum)
    invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    
    is_valid, message = validator.validate_seed_phrase(invalid_phrase)
    print(f"Invalid phrase test: {is_valid} - {message}")
    
    # Wrong number of words
    short_phrase = "abandon abandon abandon"
    is_valid, message = validator.validate_seed_phrase(short_phrase)
    print(f"Short phrase test: {is_valid} - {message}")
    
    # Invalid word count (13 words)
    invalid_count_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    is_valid, message = validator.validate_seed_phrase(invalid_count_phrase)
    print(f"Invalid count phrase test: {is_valid} - {message}")


def test_passphrase_generation():
    """Test passphrase generation."""
    print("\nTesting passphrase generation...")
    
    try:
        generator = GraspPassphraseGenerator()
        passphrase = generator.generate_passphrase("test master passphrase")
        print(f"Generated passphrase: {passphrase}")
        print(f"Passphrase length: {len(passphrase)}")
        
        # Test error handling for single word
        try:
            generator.generate_passphrase("single")
            print("❌ Should have raised an error for single word")
            assert False, "Should have raised an error"
        except ValueError as e:
            print(f"✓ Correctly rejected single word: {e}")
            
    except Exception as e:
        print(f"Passphrase generation error: {e}")


def test_gpg_encryption():
    """Test GPG encryption."""
    print("\nTesting GPG encryption...")
    
    try:
        encryptor = GPGEncryptor()
        test_data = "test seed phrase data"
        test_passphrase = "test-passphrase"
        
        encrypted = encryptor.encrypt_symmetric(test_data, test_passphrase)
        print(f"Encrypted data length: {len(encrypted)}")
        print(f"First 50 chars: {encrypted[:50]}...")
        
    except Exception as e:
        print(f"GPG encryption error: {e}")


def test_qr_code_generation():
    """Test QR code generation."""
    print("\nTesting QR code generation...")
    
    try:
        generator = QRCodeGenerator()
        test_data = "test-data-for-qr-code"
        
        qr_pixmap = generator.generate_qr_code(test_data)
        print(f"QR code generated successfully")
        print(f"QR code size: {qr_pixmap.width()}x{qr_pixmap.height()}")
        
    except Exception as e:
        print(f"QR code generation error: {e}")


def main():
    """Run all tests."""
    # Create QApplication for QPixmap support
    app = QApplication(sys.argv)
    
    print("Seed Master Test Suite")
    print("=" * 50)
    
    test_bip39_validation()
    test_passphrase_generation()
    test_gpg_encryption()
    test_qr_code_generation()
    
    print("\n" + "=" * 50)
    print("Test suite completed!")


if __name__ == "__main__":
    main()
