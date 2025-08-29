# Seed Master - BIP-39 Seed Phrase Encryptor

A secure local GUI application for encrypting BIP-39 seed phrases using GPG symmetric encryption and generating QR codes for secure storage.

## Security Features

- **Local Only**: All processing happens locally on your machine
- **No Storage**: Seed phrases are never stored or transmitted
- **BIP-39 Validation**: Supports all valid BIP-39 word counts (12, 15, 18, 21, 24) and validates checksums
- **GPG Encryption**: Uses industry-standard GPG symmetric encryption
- **Grasp Integration**: Generates encryption passphrases using the bundled grasp tool (XXXL size - 128 characters, requires multiple keywords)
- **Cross-Platform**: Includes grasp binaries for Windows, macOS (Intel/Apple Silicon), and Linux (Intel/ARM)
- **QR Code Output**: Encrypted data is encoded as QR code for easy transfer
- **Base64 Fallback**: Text representation provided in case QR code scanning fails

## Requirements

- Python 3.8+
- GPG installed on your system
- The `grasp` tool is bundled with the application (no separate installation needed)

## Installation

### Standard Installation

1. Clone or download this repository
2. Run the installation script:
   ```bash
   ./install.sh
   ```
3. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
4. Run the application:
   ```bash
   python seed_master.py
   ```

### Raspberry Pi OS Installation

For Raspberry Pi OS (Debian-based), use the specialized installation script:

1. Clone or download this repository
2. Run the Raspberry Pi installation script:
   ```bash
   ./install_pi.sh
   ```
3. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
4. Run the application:
   ```bash
   python seed_master.py
   ```

**Note**: The Raspberry Pi version uses PyQt5 instead of PyQt6 for better compatibility with ARM systems.

### Manual Installation

If you prefer to install manually:

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Ensure GPG is installed on your system:
   - macOS: `brew install gnupg`
   - Ubuntu/Debian: `sudo apt-get install gnupg`
   - Windows: Download from https://gnupg.org/

3. The grasp tool is automatically bundled and will work on supported platforms

## Usage

1. Run the application:
   ```bash
   python seed_master.py
   ```

2. Enter your BIP-39 words in the text area (12, 15, 18, 21, or 24 words)
3. Enter your master passphrase (must contain at least 2 words, use the "Show" checkbox to verify the text)
4. Click "Encrypt Seed Phrase" to generate the encrypted QR code
5. Save the QR code image and base64 text for secure storage

## Decryption

1. Switch to the "Decrypt Seed Phrase" tab
2. Click "Browse" to select your encrypted file
3. Enter your master passphrase (must contain at least 2 words)
4. Click "Decrypt Seed Phrase" to recover your seed phrase
5. Save the decrypted seed phrase if needed

## Security Notes

- **AIR-GAP REQUIRED**: Use this tool on a computer with NO internet connection
- **SECURE STORAGE**: Destroy all temporary files and storage after saving encrypted values
- **MASTER PASSPHRASE**: Never share your master passphrase with anyone
- **ENCRYPTED OUTPUT**: Store the encrypted QR code and base64 text securely
- **MEMORY ONLY**: The application does not save any seed phrases or passphrases
- **ALL CRYPTOGRAPHIC OPERATIONS**: Happen in memory only and are not persisted

## Command Line Tools

### Test the Application
```bash
source venv/bin/activate && python test_seed_master.py
```

### Run Demo
```bash
source venv/bin/activate && python demo.py
```

### Test Fallback Passphrase Generator
```bash
source venv/bin/activate && python grasp_fallback.py
```

### Compare Grasp and Fallback
```bash
source venv/bin/activate && python compare_grasp.py
```

## Warning

This tool handles sensitive cryptographic material. Use at your own risk and ensure you understand the security implications.

**CRITICAL**: This tool should ONLY be used on an air-gapped computer (no internet connection) to prevent any potential data leakage. All temporary files and storage should be destroyed after saving the encrypted values.
