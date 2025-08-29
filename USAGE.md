# Seed Master Usage Guide

## Quick Start

### Standard Installation

1. **Install the application:**
   ```bash
   ./install.sh
   ```

2. **Run the GUI application:**
   ```bash
   source venv/bin/activate && python seed_master.py
   ```

### Raspberry Pi OS Installation

For Raspberry Pi OS (Debian-based), use the specialized installation script:

1. **Install the application:**
   ```bash
   ./install_pi.sh
   ```

2. **Run the GUI application:**
   ```bash
   source venv/bin/activate && python seed_master.py
   ```

**Note**: The Raspberry Pi version uses PyQt5 instead of PyQt6 for better compatibility with ARM systems.

3. **Enter your BIP-39 words** in the text area (12, 15, 18, 21, or 24 words)
4. **Enter your master passphrase** in the password field (must contain at least 2 words, use the "Show" checkbox to verify)
5. **Click "Encrypt Seed Phrase"** to generate the encrypted output
6. **Save the QR code and base64 text** for secure storage

### Decryption Workflow

1. **Switch to the "Decrypt Seed Phrase" tab**
2. **Click "Browse"** to select your encrypted file
3. **Enter your master passphrase** in the password field (must contain at least 2 words)
4. **Click "Decrypt Seed Phrase"** to recover your seed phrase
5. **Save the decrypted seed phrase** if needed

## Security Features

### Local Processing
- All cryptographic operations happen locally on your machine
- No data is transmitted over the network
- No seed phrases or passphrases are stored

### BIP-39 Validation
- Validates that you have exactly 24 words
- Checks that all words are valid BIP-39 words
- Verifies the checksum to ensure the seed phrase is valid

### Encryption
- Uses GPG symmetric encryption for industry-standard security
- Generates encryption passphrase using the grasp tool (XXXL size - 128 characters, requires multiple keywords)
- Fallback calls the actual grasp command for 100% compatibility
- Creates deterministic passphrases from your master passphrase

### Output Formats
- **QR Code**: Easy to scan and transfer
- **Base64 Text**: Fallback option if QR code scanning fails
- Both contain the same encrypted data

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

## Decryption

### Using the GUI
1. Switch to the "Decrypt Seed Phrase" tab
2. Browse and select your encrypted file
3. Enter your master passphrase
4. Click "Decrypt Seed Phrase"

### Using the Command Line Script
```bash
python decrypt_seed.py <encrypted_file> "<master_passphrase>"
```

Example:
```bash
python decrypt_seed.py my_encrypted_seed.txt "my secret passphrase"
```

### Manual GPG Decryption

If you want to decrypt manually using GPG directly:

1. **Get the encryption passphrase** (regenerate it using the same keywords):
   ```bash
   grasp -s XXXL <word1> <word2> [<word3> ...]
   ```

2. **Decode and decrypt**:
   ```bash
   cat <encrypted_file> | base64 -d | gpg --decrypt --batch --passphrase "<encryption_passphrase>"
   ```

Example:
```bash
# First, regenerate the encryption passphrase
grasp -s XXXL one two three

# Store the passphrase in a variable to avoid shell escaping issues
PASSPHRASE=$(grasp -s XXXL one two three)

# Then decrypt using the variable
cat t1.txt | base64 -d | gpg --decrypt --batch --passphrase "$PASSPHRASE"
```

## Troubleshooting

### GPG Not Found
Install GPG on your system:
- **macOS**: `brew install gnupg`
- **Ubuntu/Debian**: `sudo apt-get install gnupg`
- **Windows**: Download from https://gnupg.org/

### Grasp Tool Not Found
The application includes bundled grasp binaries for all supported platforms. If the bundled binary doesn't work, it will fall back to using a system-installed grasp tool if available.

### Invalid Seed Phrase
- Ensure you have 12, 15, 18, 21, or 24 words
- Check that all words are valid BIP-39 words
- Verify the checksum is correct

## File Structure

```
seedMaster/
├── seed_master.py          # Main GUI application
├── grasp_binary.py         # Platform detection and binary selection
├── grasp_binaries/         # Bundled grasp binaries for all platforms
├── grasp_fallback.py       # Fallback passphrase generator
├── test_seed_master.py     # Test suite
├── demo.py                 # Demo script
├── requirements.txt        # Python dependencies
├── install.sh             # Installation script
├── README.md              # Project documentation
├── USAGE.md               # This usage guide
└── .gitignore             # Git ignore rules
```

## Security Best Practices

1. **AIR-GAP YOUR COMPUTER** - Disconnect from the internet before using this tool
2. **Use a strong master passphrase** - this is your only protection
3. **Store the encrypted output securely** - treat it like your seed phrase
4. **DESTROY TEMPORARY FILES** - Delete all temporary files after saving encrypted values
5. **Test the decryption process** before relying on it
6. **Keep backups** of your encrypted data
7. **Never share your master passphrase** with anyone
8. **SECURE STORAGE** - Use encrypted storage for the encrypted output files

## Warning

This tool handles sensitive cryptographic material. Use at your own risk and ensure you understand the security implications. The developers are not responsible for any loss of funds or data.

**CRITICAL SECURITY REQUIREMENTS**:
- Use ONLY on an air-gapped computer (no internet connection)
- Destroy all temporary files and storage after saving encrypted values
- Store encrypted output in secure, encrypted storage
- Never share your master passphrase with anyone
