#!/bin/bash

# Seed Master Installation Script for Raspberry Pi OS

echo "Seed Master - BIP-39 Seed Phrase Encryptor (Raspberry Pi)"
echo "=========================================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"

# Install system dependencies for PyQt6
echo ""
echo "📦 Installing system dependencies for PyQt6..."
apt update
apt install -y \
    python3-pyqt6 \
    python3-pip \
    python3-venv \
    gnupg \
    libgl1-mesa-dev \
    libglib2.0-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libatk1.0-dev \
    libgtk-3-dev \
    libx11-dev \
    libxext-dev \
    libxrender-dev \
    libxrandr-dev \
    libxss-dev \
    libxfixes-dev

if [ $? -eq 0 ]; then
    echo "✅ System dependencies installed"
else
    echo "⚠️  Some system dependencies failed to install - PyQt6 may still work"
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

if [ $? -eq 0 ]; then
    echo "✅ Virtual environment created"
else
    echo "❌ Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment and install dependencies
echo ""
echo "Installing Python dependencies in virtual environment..."
source venv/bin/activate
pip install --upgrade pip

# Install remaining dependencies
echo "Installing Python dependencies..."
pip install mnemonic python-gnupg qrcode[pil] Pillow

if [ $? -eq 0 ]; then
    echo "✅ Python dependencies installed successfully"
else
    echo "❌ Failed to install Python dependencies"
    echo ""
    echo "Troubleshooting tips:"
    echo "1. Try: sudo apt install python3-pyqt6"
    echo "2. Try installing dependencies manually: pip install mnemonic python-gnupg qrcode[pil] Pillow"
    exit 1
fi

# Test PyQt6 availability
echo ""
echo "Testing PyQt6 availability..."
python3 -c "import PyQt6; print('✅ PyQt6 is available')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ PyQt6 is working correctly"
else
    echo "❌ PyQt6 is not available"
    echo ""
    echo "Installing PyQt6 via pip as fallback..."
    pip install PyQt6
    
    if [ $? -eq 0 ]; then
        echo "✅ PyQt6 installed via pip successfully"
    else
        echo "❌ Failed to install PyQt6"
        echo ""
        echo "Alternative solutions:"
        echo "1. Try: sudo apt install python3-pyqt6"
        echo "2. Try: pip install PyQt5 (alternative GUI framework)"
        echo "3. Use the command-line version instead"
        exit 1
    fi
fi

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo ""
    echo "⚠️  GPG is not installed. Please install GPG:"
    echo "   sudo apt-get install gnupg"
    echo ""
    echo "The application will not work without GPG installed."
else
    echo "✅ GPG found: $(gpg --version | head -n 1)"
fi

# Test bundled grasp binary
echo ""
echo "Testing bundled grasp binary..."
python grasp_binary.py

# Check if grasp tool is available (as fallback)
if command -v grasp &> /dev/null; then
    echo "✅ System grasp tool found (will be used as fallback)"
else
    echo "ℹ️  No system grasp tool found (bundled binary will be used)"
fi

# Make scripts executable
chmod +x seed_master.py
chmod +x test_seed_master.py
chmod +x grasp_fallback.py
chmod +x grasp_binary.py

echo ""
echo "🎉 Installation completed!"
echo ""
echo "To activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "To run the application:"
echo "   source venv/bin/activate && python seed_master.py"
echo ""
echo "To run tests:"
echo "   source venv/bin/activate && python test_seed_master.py"
echo ""
echo "To test the fallback passphrase generator:"
echo "   source venv/bin/activate && python grasp_fallback.py"
