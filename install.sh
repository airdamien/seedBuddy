#!/bin/bash

# Seed Master Installation Script

echo "Seed Master - BIP-39 Seed Phrase Encryptor"
echo "=========================================="
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

# Detect OS and install Qt dependencies if needed
if [ -f /etc/debian_version ]; then
    echo ""
    echo "📦 Detected Debian-based system (Raspberry Pi OS)"
    echo "Installing Qt dependencies for PyQt6..."
    
    # Update package list
    apt update
    
    # Install Qt development libraries
    apt install -y \
        qt6-base-dev \
        qt6-declarative-dev \
        qt6-tools-dev \
        qt6-tools-dev-tools \
        libgl1-mesa-dev \
        libglib2.0-dev \
        libgirepository1.0-dev \
        libcairo2-dev \
        libpango1.0-dev \
        libatk1.0-dev \
        libgtk-3-dev \
        libx11-dev \
        libxext-dev \
        libxrender-dev \
        libxrandr-dev \
        libxss-dev \
        libxfixes-dev \
        libxcb1-dev \
        libxcb-glx0-dev \
        libxcb-keysyms1-dev \
        libxcb-image0-dev \
        libxcb-shm0-dev \
        libxcb-icccm4-dev \
        libxcb-sync-dev \
        libxcb-xfixes0-dev \
        libxcb-shape0-dev \
        libxcb-randr0-dev \
        libxcb-render-util0-dev \
        libxcb-xinerama0-dev \
        libxcb-xkb-dev \
        libxkbcommon-dev \
        libxkbcommon-x11-dev
    
    if [ $? -eq 0 ]; then
        echo "✅ Qt dependencies installed"
    else
        echo "⚠️  Failed to install some Qt dependencies - PyQt6 may still work"
    fi
elif [ -f /etc/redhat-release ] || [ -f /etc/fedora-release ]; then
    echo ""
    echo "📦 Detected Red Hat-based system"
    echo "Installing Qt dependencies for PyQt6..."
    
    # For Fedora/RHEL/CentOS
    dnf install -y \
        qt6-qtbase-devel \
        qt6-qtdeclarative-devel \
        qt6-qttools-devel \
        mesa-libGL-devel \
        glib2-devel \
        cairo-devel \
        pango-devel \
        atk-devel \
        gtk3-devel \
        libX11-devel \
        libXext-devel \
        libXrender-devel \
        libXrandr-devel \
        libXScrnSaver-devel \
        libXfixes-devel \
        libxcb-devel
    
    if [ $? -eq 0 ]; then
        echo "✅ Qt dependencies installed"
    else
        echo "⚠️  Failed to install some Qt dependencies - PyQt6 may still work"
    fi
else
    echo ""
    echo "📦 Unknown system - Qt dependencies may need manual installation"
    echo "For PyQt6, you may need to install Qt development libraries"
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

# Try to install PyQt6 with pre-built wheels first
echo "Attempting to install PyQt6 with pre-built wheels..."
pip install --only-binary=PyQt6 PyQt6

# If that fails, try building from source
if [ $? -ne 0 ]; then
    echo "Pre-built wheels failed, attempting to build from source..."
    pip install PyQt6
fi

# Install remaining dependencies
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Python dependencies installed successfully"
else
    echo "❌ Failed to install Python dependencies"
    echo ""
    echo "Troubleshooting tips:"
    echo "1. Make sure you have Qt development libraries installed"
    echo "2. On Debian/Ubuntu: sudo apt install qt6-base-dev qt6-declarative-dev"
    echo "3. On Fedora/RHEL: sudo dnf install qt6-qtbase-devel qt6-qtdeclarative-devel"
    echo "4. Try installing PyQt6 separately: pip install PyQt6"
    exit 1
fi

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo ""
    echo "⚠️  GPG is not installed. Please install GPG:"
    echo "   macOS: brew install gnupg"
    echo "   Ubuntu/Debian: sudo apt-get install gnupg"
    echo "   Windows: Download from https://gnupg.org/"
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
