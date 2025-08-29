# Raspberry Pi Installation Guide

## Overview

This guide provides solutions for installing Seed Master on Raspberry Pi OS (Debian-based systems).

## Problem

PyQt6 installation fails on Raspberry Pi OS with errors like:
```
sipbuild.pyproject.PyProjectOptionException
error: metadata-generation-failed
```

## Solutions

### Solution 1: Use the Raspberry Pi Install Script (Recommended)

The easiest solution is to use the specialized Raspberry Pi installation script:

```bash
./install_pi.sh
```

This script:
- Installs PyQt5 instead of PyQt6 (better ARM compatibility)
- Installs all necessary system dependencies
- Uses the `requirements_pi.txt` file with PyQt5

### Solution 2: Manual PyQt6 Installation

If you prefer to use PyQt6, install the Qt dependencies first:

```bash
# Update package list
sudo apt update

# Install Qt6 development libraries
sudo apt install -y \
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

# Then run the standard install script
./install.sh
```

### Solution 3: Use System PyQt5

Install PyQt5 from the system package manager:

```bash
# Install system PyQt5 packages
sudo apt install -y \
    python3-pyqt5 \
    python3-pyqt5.qtcore \
    python3-pyqt5.qtgui \
    python3-pyqt5.qtwidgets

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install other dependencies
pip install -r requirements_pi.txt
```

## Testing the Installation

After installation, test that everything works:

```bash
# Activate virtual environment
source venv/bin/activate

# Test the application
python seed_master.py

# Test the bundled grasp binary
python grasp_binary.py

# Run the test suite
python test_seed_master.py
```

## Common Issues

### Issue: "No module named 'PyQt6'"
**Solution**: Use the Raspberry Pi install script (`./install_pi.sh`) which installs PyQt5 instead.

### Issue: "gpg: command not found"
**Solution**: Install GPG:
```bash
sudo apt install gnupg
```

### Issue: "Permission denied" when running scripts
**Solution**: Make scripts executable:
```bash
chmod +x *.py
chmod +x *.sh
```

### Issue: "No such file or directory" for grasp binary
**Solution**: The bundled grasp binary should work automatically. If not, check that the `grasp_binaries/` directory exists and contains the correct platform subdirectory.

## Performance Notes

- PyQt5 may be slightly slower than PyQt6 on Raspberry Pi
- The application should work well on Raspberry Pi 3 and 4
- For headless operation, you may need to set up X11 forwarding or use a virtual display

## Support

If you continue to have issues:
1. Check that you're using Raspberry Pi OS (Debian-based)
2. Ensure you have sufficient disk space (at least 1GB free)
3. Try the Raspberry Pi install script first
4. Check the system logs for any error messages
