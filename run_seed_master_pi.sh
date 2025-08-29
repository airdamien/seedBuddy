#!/bin/bash

# Seed Master Runner for Raspberry Pi
# This script runs the application using system Python which has PyQt6 installed

echo "Seed Master - BIP-39 Seed Phrase Encryptor (Raspberry Pi)"
echo "=========================================================="
echo ""

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Using virtual environment: $VIRTUAL_ENV"
    echo "Installing packages in virtual environment..."
    PIP_INSTALL_CMD="pip install"
    PYTHON_CMD="python3"
else
    echo "✅ Using system Python (externally managed environment)"
    echo "System packages will be used where available."
    echo "For missing packages, a temporary virtual environment will be created."
    PIP_INSTALL_CMD="pip install"
    PYTHON_CMD="python3"
fi

# Check Python version and path
echo "Python Information:"
echo "Python version: $($PYTHON_CMD --version)"
echo "Python path: $(which $PYTHON_CMD)"
echo ""

# Install system packages if not already installed
echo "Checking and installing system packages..."
SYSTEM_PACKAGES=("python3-mnemonic" "python3-gnupg" "python3-qrencode")

for package in "${SYSTEM_PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii.*$package"; then
        echo "Installing $package..."
        apt-get update && apt-get install -y "$package"
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install $package"
            exit 1
        fi
    else
        echo "✅ $package already installed"
    fi
done

# Check if PyQt6 is available
echo ""
echo "Checking PyQt6 availability..."
$PYTHON_CMD -c "import PyQt6; print('✅ PyQt6 is available')" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ Using PyQt6"
    
    # Check if other dependencies are available
    echo "Checking other dependencies..."
    $PYTHON_CMD -c "import mnemonic, gnupg, qrencode; print('✅ All dependencies available')" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "✅ All dependencies are available"
        
        # Run the application
        echo ""
        echo "Starting Seed Master..."
        $PYTHON_CMD seed_master.py
    else
        echo "⚠️  Some dependencies missing, installing..."
        
        # Create temporary virtual environment if not in one
        if [[ "$VIRTUAL_ENV" == "" ]]; then
            echo "Creating temporary virtual environment..."
            python3 -m venv temp_venv
            source temp_venv/bin/activate
            PIP_INSTALL_CMD="pip install"
            PYTHON_CMD="python3"
        fi
        
        # Install missing dependencies
        echo "Installing missing dependencies..."
        $PYTHON_CMD -m $PIP_INSTALL_CMD mnemonic python-gnupg qrcode[pil] Pillow
        
        if [ $? -eq 0 ]; then
            echo "✅ Dependencies installed successfully"
            
            # Run the application
            echo ""
            echo "Starting Seed Master..."
            $PYTHON_CMD seed_master.py
            
            # Clean up temporary venv
            if [[ "$VIRTUAL_ENV" == *"temp_venv"* ]]; then
                echo ""
                echo "Cleaning up temporary virtual environment..."
                deactivate
                rm -rf temp_venv
            fi
        else
            echo "❌ Failed to install dependencies"
            exit 1
        fi
    fi
else
    echo "❌ PyQt6 not available"
    echo ""
    echo "Trying PyQt5 fallback..."
    
    # Try PyQt5
    $PYTHON_CMD -c "import PyQt5; print('✅ PyQt5 is available')" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "✅ Using PyQt5"
        
        # Check if other dependencies are available
        echo "Checking other dependencies..."
        $PYTHON_CMD -c "import mnemonic, gnupg, qrencode; print('✅ All dependencies available')" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "✅ All dependencies are available"
            
            # Run the PyQt5 version
            echo ""
            echo "Starting Seed Master (PyQt5 version)..."
            $PYTHON_CMD seed_master_pi.py
        else
            echo "⚠️  Some dependencies missing, installing..."
            
            # Create temporary virtual environment if not in one
            if [[ "$VIRTUAL_ENV" == "" ]]; then
                echo "Creating temporary virtual environment..."
                python3 -m venv temp_venv
                source temp_venv/bin/activate
                PIP_INSTALL_CMD="pip install"
                PYTHON_CMD="python3"
            fi
            
            # Install missing dependencies
            $PYTHON_CMD -m $PIP_INSTALL_CMD mnemonic python-gnupg qrcode[pil] Pillow
            
            if [ $? -eq 0 ]; then
                echo "✅ Dependencies installed successfully"
                
                # Run the PyQt5 version
                echo ""
                echo "Starting Seed Master (PyQt5 version)..."
                $PYTHON_CMD seed_master_pi.py
                
                # Clean up temporary venv
                if [[ "$VIRTUAL_ENV" == *"temp_venv"* ]]; then
                    echo ""
                    echo "Cleaning up temporary virtual environment..."
                    deactivate
                    rm -rf temp_venv
                fi
            else
                echo "❌ Failed to install dependencies"
                exit 1
            fi
        fi
    else
        echo "❌ Neither PyQt6 nor PyQt5 is available"
        echo ""
        echo "Diagnostic Information:"
        echo "======================="
        echo "Checking installed packages:"
        dpkg -l | grep -i pyqt
        echo ""
        echo "Checking Python packages:"
        $PYTHON_CMD -c "import sys; print('Python path:'); [print(p) for p in sys.path]"
        echo ""
        echo "Creating temporary virtual environment for pip installation..."
        python3 -m venv temp_venv
        source temp_venv/bin/activate
        PIP_INSTALL_CMD="pip install"
        PYTHON_CMD="python3"
        
        echo "Trying to install PyQt5 (compatible version) via pip:"
        $PYTHON_CMD -m $PIP_INSTALL_CMD "PyQt5==5.15.7"
        
        if [ $? -eq 0 ]; then
            echo "✅ PyQt5 5.15.7 installed via pip successfully"
            echo ""
            echo "Installing other dependencies..."
            $PYTHON_CMD -m $PIP_INSTALL_CMD mnemonic python-gnupg qrcode[pil] Pillow
            
            if [ $? -eq 0 ]; then
                echo "✅ Dependencies installed successfully"
                echo ""
                echo "Starting Seed Master (PyQt5 version)..."
                $PYTHON_CMD seed_master_pi.py
                
                # Clean up
                echo ""
                echo "Cleaning up temporary virtual environment..."
                deactivate
                rm -rf temp_venv
            else
                echo "❌ Failed to install dependencies"
                deactivate
                rm -rf temp_venv
                exit 1
            fi
        else
            echo "❌ Failed to install PyQt5 via pip"
            echo ""
            echo "Trying PyQt6 via pip as last resort:"
            $PYTHON_CMD -m $PIP_INSTALL_CMD PyQt6
            
            if [ $? -eq 0 ]; then
                echo "✅ PyQt6 installed via pip successfully"
                echo ""
                echo "Installing other dependencies..."
                $PYTHON_CMD -m $PIP_INSTALL_CMD mnemonic python-gnupg qrcode[pil] Pillow
                
                if [ $? -eq 0 ]; then
                    echo "✅ Dependencies installed successfully"
                    echo ""
                    echo "Starting Seed Master..."
                    $PYTHON_CMD seed_master.py
                    
                    # Clean up
                    echo ""
                    echo "Cleaning up temporary virtual environment..."
                    deactivate
                    rm -rf temp_venv
                else
                    echo "❌ Failed to install dependencies"
                    deactivate
                    rm -rf temp_venv
                    exit 1
                fi
            else
                echo "❌ Failed to install PyQt6 via pip"
                deactivate
                rm -rf temp_venv
                echo ""
                echo "Alternative solutions:"
                echo "1. Try: sudo apt install python3-pyqt6"
                echo "2. Try: sudo apt install python3-pyqt5"
                echo "3. Use the command-line version instead"
                exit 1
            fi
        fi
    fi
fi
