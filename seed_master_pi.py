#!/usr/bin/env python3
"""
Seed Master - BIP-39 Seed Phrase Encryptor (PyQt5 Version for Raspberry Pi)
"""

import sys
import os
import subprocess
import base64
import tempfile
from pathlib import Path

# Try PyQt5 first, fallback to PyQt6
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QTextEdit, QLineEdit, QPushButton, QCheckBox, QFileDialog,
        QMessageBox, QProgressBar, QTabWidget, QFrame, QScrollArea
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QPixmap
    PYQT_VERSION = 5
except ImportError:
    try:
        from PyQt6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QTextEdit, QLineEdit, QPushButton, QCheckBox, QFileDialog,
            QMessageBox, QProgressBar, QTabWidget, QFrame, QScrollArea
        )
        from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
        from PyQt6.QtGui import QFont, QPixmap
        PYQT_VERSION = 6
    except ImportError:
        print("❌ Neither PyQt5 nor PyQt6 is installed.")
        print("Please install one of them:")
        print("  sudo apt install python3-pyqt5  # For Raspberry Pi")
        print("  pip install PyQt6               # For other systems")
        sys.exit(1)

# Import other dependencies
try:
    from mnemonic import Mnemonic
    import gnupg
    try:
        import qrencode
        HAS_QRENCODE = True
    except ImportError:
        import qrcode
        HAS_QRENCODE = False
    from PIL import Image
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Please install dependencies: pip install mnemonic python-gnupg qrcode[pil] Pillow")
    sys.exit(1)

# Import local modules
try:
    from grasp_fallback import GraspFallback
    from grasp_binary import get_grasp_binary_path
except ImportError:
    print("❌ Missing local modules. Make sure you're running from the project directory.")
    sys.exit(1)


class GraspPassphraseGenerator:
    """Generates passphrases using the grasp tool."""
    
    def __init__(self):
        self.fallback = GraspFallback()
    
    def generate_passphrase(self, master_passphrase):
        """Generate a passphrase using grasp or fallback."""
        keywords = master_passphrase.split()
        
        if len(keywords) < 2:
            raise ValueError("Master passphrase must contain at least 2 words")
        
        try:
            # Try bundled grasp binary first
            grasp_path = get_grasp_binary_path()
            if grasp_path and os.path.exists(grasp_path):
                result = subprocess.run(
                    [grasp_path, "-s", "XXXL"] + keywords,
                    capture_output=True, text=True, check=True
                )
                return result.stdout.strip()
            
            # Try system grasp
            result = subprocess.run(
                ["grasp", "-s", "XXXL"] + keywords,
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Use fallback
            return self.fallback.generate_passphrase(*keywords)


class BIP39Validator:
    """Validates BIP-39 seed phrases."""
    
    def __init__(self):
        self.mnemo = Mnemonic("english")
    
    def validate_seed_phrase(self, seed_phrase):
        """Validate a BIP-39 seed phrase."""
        word_list = seed_phrase.strip().split()
        
        # Check word count
        valid_lengths = [12, 15, 18, 21, 24]
        if len(word_list) not in valid_lengths:
            return False, f"Invalid word count: {len(word_list)}. Must be 12, 15, 18, 21, or 24 words."
        
        # Check if all words are valid BIP-39 words
        if not all(word in self.mnemo.wordlist for word in word_list):
            return False, "Invalid BIP-39 word(s) found."
        
        # Validate checksum
        try:
            self.mnemo.check(seed_phrase)
            return True, f"Valid BIP-39 seed phrase ({len(word_list)} words)."
        except Exception as e:
            return False, f"Invalid checksum: {str(e)}"


class GPGEncryptor:
    """Handles GPG encryption."""
    
    def __init__(self):
        self.gpg = gnupg.GPG()
    
    def encrypt_data(self, data, passphrase):
        """Encrypt data using GPG symmetric encryption."""
        encrypted = self.gpg.encrypt(
            data,
            symmetric=True,
            passphrase=passphrase,
            armor=False
        )
        return base64.b64encode(encrypted.data).decode('utf-8')


class QRCodeGenerator:
    """Generates QR codes."""
    
    def generate_qr_code(self, data, filename):
        """Generate a QR code from data and save to filename."""
        if HAS_QRENCODE:
            # Use qrencode (faster, native)
            version, qr_size, qr_image = qrencode.encode(data)
            qr_image.save(filename)
        else:
            # Fallback to qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(filename)
        return filename


class EncryptionWorker(QThread):
    """Background thread for encryption."""
    
    finished = pyqtSignal(str, str)  # qr_filename, base64_data
    error = pyqtSignal(str)
    
    def __init__(self, seed_phrase, master_passphrase):
        super().__init__()
        self.seed_phrase = seed_phrase
        self.master_passphrase = master_passphrase
    
    def run(self):
        try:
            # Generate passphrase
            generator = GraspPassphraseGenerator()
            encryption_passphrase = generator.generate_passphrase(self.master_passphrase)
            
            # Encrypt data
            encryptor = GPGEncryptor()
            encrypted_data = encryptor.encrypt_data(self.seed_phrase, encryption_passphrase)
            
            # Generate QR code
            qr_generator = QRCodeGenerator()
            qr_filename = "encrypted_seed_qr.png"
            qr_generator.generate_qr_code(encrypted_data, qr_filename)
            
            self.finished.emit(qr_filename, encrypted_data)
            
        except Exception as e:
            self.error.emit(str(e))


class DecryptionWorker(QThread):
    """Background thread for decryption."""
    
    finished = pyqtSignal(str)  # decrypted_seed
    error = pyqtSignal(str)
    
    def __init__(self, encrypted_file, master_passphrase):
        super().__init__()
        self.encrypted_file = encrypted_file
        self.master_passphrase = master_passphrase
    
    def run(self):
        try:
            # Read encrypted data
            with open(self.encrypted_file, 'r') as f:
                encrypted_data = f.read().strip()
            
            # Decode base64
            decoded_data = base64.b64decode(encrypted_data)
            
            # Generate passphrase
            generator = GraspPassphraseGenerator()
            encryption_passphrase = generator.generate_passphrase(self.master_passphrase)
            
            # Decrypt data
            gpg = gnupg.GPG()
            decrypted = gpg.decrypt(
                decoded_data,
                passphrase=encryption_passphrase
            )
            
            if decrypted.ok:
                self.finished.emit(decrypted.data.decode('utf-8'))
            else:
                self.error.emit(f"Decryption failed: {decrypted.status}")
                
        except Exception as e:
            self.error.emit(str(e))


class SeedMasterGUI(QMainWindow):
    """Main GUI application."""
    
    def __init__(self):
        super().__init__()
        self.encryption_worker = None
        self.decryption_worker = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Seed Master - BIP-39 Seed Phrase Encryptor")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        tab_widget = QTabWidget()
        layout = QVBoxLayout(central_widget)
        layout.addWidget(tab_widget)
        
        # Create tabs
        self.init_encryption_ui(tab_widget)
        self.init_decryption_ui(tab_widget)
    
    def init_encryption_ui(self, tab_widget):
        """Initialize encryption tab."""
        encryption_widget = QWidget()
        main_layout = QVBoxLayout(encryption_widget)
        
        # Title
        title_label = QLabel("Seed Master - Secure BIP-39 Encryptor")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Security warnings
        warning_label = QLabel("⚠️  CRITICAL SECURITY WARNING")
        warning_label.setAlignment(Qt.AlignCenter)
        warning_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        main_layout.addWidget(warning_label)
        
        airgap_label = QLabel("🔒 Use this tool on an AIR-GAPPED computer (no internet connection)")
        airgap_label.setAlignment(Qt.AlignCenter)
        airgap_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(airgap_label)
        
        storage_label = QLabel("🗑️  DESTROY all temporary files and storage after saving encrypted values")
        storage_label.setAlignment(Qt.AlignCenter)
        storage_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(storage_label)
        
        risk_label = QLabel("⚠️  This tool handles sensitive cryptographic material. Use at your own risk.")
        risk_label.setAlignment(Qt.AlignCenter)
        risk_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(risk_label)
        
        # Input section
        input_label = QLabel("Enter your BIP-39 seed phrase (12, 15, 18, 21, or 24 words):")
        main_layout.addWidget(input_label)
        
        self.seed_text = QTextEdit()
        self.seed_text.setPlaceholderText("friend confirm mobile early diesel hurt swamp orphan good cruise script crisp")
        self.seed_text.setMaximumHeight(100)
        main_layout.addWidget(self.seed_text)
        
        # Passphrase input
        passphrase_label = QLabel("Enter your master passphrase (at least 2 words):")
        main_layout.addWidget(passphrase_label)
        
        passphrase_layout = QHBoxLayout()
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setPlaceholderText("Enter your master passphrase (at least 2 words)")
        passphrase_layout.addWidget(self.passphrase_input)
        
        self.show_passphrase = QCheckBox("Show")
        self.show_passphrase.toggled.connect(self.toggle_passphrase_visibility)
        passphrase_layout.addWidget(self.show_passphrase)
        
        main_layout.addLayout(passphrase_layout)
        
        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt Seed Phrase")
        self.encrypt_button.clicked.connect(self.encrypt_seed_phrase)
        main_layout.addWidget(self.encrypt_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Results section
        results_label = QLabel("Encrypted Output:")
        main_layout.addWidget(results_label)
        
        results_layout = QHBoxLayout()
        
        # QR code display
        qr_layout = QVBoxLayout()
        qr_label = QLabel("QR Code:")
        qr_layout.addWidget(qr_label)
        
        self.qr_display = QLabel()
        self.qr_display.setMinimumSize(200, 200)
        self.qr_display.setStyleSheet("border: 1px solid #ccc;")
        self.qr_display.setAlignment(Qt.AlignCenter)
        qr_layout.addWidget(self.qr_display)
        
        self.save_qr_button = QPushButton("Save QR Code")
        self.save_qr_button.clicked.connect(self.save_qr_code)
        self.save_qr_button.setEnabled(False)
        qr_layout.addWidget(self.save_qr_button)
        
        results_layout.addLayout(qr_layout)
        
        # Base64 text display
        text_layout = QVBoxLayout()
        text_label = QLabel("Base64 Text:")
        text_layout.addWidget(text_label)
        
        self.base64_display = QTextEdit()
        self.base64_display.setReadOnly(True)
        self.base64_display.setMaximumHeight(200)
        text_layout.addWidget(self.base64_display)
        
        self.save_text_button = QPushButton("Save Base64 Text")
        self.save_text_button.clicked.connect(self.save_base64_text)
        self.save_text_button.setEnabled(False)
        text_layout.addWidget(self.save_text_button)
        
        results_layout.addLayout(text_layout)
        
        main_layout.addLayout(results_layout)
        
        # Add to tab widget
        tab_widget.addTab(encryption_widget, "Encrypt Seed Phrase")
    
    def init_decryption_ui(self, tab_widget):
        """Initialize decryption tab."""
        decryption_widget = QWidget()
        main_layout = QVBoxLayout(decryption_widget)
        
        # Title
        title_label = QLabel("Seed Master - Decrypt Seed Phrase")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Security warnings
        warning_label = QLabel("⚠️  CRITICAL SECURITY WARNING")
        warning_label.setAlignment(Qt.AlignCenter)
        warning_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        main_layout.addWidget(warning_label)
        
        airgap_label = QLabel("🔒 Use this tool on an AIR-GAPPED computer (no internet connection)")
        airgap_label.setAlignment(Qt.AlignCenter)
        airgap_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(airgap_label)
        
        storage_label = QLabel("🗑️  DESTROY all temporary files and storage after saving encrypted values")
        storage_label.setAlignment(Qt.AlignCenter)
        storage_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(storage_label)
        
        risk_label = QLabel("⚠️  This tool handles sensitive cryptographic material. Use at your own risk.")
        risk_label.setAlignment(Qt.AlignCenter)
        risk_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(risk_label)
        
        # Input section
        file_label = QLabel("Select encrypted file:")
        main_layout.addWidget(file_label)
        
        file_layout = QHBoxLayout()
        self.file_path_label = QLabel("No file selected")
        file_layout.addWidget(self.file_path_label)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_encrypted_file)
        file_layout.addWidget(browse_button)
        
        main_layout.addLayout(file_layout)
        
        # Passphrase input
        decrypt_passphrase_label = QLabel("Enter your master passphrase (at least 2 words):")
        main_layout.addWidget(decrypt_passphrase_label)
        
        decrypt_passphrase_layout = QHBoxLayout()
        self.decrypt_passphrase_input = QLineEdit()
        self.decrypt_passphrase_input.setEchoMode(QLineEdit.Password)
        self.decrypt_passphrase_input.setPlaceholderText("Enter your master passphrase (at least 2 words)")
        decrypt_passphrase_layout.addWidget(self.decrypt_passphrase_input)
        
        self.show_decrypt_passphrase = QCheckBox("Show")
        self.show_decrypt_passphrase.toggled.connect(self.toggle_decrypt_passphrase_visibility)
        decrypt_passphrase_layout.addWidget(self.show_decrypt_passphrase)
        
        main_layout.addLayout(decrypt_passphrase_layout)
        
        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt Seed Phrase")
        self.decrypt_button.clicked.connect(self.decrypt_seed_phrase)
        main_layout.addWidget(self.decrypt_button)
        
        # Progress bar
        self.decrypt_progress_bar = QProgressBar()
        self.decrypt_progress_bar.setVisible(False)
        main_layout.addWidget(self.decrypt_progress_bar)
        
        # Results section
        decrypt_results_label = QLabel("Decrypted Seed Phrase:")
        main_layout.addWidget(decrypt_results_label)
        
        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        self.decrypted_text.setMaximumHeight(150)
        main_layout.addWidget(self.decrypted_text)
        
        self.save_decrypted_button = QPushButton("Save Decrypted Seed Phrase")
        self.save_decrypted_button.clicked.connect(self.save_decrypted_seed_phrase)
        self.save_decrypted_button.setEnabled(False)
        main_layout.addWidget(self.save_decrypted_button)
        
        # Add to tab widget
        tab_widget.addTab(decryption_widget, "Decrypt Seed Phrase")
    
    def toggle_passphrase_visibility(self, checked):
        """Toggle passphrase visibility."""
        if checked:
            self.passphrase_input.setEchoMode(QLineEdit.Normal)
        else:
            self.passphrase_input.setEchoMode(QLineEdit.Password)
    
    def toggle_decrypt_passphrase_visibility(self, checked):
        """Toggle decrypt passphrase visibility."""
        if checked:
            self.decrypt_passphrase_input.setEchoMode(QLineEdit.Normal)
        else:
            self.decrypt_passphrase_input.setEchoMode(QLineEdit.Password)
    
    def encrypt_seed_phrase(self):
        """Encrypt the seed phrase."""
        seed_phrase = self.seed_text.toPlainText().strip()
        master_passphrase = self.passphrase_input.text().strip()
        
        if not seed_phrase:
            QMessageBox.warning(self, "Error", "Please enter a seed phrase.")
            return
        
        if not master_passphrase:
            QMessageBox.warning(self, "Error", "Please enter a master passphrase.")
            return
        
        # Validate seed phrase
        validator = BIP39Validator()
        is_valid, message = validator.validate_seed_phrase(seed_phrase)
        
        if not is_valid:
            QMessageBox.warning(self, "Validation Error", message)
            return
        
        # Start encryption in background
        self.encrypt_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.encryption_worker = EncryptionWorker(seed_phrase, master_passphrase)
        self.encryption_worker.finished.connect(self.on_encryption_finished)
        self.encryption_worker.error.connect(self.on_encryption_error)
        self.encryption_worker.start()
    
    def on_encryption_finished(self, qr_filename, base64_data):
        """Handle encryption completion."""
        self.progress_bar.setVisible(False)
        self.encrypt_button.setEnabled(True)
        
        # Display QR code
        pixmap = QPixmap(qr_filename)
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_display.setPixmap(scaled_pixmap)
        
        # Display base64 text
        self.base64_display.setPlainText(base64_data)
        
        # Enable save buttons
        self.save_qr_button.setEnabled(True)
        self.save_text_button.setEnabled(True)
        
        QMessageBox.information(self, "Success", "Seed phrase encrypted successfully!")
    
    def on_encryption_error(self, error_message):
        """Handle encryption error."""
        self.progress_bar.setVisible(False)
        self.encrypt_button.setEnabled(True)
        QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt: {error_message}")
    
    def save_qr_code(self):
        """Save the QR code image."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save QR Code", "", "PNG Files (*.png)"
        )
        if filename:
            try:
                import shutil
                shutil.copy("encrypted_seed_qr.png", filename)
                QMessageBox.information(self, "Success", f"QR code saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save QR code: {str(e)}")
    
    def save_base64_text(self):
        """Save the base64 text."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Base64 Text", "", "Text Files (*.txt)"
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.base64_display.toPlainText())
                QMessageBox.information(self, "Success", f"Base64 text saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save base64 text: {str(e)}")
    
    def browse_encrypted_file(self):
        """Browse for encrypted file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Encrypted File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.file_path_label.setText(filename)
    
    def decrypt_seed_phrase(self):
        """Decrypt the seed phrase."""
        encrypted_file = self.file_path_label.text()
        master_passphrase = self.decrypt_passphrase_input.text().strip()
        
        if encrypted_file == "No file selected":
            QMessageBox.warning(self, "Error", "Please select an encrypted file.")
            return
        
        if not master_passphrase:
            QMessageBox.warning(self, "Error", "Please enter a master passphrase.")
            return
        
        # Start decryption in background
        self.decrypt_button.setEnabled(False)
        self.decrypt_progress_bar.setVisible(True)
        self.decrypt_progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.decryption_worker = DecryptionWorker(encrypted_file, master_passphrase)
        self.decryption_worker.finished.connect(self.on_decryption_finished)
        self.decryption_worker.error.connect(self.on_decryption_error)
        self.decryption_worker.start()
    
    def on_decryption_finished(self, decrypted_seed):
        """Handle decryption completion."""
        self.decrypt_progress_bar.setVisible(False)
        self.decrypt_button.setEnabled(True)
        
        # Display decrypted seed
        self.decrypted_text.setPlainText(decrypted_seed)
        
        # Enable save button
        self.save_decrypted_button.setEnabled(True)
        
        QMessageBox.information(self, "Success", "Seed phrase decrypted successfully!")
    
    def on_decryption_error(self, error_message):
        """Handle decryption error."""
        self.decrypt_progress_bar.setVisible(False)
        self.decrypt_button.setEnabled(True)
        QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt: {error_message}")
    
    def save_decrypted_seed_phrase(self):
        """Save the decrypted seed phrase."""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Decrypted Seed Phrase", "", "Text Files (*.txt)"
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.decrypted_text.toPlainText())
                QMessageBox.information(self, "Success", f"Decrypted seed phrase saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save decrypted seed phrase: {str(e)}")


def main():
    """Main function."""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Seed Master")
    app.setApplicationVersion("1.0")
    
    # Create and show the main window
    window = SeedMasterGUI()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
