#!/usr/bin/env python3
"""
Seed Buddy - BIP-39 Seed Phrase Encryptor
A secure local GUI application for encrypting BIP-39 seed phrases.
"""

import sys
import os
import subprocess
import base64
import tempfile
import hashlib
from typing import Optional, Tuple
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QTextEdit, QLineEdit, QPushButton, QLabel, QMessageBox,
    QScrollArea, QFrame, QSplitter, QFileDialog, QCheckBox, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap, QFont, QPalette, QColor
try:
    import qrencode
    HAS_QRENCODE = True
except ImportError:
    import qrcode
    HAS_QRENCODE = False
from mnemonic import Mnemonic
import gnupg
from grasp_fallback import GraspFallback
from grasp_binary import get_grasp_binary_path


class GraspPassphraseGenerator:
    """Interface to the grasp tool for passphrase generation."""
    
    @staticmethod
    def generate_passphrase(master_passphrase: str, salt: str = "seedmaster") -> str:
        """
        Generate a passphrase using the grasp tool.
        
        Args:
            master_passphrase: The user's master passphrase
            salt: Salt for the passphrase generation
            
        Returns:
            Generated passphrase for GPG encryption
        """
        try:
            # Split master passphrase into keywords
            keywords = master_passphrase.split()
            if len(keywords) < 2:
                raise ValueError("Master passphrase must contain at least 2 words")
            
            # Try to get the bundled grasp binary
            grasp_binary = get_grasp_binary_path()
            if grasp_binary:
                # Use bundled binary
                result = subprocess.run(
                    [grasp_binary, "-s", "XXXL"] + keywords,  # Use XXXL size (128 chars)
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout.strip()
            else:
                # Try system grasp binary
                result = subprocess.run(
                    ["grasp", "-s", "XXXL"] + keywords,  # Use XXXL size (128 chars)
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout.strip()
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Grasp tool error: {e.stderr}")
        except FileNotFoundError:
            # Fallback to internal implementation
            print("Grasp tool not found, using fallback implementation")
            return GraspFallback.generate_passphrase(*keywords)


class BIP39Validator:
    """BIP-39 seed phrase validation."""
    
    def __init__(self):
        self.mnemo = Mnemonic("english")
    
    def validate_seed_phrase(self, words: str) -> Tuple[bool, str]:
        """
        Validate a BIP-39 seed phrase.
        
        Args:
            words: Space-separated BIP-39 words
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Clean and normalize the input
            word_list = [word.strip().lower() for word in words.split() if word.strip()]
            
            # Check for valid word counts (12, 15, 18, 21, 24)
            valid_counts = [12, 15, 18, 21, 24]
            if len(word_list) not in valid_counts:
                return False, f"Expected 12, 15, 18, 21, or 24 words, got {len(word_list)}"
            
            # Check if all words are valid BIP-39 words
            invalid_words = [word for word in word_list if word not in self.mnemo.wordlist]
            if invalid_words:
                return False, f"Invalid BIP-39 words: {', '.join(invalid_words)}"
            
            # Validate checksum
            if not self.mnemo.check(' '.join(word_list)):
                return False, "Invalid checksum - seed phrase is not valid"
            
            return True, f"Valid BIP-39 seed phrase ({len(word_list)} words)"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"


class GPGEncryptor:
    """GPG symmetric encryption handler."""
    
    def __init__(self):
        self.gpg = gnupg.GPG()
    
    def encrypt_symmetric(self, data: str, passphrase: str) -> str:
        """
        Encrypt data using GPG symmetric encryption.
        
        Args:
            data: Data to encrypt
            passphrase: Passphrase for encryption
            
        Returns:
            Base64 encoded encrypted data
        """
        try:
            # Encrypt the data
            encrypted = self.gpg.encrypt(
                data,
                None,  # No recipient (symmetric encryption)
                symmetric=True,
                passphrase=passphrase,
                armor=False  # Binary output for base64 encoding
            )
            
            if encrypted.ok:
                # Convert to base64
                return base64.b64encode(encrypted.data).decode('utf-8')
            else:
                raise RuntimeError(f"GPG encryption failed: {encrypted.status}")
                
        except Exception as e:
            raise RuntimeError(f"Encryption error: {str(e)}")


class QRCodeGenerator:
    """QR code generation for encrypted data."""
    
    @staticmethod
    def generate_qr_code(data: str, size: int = 400) -> QPixmap:
        """
        Generate a QR code from data using qrencode.
        
        Args:
            data: Data to encode in QR code
            size: Size of the QR code image
            
        Returns:
            QPixmap containing the QR code
        """
        try:
            if HAS_QRENCODE:
                # Generate QR code using qrencode (faster, native)
                version, qr_size, qr_image = qrencode.encode(data)
                
                # Convert to QPixmap
                temp_path = tempfile.mktemp(suffix='.png')
                qr_image.save(temp_path)
                pixmap = QPixmap(temp_path)
                os.unlink(temp_path)  # Clean up temp file
            else:
                # Fallback to qrcode (slower, but more portable)
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(data)
                qr.make(fit=True)
                
                # Create image
                img = qr.make_image(fill_color="black", back_color="white")
                
                # Convert to QPixmap
                temp_path = tempfile.mktemp(suffix='.png')
                img.save(temp_path)
                pixmap = QPixmap(temp_path)
                os.unlink(temp_path)  # Clean up temp file
            
            return pixmap.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio)
            
        except Exception as e:
            raise RuntimeError(f"QR code generation error: {str(e)}")


class EncryptionWorker(QThread):
    """Background worker for encryption operations."""
    
    finished = pyqtSignal(bool, str, str, QPixmap)  # success, message, base64_data, qr_pixmap
    error = pyqtSignal(str)
    
    def __init__(self, seed_phrase: str, master_passphrase: str):
        super().__init__()
        self.seed_phrase = seed_phrase
        self.master_passphrase = master_passphrase
    
    def run(self):
        try:
            # Validate seed phrase
            validator = BIP39Validator()
            is_valid, message = validator.validate_seed_phrase(self.seed_phrase)
            
            if not is_valid:
                self.finished.emit(False, message, "", QPixmap())
                return
            
            # Generate encryption passphrase using grasp
            grasp_gen = GraspPassphraseGenerator()
            encryption_passphrase = grasp_gen.generate_passphrase(self.master_passphrase)
            
            # Encrypt the seed phrase
            encryptor = GPGEncryptor()
            encrypted_data = encryptor.encrypt_symmetric(self.seed_phrase, encryption_passphrase)
            
            # Generate QR code
            qr_gen = QRCodeGenerator()
            qr_pixmap = qr_gen.generate_qr_code(encrypted_data)
            
            self.finished.emit(True, "Encryption successful", encrypted_data, qr_pixmap)
            
        except Exception as e:
            self.error.emit(str(e))


class DecryptionWorker(QThread):
    """Background worker for decryption operations."""
    
    finished = pyqtSignal(bool, str, str)  # success, message, decrypted_seed_phrase
    error = pyqtSignal(str)
    
    def __init__(self, encrypted_file: str, master_passphrase: str):
        super().__init__()
        self.encrypted_file = encrypted_file
        self.master_passphrase = master_passphrase
    
    def run(self):
        try:
            # Read the encrypted data
            with open(self.encrypted_file, 'r') as f:
                encrypted_base64 = f.read().strip()
            
            # Regenerate the encryption passphrase using the same keywords
            encryption_passphrase = GraspPassphraseGenerator().generate_passphrase(self.master_passphrase)
            
            # Decode base64 and decrypt
            encrypted_data = base64.b64decode(encrypted_base64)
            
            # Create a temporary file for the encrypted data
            temp_file = "temp_encrypted.gpg"
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)
            
            try:
                # Decrypt using GPG
                result = subprocess.run([
                    'gpg', '--decrypt', '--batch', '--passphrase', encryption_passphrase,
                    temp_file
                ], capture_output=True, text=True, check=True)
                
                decrypted_data = result.stdout.strip()
                
                # Validate the decrypted data as BIP-39
                validator = BIP39Validator()
                is_valid, message = validator.validate_seed_phrase(decrypted_data)
                
                if is_valid:
                    self.finished.emit(True, "Decryption successful - Valid BIP-39 seed phrase", decrypted_data)
                else:
                    self.finished.emit(False, f"Decryption successful but invalid BIP-39: {message}", decrypted_data)
                    
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    
        except FileNotFoundError:
            self.error.emit(f"File '{self.encrypted_file}' not found")
        except subprocess.CalledProcessError as e:
            self.error.emit(f"Decryption failed: {e.stderr}")
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
        self.setWindowTitle("Seed Buddy - BIP-39 Seed Phrase Encryptor")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget with tabs
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        
        # Create encryption tab
        self.encryption_tab = QWidget()
        self.tab_widget.addTab(self.encryption_tab, "🔒 Encrypt Seed Phrase")
        
        # Create decryption tab
        self.decryption_tab = QWidget()
        self.tab_widget.addTab(self.decryption_tab, "🔓 Decrypt Seed Phrase")
        
        # Initialize encryption UI
        self.init_encryption_ui()
        
        # Initialize decryption UI
        self.init_decryption_ui()
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def init_encryption_ui(self):
        """Initialize the encryption tab UI."""
        main_layout = QVBoxLayout(self.encryption_tab)
        
        # Title
        title_label = QLabel("Seed Buddy - Secure BIP-39 Encryptor")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Security warnings
        warning_label = QLabel("⚠️  CRITICAL SECURITY WARNING")
        warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        main_layout.addWidget(warning_label)
        
        airgap_label = QLabel("🔒 Use this tool on an AIR-GAPPED computer (no internet connection)")
        airgap_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        airgap_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(airgap_label)
        
        storage_label = QLabel("🗑️  DESTROY all temporary files and storage after saving encrypted values")
        storage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        storage_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(storage_label)
        
        risk_label = QLabel("⚠️  This tool handles sensitive cryptographic material. Use at your own risk.")
        risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(risk_label)
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        input_layout = QVBoxLayout(input_frame)
        
        # Seed phrase input
        seed_label = QLabel("Enter your BIP-39 words (12, 15, 18, 21, or 24 words, space-separated):")
        input_layout.addWidget(seed_label)
        
        self.seed_text = QTextEdit()
        self.seed_text.setMaximumHeight(100)
        self.seed_text.setPlaceholderText("friend confirm mobile early diesel hurt swamp orphan good cruise script crisp")
        input_layout.addWidget(self.seed_text)
        
        # Master passphrase input
        passphrase_label = QLabel("Enter your master passphrase:")
        input_layout.addWidget(passphrase_label)
        
        # Passphrase input with show/hide checkbox
        passphrase_layout = QHBoxLayout()
        
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_input.setPlaceholderText("Enter your master passphrase (at least 2 words)")
        passphrase_layout.addWidget(self.passphrase_input)
        
        self.show_passphrase_checkbox = QCheckBox("Show")
        self.show_passphrase_checkbox.toggled.connect(self.toggle_passphrase_visibility)
        passphrase_layout.addWidget(self.show_passphrase_checkbox)
        
        input_layout.addLayout(passphrase_layout)
        
        # Encrypt button
        self.encrypt_button = QPushButton("🔒 Encrypt Seed Phrase")
        self.encrypt_button.clicked.connect(self.encrypt_seed_phrase)
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        input_layout.addWidget(self.encrypt_button)
        
        main_layout.addWidget(input_frame)
        
        # Output section
        output_frame = QFrame()
        output_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        output_layout = QVBoxLayout(output_frame)
        
        output_label = QLabel("Encrypted Output:")
        output_layout.addWidget(output_label)
        
        # Splitter for QR code and base64
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # QR code display
        qr_frame = QFrame()
        qr_layout = QVBoxLayout(qr_frame)
        qr_title = QLabel("QR Code:")
        qr_layout.addWidget(qr_title)
        
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumSize(400, 400)
        self.qr_label.setStyleSheet("border: 1px solid #ccc;")
        qr_layout.addWidget(self.qr_label)
        
        # Save QR code button
        self.save_qr_button = QPushButton("💾 Save QR Code")
        self.save_qr_button.clicked.connect(self.save_qr_code)
        self.save_qr_button.setEnabled(False)
        qr_layout.addWidget(self.save_qr_button)
        
        splitter.addWidget(qr_frame)
        
        # Base64 display
        base64_frame = QFrame()
        base64_layout = QVBoxLayout(base64_frame)
        base64_title = QLabel("Base64 Encoded Data:")
        base64_layout.addWidget(base64_title)
        
        self.base64_text = QTextEdit()
        self.base64_text.setReadOnly(True)
        self.base64_text.setPlaceholderText("Encrypted data will appear here...")
        base64_layout.addWidget(self.base64_text)
        
        # Save base64 button
        self.save_base64_button = QPushButton("💾 Save Base64 Text")
        self.save_base64_button.clicked.connect(self.save_base64_text)
        self.save_base64_button.setEnabled(False)
        base64_layout.addWidget(self.save_base64_button)
        
        splitter.addWidget(base64_frame)
        
        output_layout.addWidget(splitter)
        main_layout.addWidget(output_frame)
    
    def init_decryption_ui(self):
        """Initialize the decryption tab UI."""
        main_layout = QVBoxLayout(self.decryption_tab)
        
        # Title
        title_label = QLabel("Seed Buddy - Decrypt Seed Phrase")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Security warnings
        warning_label = QLabel("⚠️  CRITICAL SECURITY WARNING")
        warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        main_layout.addWidget(warning_label)
        
        airgap_label = QLabel("🔒 Use this tool on an AIR-GAPPED computer (no internet connection)")
        airgap_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        airgap_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(airgap_label)
        
        storage_label = QLabel("🗑️  DESTROY all temporary files and storage after saving encrypted values")
        storage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        storage_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(storage_label)
        
        risk_label = QLabel("⚠️  This tool handles sensitive cryptographic material. Use at your own risk.")
        risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk_label.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(risk_label)
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        input_layout = QVBoxLayout(input_frame)
        
        # File selection
        file_label = QLabel("Select encrypted file:")
        input_layout.addWidget(file_label)
        
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Click 'Browse' to select an encrypted file...")
        self.file_path_input.setReadOnly(True)
        file_layout.addWidget(self.file_path_input)
        
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_encrypted_file)
        file_layout.addWidget(self.browse_button)
        
        input_layout.addLayout(file_layout)
        
        # Master passphrase input for decryption
        decrypt_passphrase_label = QLabel("Enter your master passphrase:")
        input_layout.addWidget(decrypt_passphrase_label)
        
        # Passphrase input with show/hide checkbox
        decrypt_passphrase_layout = QHBoxLayout()
        
        self.decrypt_passphrase_input = QLineEdit()
        self.decrypt_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_passphrase_input.setPlaceholderText("Enter your master passphrase (at least 2 words)")
        decrypt_passphrase_layout.addWidget(self.decrypt_passphrase_input)
        
        self.show_decrypt_passphrase_checkbox = QCheckBox("Show")
        self.show_decrypt_passphrase_checkbox.toggled.connect(self.toggle_decrypt_passphrase_visibility)
        decrypt_passphrase_layout.addWidget(self.show_decrypt_passphrase_checkbox)
        
        input_layout.addLayout(decrypt_passphrase_layout)
        
        # Decrypt button
        self.decrypt_button = QPushButton("🔓 Decrypt Seed Phrase")
        self.decrypt_button.clicked.connect(self.decrypt_seed_phrase)
        self.decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        input_layout.addWidget(self.decrypt_button)
        
        main_layout.addWidget(input_frame)
        
        # Output section
        output_frame = QFrame()
        output_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        output_layout = QVBoxLayout(output_frame)
        
        output_label = QLabel("Decrypted Output:")
        output_layout.addWidget(output_label)
        
        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        self.decrypted_text.setPlaceholderText("Decrypted seed phrase will appear here...")
        output_layout.addWidget(self.decrypted_text)
        
        # Save decrypted button
        self.save_decrypted_button = QPushButton("💾 Save Decrypted Seed Phrase")
        self.save_decrypted_button.clicked.connect(self.save_decrypted_seed_phrase)
        self.save_decrypted_button.setEnabled(False)
        output_layout.addWidget(self.save_decrypted_button)
        
        main_layout.addWidget(output_frame)
    
    def encrypt_seed_phrase(self):
        """Handle seed phrase encryption."""
        seed_phrase = self.seed_text.toPlainText().strip()
        master_passphrase = self.passphrase_input.text()
        
        if not seed_phrase:
            QMessageBox.warning(self, "Input Error", "Please enter your BIP-39 seed phrase.")
            return
        
        if not master_passphrase:
            QMessageBox.warning(self, "Input Error", "Please enter your master passphrase.")
            return
        
        # Disable UI during processing
        self.encrypt_button.setEnabled(False)
        self.statusBar().showMessage("Encrypting...")
        
        # Start background worker
        self.encryption_worker = EncryptionWorker(seed_phrase, master_passphrase)
        self.encryption_worker.finished.connect(self.on_encryption_finished)
        self.encryption_worker.error.connect(self.on_encryption_error)
        self.encryption_worker.start()
    
    def on_encryption_finished(self, success: bool, message: str, base64_data: str, qr_pixmap: QPixmap):
        """Handle encryption completion."""
        self.encrypt_button.setEnabled(True)
        
        if success:
            # Display results
            self.qr_label.setPixmap(qr_pixmap)
            self.base64_text.setPlainText(base64_data)
            
            # Enable save buttons
            self.save_qr_button.setEnabled(True)
            self.save_base64_button.setEnabled(True)
            
            self.statusBar().showMessage("Encryption successful")
            QMessageBox.information(self, "Success", "Seed phrase encrypted successfully!")
        else:
            self.statusBar().showMessage("Validation failed")
            QMessageBox.warning(self, "Validation Error", message)
    
    def on_encryption_error(self, error_message: str):
        """Handle encryption errors."""
        self.encrypt_button.setEnabled(True)
        self.statusBar().showMessage("Encryption failed")
        QMessageBox.critical(self, "Encryption Error", f"An error occurred: {error_message}")
    
    def save_qr_code(self):
        """Save QR code to file."""
        if not self.qr_label.pixmap():
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save QR Code",
            "",
            "PNG Files (*.png);;All Files (*)"
        )
        
        if file_path:
            self.qr_label.pixmap().save(file_path)
            self.statusBar().showMessage(f"QR code saved to {file_path}")
    
    def toggle_passphrase_visibility(self, checked):
        """Toggle passphrase visibility based on checkbox state."""
        if checked:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def save_base64_text(self):
        """Save base64 text to file."""
        base64_data = self.base64_text.toPlainText()
        if not base64_data:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Base64 Text",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(base64_data)
            self.statusBar().showMessage(f"Base64 text saved to {file_path}")
    
    def browse_encrypted_file(self):
        """Browse for an encrypted file to decrypt."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Encrypted File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.file_path_input.setText(file_path)
    
    def decrypt_seed_phrase(self):
        """Handle seed phrase decryption."""
        file_path = self.file_path_input.text().strip()
        master_passphrase = self.decrypt_passphrase_input.text()
        
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select an encrypted file.")
            return
        
        if not master_passphrase:
            QMessageBox.warning(self, "Input Error", "Please enter your master passphrase.")
            return
        
        # Disable UI during processing
        self.decrypt_button.setEnabled(False)
        self.statusBar().showMessage("Decrypting...")
        
        # Start background worker
        self.decryption_worker = DecryptionWorker(file_path, master_passphrase)
        self.decryption_worker.finished.connect(self.on_decryption_finished)
        self.decryption_worker.error.connect(self.on_decryption_error)
        self.decryption_worker.start()
    
    def on_decryption_finished(self, success: bool, message: str, decrypted_seed_phrase: str):
        """Handle decryption completion."""
        self.decrypt_button.setEnabled(True)
        
        if success:
            # Display results
            self.decrypted_text.setPlainText(decrypted_seed_phrase)
            
            # Enable save button
            self.save_decrypted_button.setEnabled(True)
            
            self.statusBar().showMessage("Decryption successful")
            QMessageBox.information(self, "Success", "Seed phrase decrypted successfully!")
        else:
            self.statusBar().showMessage("Decryption failed")
            QMessageBox.warning(self, "Decryption Error", message)
    
    def on_decryption_error(self, error_message: str):
        """Handle decryption errors."""
        self.decrypt_button.setEnabled(True)
        self.statusBar().showMessage("Decryption failed")
        QMessageBox.critical(self, "Decryption Error", f"An error occurred: {error_message}")
    
    def save_decrypted_seed_phrase(self):
        """Save decrypted seed phrase to file."""
        decrypted_data = self.decrypted_text.toPlainText()
        if not decrypted_data:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Decrypted Seed Phrase",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(decrypted_data)
            self.statusBar().showMessage(f"Decrypted seed phrase saved to {file_path}")
    
    def toggle_decrypt_passphrase_visibility(self, checked):
        """Toggle decryption passphrase visibility based on checkbox state."""
        if checked:
            self.decrypt_passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.decrypt_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = SeedMasterGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
