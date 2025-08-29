#!/usr/bin/env python3
"""
Fallback passphrase generator that calls the actual grasp command.
This ensures 100% compatibility with grasp's output.
"""

import hashlib
import base64
import secrets
import sys
import subprocess
from typing import Optional
import os


class GraspFallback:
    """Fallback passphrase generator that calls the actual grasp command."""
    
    @staticmethod
    def generate_passphrase(*keywords) -> str:
        """
        Generate a deterministic passphrase using the actual grasp command.
        This ensures 100% compatibility with grasp's output.
        
        Args:
            *keywords: Multiple keywords (at least 2 required)
            
        Returns:
            Generated passphrase for GPG encryption
        """
        if len(keywords) < 2:
            raise ValueError("At least 2 keywords are required")
        
        try:
            # Call the actual grasp command with XXXL size
            result = subprocess.run(
                ["grasp", "-s", "XXXL"] + list(keywords),
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout.strip()
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Grasp command error: {e.stderr}")
        except FileNotFoundError:
            raise RuntimeError("Grasp command not found. Please install grasp first: brew tap lucasepe/grasp && brew install grasp")


def test_grasp_fallback():
    """Test the fallback passphrase generator."""
    fallback = GraspFallback()
    
    # Use command line arguments if provided, otherwise use default test keywords
    if len(sys.argv) > 1:
        test_keywords = sys.argv[1:]
        print(f"Using command line arguments: {test_keywords}")
    else:
        test_keywords = ["my-secret-passphrase", "seedmaster"]
        print(f"Using default test keywords: {test_keywords}")
    
    generated = fallback.generate_passphrase(*test_keywords)
    
    print(f"Generated passphrase: {generated}")
    print(f"Length: {len(generated)}")
    
    # Test determinism
    generated2 = fallback.generate_passphrase(*test_keywords)
    assert generated == generated2, "Passphrase generation is not deterministic!"
    print("✓ Deterministic generation confirmed")
    
    # Test error handling for insufficient keywords
    try:
        fallback.generate_passphrase("single-keyword")
        print("❌ Should have raised an error for single keyword")
    except ValueError as e:
        print(f"✓ Correctly rejected single keyword: {e}")


if __name__ == "__main__":
    test_grasp_fallback()
