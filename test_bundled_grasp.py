#!/usr/bin/env python3
"""
Test script for bundled grasp binary functionality.
"""

import sys
import os
import subprocess

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from grasp_binary import get_grasp_binary_path, test_grasp_binary, get_available_platforms

def test_bundled_grasp():
    """Test that the bundled grasp binary works correctly."""
    print("Testing Bundled Grasp Binary")
    print("=" * 40)
    
    # Test platform detection
    binary_path = get_grasp_binary_path()
    if binary_path:
        print(f"✅ Found bundled binary: {binary_path}")
    else:
        print("❌ No bundled binary found")
        return False
    
    # Test binary functionality
    if test_grasp_binary():
        print("✅ Binary test passed")
    else:
        print("❌ Binary test failed")
        return False
    
    # Test passphrase generation
    try:
        result = subprocess.run(
            [binary_path, "-s", "XXXL", "test", "passphrase"],
            capture_output=True,
            text=True,
            check=True
        )
        
        passphrase = result.stdout.strip()
        print(f"✅ Generated passphrase: {passphrase[:20]}...")
        print(f"   Length: {len(passphrase)} characters")
        
        if len(passphrase) == 128:
            print("✅ Passphrase length is correct (128 characters)")
        else:
            print(f"❌ Passphrase length is incorrect: {len(passphrase)}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Passphrase generation failed: {e}")
        return False
    
    # Show available platforms
    platforms = get_available_platforms()
    print(f"\n📦 Available platforms: {', '.join(platforms)}")
    
    print("\n✅ Bundled Grasp Test PASSED!")
    return True

if __name__ == "__main__":
    success = test_bundled_grasp()
    sys.exit(0 if success else 1)
