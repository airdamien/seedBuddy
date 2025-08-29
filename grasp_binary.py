#!/usr/bin/env python3
"""
Platform detection and grasp binary selection module.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path


def get_platform_info():
    """
    Get platform information for binary selection.
    
    Returns:
        Tuple of (system, machine, binary_name)
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map machine architectures
    if machine in ['x86_64', 'amd64']:
        machine = 'amd64'
    elif machine in ['aarch64', 'arm64']:
        machine = 'arm64'
    
    # Determine binary name
    if system == 'windows':
        binary_name = 'grasp.exe'
    else:
        binary_name = 'grasp'
    
    return system, machine, binary_name


def get_grasp_binary_path():
    """
    Get the path to the appropriate grasp binary for the current platform.
    
    Returns:
        Path to the grasp binary, or None if not found
    """
    system, machine, binary_name = get_platform_info()
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    binary_dir = script_dir / 'grasp_binaries' / f'{system}_{machine}'
    binary_path = binary_dir / binary_name
    
    if binary_path.exists():
        # Make sure the binary is executable (for Unix-like systems)
        if system != 'windows':
            os.chmod(binary_path, 0o755)
        return str(binary_path)
    
    return None


def test_grasp_binary():
    """
    Test if the grasp binary works correctly.
    
    Returns:
        True if binary works, False otherwise
    """
    binary_path = get_grasp_binary_path()
    if not binary_path:
        return False
    
    try:
        result = subprocess.run(
            [binary_path, '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_available_platforms():
    """
    Get list of available platform binaries.
    
    Returns:
        List of available platform directories
    """
    script_dir = Path(__file__).parent
    binary_base = script_dir / 'grasp_binaries'
    
    if not binary_base.exists():
        return []
    
    platforms = []
    for platform_dir in binary_base.iterdir():
        if platform_dir.is_dir():
            platforms.append(platform_dir.name)
    
    return sorted(platforms)


if __name__ == "__main__":
    print("Grasp Binary Platform Detection")
    print("=" * 40)
    
    system, machine, binary_name = get_platform_info()
    print(f"Current platform: {system}_{machine}")
    print(f"Binary name: {binary_name}")
    
    binary_path = get_grasp_binary_path()
    if binary_path:
        print(f"Binary path: {binary_path}")
        print(f"Binary exists: {Path(binary_path).exists()}")
        
        if test_grasp_binary():
            print("✅ Binary test: PASSED")
        else:
            print("❌ Binary test: FAILED")
    else:
        print("❌ No suitable binary found")
    
    print(f"\nAvailable platforms: {', '.join(get_available_platforms())}")
