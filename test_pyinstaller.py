#!/usr/bin/env python3
"""
Test script to verify PyInstaller command works correctly.
"""

import os
import sys
import subprocess
from pathlib import Path

def test_pyinstaller_command():
    """Test the PyInstaller command that's used in CI."""
    
    # Check if config file exists
    config_file = Path("ward_core/config.yaml")
    if not config_file.exists():
        print(f"❌ Config file not found: {config_file}")
        return False
    
    print(f"✅ Config file found: {config_file.absolute()}")
    
    # Prepare the command
    if os.name == 'nt':  # Windows
        add_data_arg = f"{config_file.absolute()};."
    else:  # Linux/macOS
        add_data_arg = f"{config_file.absolute()}:."
    
    cmd = [
        "pyinstaller",
        "--noconfirm",
        "--clean", 
        "--name", "ward-core",
        "--distpath", "test_build/dist",
        "--workpath", "test_build/work",
        "--add-data", add_data_arg,
        "main.py"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ PyInstaller command succeeded")
            
            # Check if config file was included
            built_config = Path("test_build/dist/ward-core/config.yaml")
            if built_config.exists():
                print(f"✅ Config file found in build: {built_config}")
                return True
            else:
                print(f"❌ Config file NOT found in build: {built_config}")
                print("Contents of build directory:")
                build_dir = Path("test_build/dist/ward-core")
                if build_dir.exists():
                    for item in build_dir.iterdir():
                        print(f"  {item.name}")
                return False
        else:
            print(f"❌ PyInstaller command failed with return code {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ PyInstaller command timed out")
        return False
    except Exception as e:
        print(f"❌ Error running PyInstaller: {e}")
        return False

def main():
    """Run the test."""
    print("Testing PyInstaller command...")
    print("=" * 50)
    
    if test_pyinstaller_command():
        print("\n✅ Test passed! PyInstaller command should work in CI.")
        return 0
    else:
        print("\n❌ Test failed! PyInstaller command needs fixing.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
