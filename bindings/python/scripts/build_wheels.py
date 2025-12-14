#!/usr/bin/env python3
"""
Build platform-specific wheels for the QUAC 100 Python SDK.

This script builds wheels with the native libraries bundled for each platform.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


# Platform configurations
PLATFORMS = {
    "windows-x64": {
        "lib_name": "quac100.dll",
        "wheel_plat": "win_amd64",
    },
    "linux-x64": {
        "lib_name": "libquac100.so",
        "wheel_plat": "manylinux2014_x86_64",
    },
    "macos-x64": {
        "lib_name": "libquac100.dylib",
        "wheel_plat": "macosx_10_9_x86_64",
    },
    "macos-arm64": {
        "lib_name": "libquac100.dylib",
        "wheel_plat": "macosx_11_0_arm64",
    },
}


def clean_build():
    """Remove build artifacts."""
    dirs_to_remove = ["build", "dist", "*.egg-info"]
    for pattern in dirs_to_remove:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"Removed: {path}")


def build_sdist():
    """Build source distribution."""
    print("\n" + "=" * 60)
    print("Building source distribution...")
    print("=" * 60)
    
    subprocess.run([
        sys.executable, "-m", "build", "--sdist"
    ], check=True)


def build_wheel(platform: str):
    """Build wheel for specific platform."""
    config = PLATFORMS.get(platform)
    if not config:
        print(f"Unknown platform: {platform}")
        return False
    
    print(f"\n" + "=" * 60)
    print(f"Building wheel for {platform}...")
    print("=" * 60)
    
    # Check if native library exists
    native_dir = Path(f"quantacore/native/{platform}")
    lib_path = native_dir / config["lib_name"]
    
    if not lib_path.exists():
        print(f"Warning: Native library not found at {lib_path}")
        print("Building wheel without bundled native library.")
    
    # Build wheel
    subprocess.run([
        sys.executable, "-m", "build", "--wheel"
    ], check=True)
    
    return True


def build_all():
    """Build for all platforms."""
    clean_build()
    build_sdist()
    
    for platform in PLATFORMS:
        build_wheel(platform)
    
    print("\n" + "=" * 60)
    print("Build complete!")
    print("=" * 60)
    print("\nBuilt packages:")
    for path in Path("dist").glob("*"):
        print(f"  {path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Build QUAC 100 Python SDK wheels")
    parser.add_argument(
        "--platform",
        choices=list(PLATFORMS.keys()) + ["all"],
        default="all",
        help="Target platform (default: all)"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Only clean build artifacts"
    )
    
    args = parser.parse_args()
    
    if args.clean:
        clean_build()
        return
    
    if args.platform == "all":
        build_all()
    else:
        clean_build()
        build_wheel(args.platform)


if __name__ == "__main__":
    main()