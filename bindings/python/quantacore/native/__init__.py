"""
Native library package for QUAC 100 SDK.

This package contains platform-specific native libraries:
- windows-x64/quac100.dll
- linux-x64/libquac100.so
- macos-x64/libquac100.dylib
"""

from pathlib import Path

# Package directory
PACKAGE_DIR = Path(__file__).parent

# Platform directories
WINDOWS_X64 = PACKAGE_DIR / "windows-x64"
LINUX_X64 = PACKAGE_DIR / "linux-x64"
MACOS_X64 = PACKAGE_DIR / "macos-x64"

__all__ = ["PACKAGE_DIR", "WINDOWS_X64", "LINUX_X64", "MACOS_X64"]