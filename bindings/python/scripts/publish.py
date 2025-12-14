#!/usr/bin/env python3
"""
Publish QUAC 100 Python SDK to PyPI.

This script handles uploading to TestPyPI for testing and PyPI for production.
"""

import subprocess
import sys
from pathlib import Path


def check_dist():
    """Check if distribution files exist."""
    dist_dir = Path("dist")
    if not dist_dir.exists():
        print("Error: dist/ directory not found. Run 'make build' first.")
        return False
    
    files = list(dist_dir.glob("*"))
    if not files:
        print("Error: No distribution files found in dist/")
        return False
    
    print("Distribution files:")
    for f in files:
        print(f"  {f}")
    
    return True


def check_twine():
    """Check if twine is installed."""
    try:
        subprocess.run(
            [sys.executable, "-m", "twine", "--version"],
            capture_output=True,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: twine not installed. Run 'pip install twine'")
        return False


def upload_testpypi():
    """Upload to TestPyPI."""
    print("\n" + "=" * 60)
    print("Uploading to TestPyPI...")
    print("=" * 60)
    
    subprocess.run([
        sys.executable, "-m", "twine", "upload",
        "--repository", "testpypi",
        "dist/*"
    ], check=True)
    
    print("\nUpload complete!")
    print("Test installation with:")
    print("  pip install --index-url https://test.pypi.org/simple/ quantacore-sdk")


def upload_pypi():
    """Upload to PyPI."""
    print("\n" + "=" * 60)
    print("Uploading to PyPI...")
    print("=" * 60)
    
    # Confirm
    response = input("\nAre you sure you want to upload to PyPI? (yes/no): ")
    if response.lower() != "yes":
        print("Upload cancelled.")
        return
    
    subprocess.run([
        sys.executable, "-m", "twine", "upload",
        "dist/*"
    ], check=True)
    
    print("\nUpload complete!")
    print("Install with:")
    print("  pip install quantacore-sdk")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Publish QUAC 100 Python SDK to PyPI")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Upload to TestPyPI instead of PyPI"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check distribution files"
    )
    
    args = parser.parse_args()
    
    if not check_dist():
        sys.exit(1)
    
    if args.check:
        print("\nDistribution files ready for upload.")
        return
    
    if not check_twine():
        sys.exit(1)
    
    if args.test:
        upload_testpypi()
    else:
        upload_pypi()


if __name__ == "__main__":
    main()