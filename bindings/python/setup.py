#!/usr/bin/env python3
"""
QUAC 100 Python SDK - Setup Script

This file provides legacy support for pip installations.
Modern installations should use pyproject.toml.
"""

from setuptools import setup, find_packages
import os
import sys

# Read version from package
def get_version():
    version_file = os.path.join(os.path.dirname(__file__), "quantacore", "__init__.py")
    with open(version_file, "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"').strip("'")
    return "1.0.0"

# Read README for long description
def get_long_description():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

# Platform-specific native library patterns
def get_package_data():
    return {
        "quantacore": ["py.typed"],
        "quantacore.native": [
            "windows-x64/*.dll",
            "linux-x64/*.so", 
            "linux-x64/*.so.*",
            "macos-x64/*.dylib",
        ],
    }

setup(
    name="quantacore-sdk",
    version=get_version(),
    author="Dyber, Inc.",
    author_email="support@dyber.org",
    description="Python bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/dyber-pqc/quantacore-sdk",
    project_urls={
        "Documentation": "https://docs.dyber.org/quac100/python",
        "Bug Tracker": "https://github.com/dyber-pqc/quantacore-sdk/issues",
        "Homepage": "https://dyber.org",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "docs"]),
    package_data=get_package_data(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.0",
            "black>=23.0",
            "isort>=5.0",
            "flake8>=6.0",
        ],
        "test": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
        "docs": [
            "sphinx>=6.0",
            "sphinx-rtd-theme>=1.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: Other/Proprietary License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords="cryptography post-quantum pqc kyber dilithium ml-kem ml-dsa hsm qrng",
    zip_safe=False,
)