"""
Native library loader for QUAC 100 SDK.

This module handles loading the platform-specific native library using ctypes.
"""

import ctypes
import os
import platform
import sys
from pathlib import Path
from typing import Optional

# Global reference to the loaded library
_lib: Optional[ctypes.CDLL] = None


def get_platform_info() -> tuple:
    """Get platform identifier and library extension.
    
    Returns:
        Tuple of (platform_dir, lib_prefix, lib_extension).
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Determine architecture
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "x86"
    else:
        arch = "x64"  # Default
    
    # Determine platform-specific settings
    if system == "windows":
        return f"windows-{arch}", "", ".dll"
    elif system == "darwin":
        return f"macos-{arch}", "lib", ".dylib"
    else:  # Linux and others
        return f"linux-{arch}", "lib", ".so"


def find_library() -> Optional[Path]:
    """Find the native library in various locations.
    
    Search order:
    1. Environment variable QUAC100_LIBRARY_PATH
    2. Bundled in package (quantacore/native/<platform>/)
    3. System library path
    4. Current directory
    
    Returns:
        Path to the library or None if not found.
    """
    platform_dir, lib_prefix, lib_ext = get_platform_info()
    lib_name = f"{lib_prefix}quac100{lib_ext}"
    
    # 1. Check environment variable
    env_path = os.environ.get("QUAC100_LIBRARY_PATH")
    if env_path:
        lib_path = Path(env_path)
        if lib_path.is_file():
            return lib_path
        elif lib_path.is_dir():
            candidate = lib_path / lib_name
            if candidate.exists():
                return candidate
    
    # 2. Check bundled in package
    package_dir = Path(__file__).parent
    bundled_path = package_dir / "native" / platform_dir / lib_name
    if bundled_path.exists():
        return bundled_path
    
    # 3. Try system library path (let ctypes handle it)
    # We'll return None and try to load by name
    
    # 4. Check current directory
    cwd_path = Path.cwd() / lib_name
    if cwd_path.exists():
        return cwd_path
    
    # 5. Check relative to script
    if hasattr(sys, 'frozen'):
        # PyInstaller or similar
        exe_dir = Path(sys.executable).parent
        exe_path = exe_dir / lib_name
        if exe_path.exists():
            return exe_path
    
    return None


def load_library() -> ctypes.CDLL:
    """Load the native QUAC 100 library.
    
    Returns:
        Loaded ctypes.CDLL instance.
        
    Raises:
        OSError: If the library cannot be loaded.
    """
    global _lib
    
    if _lib is not None:
        return _lib
    
    _, lib_prefix, lib_ext = get_platform_info()
    lib_name = f"{lib_prefix}quac100{lib_ext}"
    
    # Try to find the library
    lib_path = find_library()
    
    errors = []
    
    # Try loading from found path
    if lib_path:
        try:
            _lib = ctypes.CDLL(str(lib_path))
            _setup_prototypes(_lib)
            return _lib
        except OSError as e:
            errors.append(f"Failed to load {lib_path}: {e}")
    
    # Try loading by name (system library path)
    try:
        if platform.system() == "Windows":
            _lib = ctypes.CDLL("quac100")
        else:
            _lib = ctypes.CDLL("libquac100.so" if platform.system() != "Darwin" 
                              else "libquac100.dylib")
        _setup_prototypes(_lib)
        return _lib
    except OSError as e:
        errors.append(f"Failed to load from system path: {e}")
    
    # All attempts failed
    error_msg = "\n".join([
        "Failed to load QUAC 100 native library.",
        "",
        "Search locations:",
        f"  - Environment: QUAC100_LIBRARY_PATH",
        f"  - Package: quantacore/native/<platform>/",
        f"  - System library path",
        f"  - Current directory",
        "",
        "Errors encountered:",
        *[f"  - {e}" for e in errors],
        "",
        "Please ensure the native library is installed correctly.",
        "See https://docs.dyber.org/quac100/python for installation instructions.",
    ])
    raise OSError(error_msg)


def get_library() -> ctypes.CDLL:
    """Get the loaded native library.
    
    Returns:
        Loaded ctypes.CDLL instance.
        
    Raises:
        OSError: If the library is not loaded and cannot be loaded.
    """
    global _lib
    if _lib is None:
        return load_library()
    return _lib


def _setup_prototypes(lib: ctypes.CDLL) -> None:
    """Set up function prototypes for the native library.
    
    This ensures proper argument and return types for all functions.
    """
    # Library management
    lib.quac100_init.argtypes = [ctypes.c_uint32]
    lib.quac100_init.restype = ctypes.c_int
    
    lib.quac100_cleanup.argtypes = []
    lib.quac100_cleanup.restype = ctypes.c_int
    
    lib.quac100_is_initialized.argtypes = []
    lib.quac100_is_initialized.restype = ctypes.c_bool
    
    lib.quac100_version.argtypes = []
    lib.quac100_version.restype = ctypes.c_char_p
    
    lib.quac100_build_info.argtypes = []
    lib.quac100_build_info.restype = ctypes.c_char_p
    
    # Device management
    lib.quac100_device_count.argtypes = []
    lib.quac100_device_count.restype = ctypes.c_int
    
    lib.quac100_device_open.argtypes = [ctypes.c_int, ctypes.c_uint32]
    lib.quac100_device_open.restype = ctypes.c_void_p
    
    lib.quac100_device_close.argtypes = [ctypes.c_void_p]
    lib.quac100_device_close.restype = ctypes.c_int
    
    # KEM operations
    lib.quac100_kem_keygen.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # public key out
        ctypes.POINTER(ctypes.c_size_t),  # public key size
        ctypes.c_void_p,      # secret key out
        ctypes.POINTER(ctypes.c_size_t),  # secret key size
    ]
    lib.quac100_kem_keygen.restype = ctypes.c_int
    
    lib.quac100_kem_encaps.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # public key
        ctypes.c_size_t,      # public key size
        ctypes.c_void_p,      # ciphertext out
        ctypes.POINTER(ctypes.c_size_t),  # ciphertext size
        ctypes.c_void_p,      # shared secret out
        ctypes.POINTER(ctypes.c_size_t),  # shared secret size
    ]
    lib.quac100_kem_encaps.restype = ctypes.c_int
    
    lib.quac100_kem_decaps.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # secret key
        ctypes.c_size_t,      # secret key size
        ctypes.c_void_p,      # ciphertext
        ctypes.c_size_t,      # ciphertext size
        ctypes.c_void_p,      # shared secret out
        ctypes.POINTER(ctypes.c_size_t),  # shared secret size
    ]
    lib.quac100_kem_decaps.restype = ctypes.c_int
    
    # Sign operations
    lib.quac100_sign_keygen.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # public key out
        ctypes.POINTER(ctypes.c_size_t),  # public key size
        ctypes.c_void_p,      # secret key out
        ctypes.POINTER(ctypes.c_size_t),  # secret key size
    ]
    lib.quac100_sign_keygen.restype = ctypes.c_int
    
    lib.quac100_sign.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # secret key
        ctypes.c_size_t,      # secret key size
        ctypes.c_void_p,      # message
        ctypes.c_size_t,      # message size
        ctypes.c_void_p,      # signature out
        ctypes.POINTER(ctypes.c_size_t),  # signature size
    ]
    lib.quac100_sign.restype = ctypes.c_int
    
    lib.quac100_verify.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # public key
        ctypes.c_size_t,      # public key size
        ctypes.c_void_p,      # message
        ctypes.c_size_t,      # message size
        ctypes.c_void_p,      # signature
        ctypes.c_size_t,      # signature size
    ]
    lib.quac100_verify.restype = ctypes.c_int
    
    # Hash operations
    lib.quac100_hash.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_int,         # algorithm
        ctypes.c_void_p,      # input
        ctypes.c_size_t,      # input size
        ctypes.c_void_p,      # output
        ctypes.c_size_t,      # output size
    ]
    lib.quac100_hash.restype = ctypes.c_int
    
    # Random operations
    lib.quac100_random_bytes.argtypes = [
        ctypes.c_void_p,      # device handle
        ctypes.c_void_p,      # output
        ctypes.c_size_t,      # size
    ]
    lib.quac100_random_bytes.restype = ctypes.c_int


# C structure definitions for complex return types
class DeviceInfoStruct(ctypes.Structure):
    """C structure for device information."""
    _fields_ = [
        ("index", ctypes.c_int),
        ("model", ctypes.c_char * 64),
        ("serial", ctypes.c_char * 32),
        ("firmware", ctypes.c_char * 32),
        ("key_slots", ctypes.c_int),
    ]


class DeviceStatusStruct(ctypes.Structure):
    """C structure for device status."""
    _fields_ = [
        ("temperature", ctypes.c_float),
        ("entropy_level", ctypes.c_int),
        ("operation_count", ctypes.c_uint64),
        ("is_healthy", ctypes.c_bool),
        ("last_error", ctypes.c_int),
    ]


class EntropyStatusStruct(ctypes.Structure):
    """C structure for entropy status."""
    _fields_ = [
        ("level", ctypes.c_int),
        ("is_healthy", ctypes.c_bool),
        ("total_generated", ctypes.c_uint64),
        ("generation_rate", ctypes.c_float),
    ]