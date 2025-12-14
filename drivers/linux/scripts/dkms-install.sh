#!/bin/bash
#=============================================================================
# QUAC 100 DKMS Installation Script
#
# Registers and builds the QUAC 100 driver using DKMS for automatic
# kernel module management.
#
# Usage: sudo ./dkms-install.sh [options]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

set -e

#-----------------------------------------------------------------------------
# Configuration
#-----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="${DRIVER_DIR}/src"
DKMS_DIR="${DRIVER_DIR}/dkms"

MODULE_NAME="quac100"
MODULE_VERSION="1.0.0"
DKMS_SRC="/usr/src/${MODULE_NAME}-${MODULE_VERSION}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#-----------------------------------------------------------------------------
# Helper Functions
#-----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Try: sudo $0"
        exit 1
    fi
}

usage() {
    cat << EOF
QUAC 100 DKMS Installation Script

Usage: sudo $(basename "$0") [options]

Options:
    -h, --help          Show this help message
    -v, --version VER   Specify module version (default: ${MODULE_VERSION})
    -k, --kernel VER    Build for specific kernel version
    --all-kernels       Build for all installed kernels
    --no-load           Don't load module after installation
    --force             Force reinstall if already installed
    -y, --yes           Assume yes to all prompts

Examples:
    sudo $(basename "$0")                     # Install for current kernel
    sudo $(basename "$0") --all-kernels       # Install for all kernels
    sudo $(basename "$0") -k 5.15.0-generic   # Install for specific kernel

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

SPECIFIC_KERNEL=""
ALL_KERNELS=false
LOAD_MODULE=true
FORCE_INSTALL=false
ASSUME_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -v|--version) MODULE_VERSION="$2"; DKMS_SRC="/usr/src/${MODULE_NAME}-${MODULE_VERSION}"; shift 2 ;;
        -k|--kernel) SPECIFIC_KERNEL="$2"; shift 2 ;;
        --all-kernels) ALL_KERNELS=true; shift ;;
        --no-load) LOAD_MODULE=false; shift ;;
        --force) FORCE_INSTALL=true; shift ;;
        -y|--yes) ASSUME_YES=true; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

#-----------------------------------------------------------------------------
# Check Prerequisites
#-----------------------------------------------------------------------------

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=()
    
    # Check for DKMS
    if ! command -v dkms &>/dev/null; then
        missing+=("dkms")
    fi
    
    # Check for kernel headers
    local kernel_ver="${SPECIFIC_KERNEL:-$(uname -r)}"
    if [ ! -d "/lib/modules/${kernel_ver}/build" ] && [ ! -d "/usr/src/linux-headers-${kernel_ver}" ]; then
        missing+=("linux-headers-${kernel_ver}")
    fi
    
    # Check for build tools
    if ! command -v gcc &>/dev/null; then
        missing+=("gcc")
    fi
    
    if ! command -v make &>/dev/null; then
        missing+=("make")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Install with:"
        if command -v apt-get &>/dev/null; then
            echo "  sudo apt-get install ${missing[*]}"
        elif command -v dnf &>/dev/null; then
            echo "  sudo dnf install ${missing[*]}"
        elif command -v yum &>/dev/null; then
            echo "  sudo yum install ${missing[*]}"
        fi
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

#-----------------------------------------------------------------------------
# Check Existing Installation
#-----------------------------------------------------------------------------

check_existing() {
    if dkms status "${MODULE_NAME}/${MODULE_VERSION}" &>/dev/null; then
        local status=$(dkms status "${MODULE_NAME}/${MODULE_VERSION}")
        if [ -n "$status" ]; then
            log_warn "QUAC 100 DKMS module already registered:"
            echo "  $status"
            
            if ! $FORCE_INSTALL; then
                if $ASSUME_YES; then
                    log_info "Removing existing installation..."
                else
                    read -p "Remove existing installation? [y/N] " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        log_info "Installation cancelled"
                        exit 0
                    fi
                fi
            fi
            
            # Remove existing installation
            log_info "Removing existing DKMS registration..."
            dkms remove "${MODULE_NAME}/${MODULE_VERSION}" --all 2>/dev/null || true
        fi
    fi
    
    # Remove old source directory if exists
    if [ -d "${DKMS_SRC}" ]; then
        log_info "Removing old source directory..."
        rm -rf "${DKMS_SRC}"
    fi
}

#-----------------------------------------------------------------------------
# Copy Source Files
#-----------------------------------------------------------------------------

copy_source() {
    log_info "Copying source files to ${DKMS_SRC}..."
    
    mkdir -p "${DKMS_SRC}"
    
    # Copy source files
    cp "${SRC_DIR}/"*.c "${DKMS_SRC}/" 2>/dev/null || true
    cp "${SRC_DIR}/"*.h "${DKMS_SRC}/" 2>/dev/null || true
    cp "${SRC_DIR}/Makefile" "${DKMS_SRC}/" 2>/dev/null || true
    cp "${SRC_DIR}/Kbuild" "${DKMS_SRC}/" 2>/dev/null || true
    
    # Copy DKMS config
    cp "${DKMS_DIR}/dkms.conf" "${DKMS_SRC}/"
    
    # Update version in dkms.conf
    sed -i "s/PACKAGE_VERSION=\"[^\"]*\"/PACKAGE_VERSION=\"${MODULE_VERSION}\"/" "${DKMS_SRC}/dkms.conf"
    
    # Set permissions
    chmod 644 "${DKMS_SRC}/"*
    
    log_success "Source files copied"
}

#-----------------------------------------------------------------------------
# DKMS Registration
#-----------------------------------------------------------------------------

register_dkms() {
    log_info "Registering module with DKMS..."
    
    if ! dkms add -m "${MODULE_NAME}" -v "${MODULE_VERSION}"; then
        log_error "Failed to register with DKMS"
        exit 1
    fi
    
    log_success "Module registered with DKMS"
}

#-----------------------------------------------------------------------------
# Build Module
#-----------------------------------------------------------------------------

build_module() {
    local kernel_ver="$1"
    
    log_info "Building module for kernel ${kernel_ver}..."
    
    if dkms build -m "${MODULE_NAME}" -v "${MODULE_VERSION}" -k "${kernel_ver}"; then
        log_success "Build successful for kernel ${kernel_ver}"
        return 0
    else
        log_error "Build failed for kernel ${kernel_ver}"
        return 1
    fi
}

#-----------------------------------------------------------------------------
# Install Module
#-----------------------------------------------------------------------------

install_module() {
    local kernel_ver="$1"
    
    log_info "Installing module for kernel ${kernel_ver}..."
    
    if dkms install -m "${MODULE_NAME}" -v "${MODULE_VERSION}" -k "${kernel_ver}" --force; then
        log_success "Installation successful for kernel ${kernel_ver}"
        return 0
    else
        log_error "Installation failed for kernel ${kernel_ver}"
        return 1
    fi
}

#-----------------------------------------------------------------------------
# Load Module
#-----------------------------------------------------------------------------

load_module() {
    if ! $LOAD_MODULE; then
        return
    fi
    
    # Only load if installing for current kernel
    if [ -n "$SPECIFIC_KERNEL" ] && [ "$SPECIFIC_KERNEL" != "$(uname -r)" ]; then
        return
    fi
    
    log_info "Loading module..."
    
    # Unload if already loaded
    if lsmod | grep -q "^${MODULE_NAME}"; then
        modprobe -r "${MODULE_NAME}" 2>/dev/null || true
    fi
    
    if modprobe "${MODULE_NAME}"; then
        log_success "Module loaded"
    else
        log_warn "Could not load module (hardware may not be present)"
    fi
}

#-----------------------------------------------------------------------------
# Show Status
#-----------------------------------------------------------------------------

show_status() {
    echo ""
    echo "========================================"
    echo " DKMS Installation Status"
    echo "========================================"
    echo ""
    dkms status "${MODULE_NAME}"
    echo ""
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        echo "Module loaded: Yes"
        modinfo "${MODULE_NAME}" | grep -E "^(version|filename):"
    else
        echo "Module loaded: No"
    fi
    
    echo ""
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    echo "========================================"
    echo " QUAC 100 DKMS Installation"
    echo " Version: ${MODULE_VERSION}"
    echo "========================================"
    echo ""
    
    check_root
    check_prerequisites
    check_existing
    copy_source
    register_dkms
    
    local failed_kernels=()
    
    if $ALL_KERNELS; then
        # Build for all installed kernels
        for kernel_dir in /lib/modules/*/build; do
            if [ -d "$kernel_dir" ]; then
                local kernel_ver=$(basename $(dirname "$kernel_dir"))
                build_module "$kernel_ver" && install_module "$kernel_ver" || failed_kernels+=("$kernel_ver")
            fi
        done
    elif [ -n "$SPECIFIC_KERNEL" ]; then
        # Build for specific kernel
        build_module "$SPECIFIC_KERNEL" && install_module "$SPECIFIC_KERNEL" || failed_kernels+=("$SPECIFIC_KERNEL")
    else
        # Build for current kernel
        local current_kernel=$(uname -r)
        build_module "$current_kernel" && install_module "$current_kernel" || failed_kernels+=("$current_kernel")
    fi
    
    load_module
    
    show_status
    
    if [ ${#failed_kernels[@]} -gt 0 ]; then
        log_warn "Failed to build/install for kernels: ${failed_kernels[*]}"
        exit 1
    fi
    
    log_success "DKMS installation complete!"
}

main "$@"