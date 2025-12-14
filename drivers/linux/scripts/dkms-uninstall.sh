#!/bin/bash
#=============================================================================
# QUAC 100 DKMS Uninstallation Script
#
# Removes the QUAC 100 driver from DKMS and unloads the module.
#
# Usage: sudo ./dkms-uninstall.sh [options]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

set -e

#-----------------------------------------------------------------------------
# Configuration
#-----------------------------------------------------------------------------

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
QUAC 100 DKMS Uninstallation Script

Usage: sudo $(basename "$0") [options]

Options:
    -h, --help          Show this help message
    -v, --version VER   Specify module version (default: ${MODULE_VERSION})
    -k, --kernel VER    Remove from specific kernel only
    --all               Remove from all kernels (default)
    --keep-source       Keep source directory
    -y, --yes           Assume yes to all prompts

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

SPECIFIC_KERNEL=""
REMOVE_ALL=true
KEEP_SOURCE=false
ASSUME_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -v|--version) MODULE_VERSION="$2"; DKMS_SRC="/usr/src/${MODULE_NAME}-${MODULE_VERSION}"; shift 2 ;;
        -k|--kernel) SPECIFIC_KERNEL="$2"; REMOVE_ALL=false; shift 2 ;;
        --all) REMOVE_ALL=true; shift ;;
        --keep-source) KEEP_SOURCE=true; shift ;;
        -y|--yes) ASSUME_YES=true; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

#-----------------------------------------------------------------------------
# Confirm Action
#-----------------------------------------------------------------------------

confirm_action() {
    if $ASSUME_YES; then
        return 0
    fi
    
    echo ""
    echo "This will remove the QUAC 100 driver from DKMS."
    if $REMOVE_ALL; then
        echo "The module will be removed from all installed kernels."
    else
        echo "The module will be removed from kernel: ${SPECIFIC_KERNEL}"
    fi
    echo ""
    
    read -p "Continue? [y/N] " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
}

#-----------------------------------------------------------------------------
# Unload Module
#-----------------------------------------------------------------------------

unload_module() {
    log_info "Checking if module is loaded..."
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Unloading module..."
        
        # Try graceful unload
        if modprobe -r "${MODULE_NAME}" 2>/dev/null; then
            log_success "Module unloaded"
        else
            log_warn "Module is in use, forcing removal..."
            rmmod -f "${MODULE_NAME}" 2>/dev/null || true
        fi
    else
        log_info "Module not loaded"
    fi
}

#-----------------------------------------------------------------------------
# Check DKMS Status
#-----------------------------------------------------------------------------

check_dkms_status() {
    if ! command -v dkms &>/dev/null; then
        log_error "DKMS not found"
        exit 1
    fi
    
    local status=$(dkms status "${MODULE_NAME}/${MODULE_VERSION}" 2>/dev/null)
    
    if [ -z "$status" ]; then
        log_warn "Module not registered with DKMS"
        return 1
    fi
    
    log_info "Current DKMS status:"
    echo "  $status"
    return 0
}

#-----------------------------------------------------------------------------
# Remove from DKMS
#-----------------------------------------------------------------------------

remove_from_dkms() {
    log_info "Removing from DKMS..."
    
    if $REMOVE_ALL; then
        # Remove from all kernels
        if dkms remove "${MODULE_NAME}/${MODULE_VERSION}" --all 2>/dev/null; then
            log_success "Removed from all kernels"
        else
            log_warn "Could not remove from DKMS (may not be registered)"
        fi
    else
        # Remove from specific kernel
        if dkms remove "${MODULE_NAME}/${MODULE_VERSION}" -k "${SPECIFIC_KERNEL}" 2>/dev/null; then
            log_success "Removed from kernel ${SPECIFIC_KERNEL}"
        else
            log_warn "Could not remove from kernel ${SPECIFIC_KERNEL}"
        fi
    fi
}

#-----------------------------------------------------------------------------
# Clean Up
#-----------------------------------------------------------------------------

cleanup() {
    # Remove leftover module files
    log_info "Cleaning up module files..."
    
    find /lib/modules -name "${MODULE_NAME}.ko*" -delete 2>/dev/null || true
    
    # Update module dependencies
    depmod -a 2>/dev/null || true
    
    # Remove source directory
    if ! $KEEP_SOURCE; then
        if [ -d "${DKMS_SRC}" ]; then
            log_info "Removing source directory..."
            rm -rf "${DKMS_SRC}"
        fi
    else
        log_info "Keeping source directory: ${DKMS_SRC}"
    fi
    
    log_success "Cleanup complete"
}

#-----------------------------------------------------------------------------
# Show Status
#-----------------------------------------------------------------------------

show_status() {
    echo ""
    echo "========================================"
    echo " DKMS Uninstallation Status"
    echo "========================================"
    echo ""
    
    local status=$(dkms status "${MODULE_NAME}" 2>/dev/null)
    if [ -n "$status" ]; then
        echo "DKMS status: $status"
    else
        echo "DKMS status: Not registered"
    fi
    
    echo ""
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        echo "Module loaded: Yes (WARNING: should be unloaded)"
    else
        echo "Module loaded: No"
    fi
    
    if [ -d "${DKMS_SRC}" ]; then
        echo "Source directory: Present at ${DKMS_SRC}"
    else
        echo "Source directory: Removed"
    fi
    
    echo ""
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    echo "========================================"
    echo " QUAC 100 DKMS Uninstallation"
    echo " Version: ${MODULE_VERSION}"
    echo "========================================"
    echo ""
    
    check_root
    
    if check_dkms_status; then
        confirm_action
        unload_module
        remove_from_dkms
    else
        # Even if not in DKMS, try to unload and cleanup
        unload_module
    fi
    
    cleanup
    show_status
    
    log_success "DKMS uninstallation complete!"
}

main "$@"