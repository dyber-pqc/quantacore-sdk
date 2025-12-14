#!/bin/bash
#
# QUAC 100 Post-Quantum Cryptographic Accelerator - Uninstall Script
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# Document: QUAC100-SDK-DEV-001
#
# This script removes the QUAC 100 kernel driver, udev rules, and
# associated system configuration.
#
# Usage: sudo ./uninstall.sh [--purge]
#
# Options:
#   --purge    Remove all configuration files and logs
#

set -e

# Script configuration
SCRIPT_NAME="$(basename "$0")"
DRIVER_NAME="quac100"
MODULE_NAME="quac100"
SERVICE_NAME="quac100.service"

# Installation paths
UDEV_RULES_DIR="/etc/udev/rules.d"
UDEV_RULES_FILE="99-quac100.rules"
SYSTEMD_DIR="/etc/systemd/system"
MODULE_DIR="/lib/modules/$(uname -r)"
FIRMWARE_DIR="/lib/firmware/quac100"
CONFIG_DIR="/etc/quac100"
LOG_DIR="/var/log/quac100"
SYSCONFIG_FILE="/etc/sysconfig/quac100"
DEFAULT_FILE="/etc/default/quac100"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Parse command line arguments
PURGE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --purge)
            PURGE=1
            shift
            ;;
        -h|--help)
            echo "Usage: sudo $SCRIPT_NAME [--purge]"
            echo ""
            echo "Uninstall the QUAC 100 kernel driver and related components."
            echo ""
            echo "Options:"
            echo "  --purge    Remove all configuration files and logs"
            echo "  -h, --help Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Print banner
print_banner() {
    echo ""
    echo "========================================================"
    echo "  QUAC 100 Post-Quantum Cryptographic Accelerator"
    echo "  Driver Uninstall Script"
    echo "  Copyright 2025 Dyber, Inc."
    echo "========================================================"
    echo ""
}

# Stop and disable systemd service
stop_service() {
    log_info "Stopping QUAC 100 service..."
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME" || true
        log_success "Service stopped"
    else
        log_info "Service was not running"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" || true
        log_success "Service disabled"
    fi
}

# Unload kernel module
unload_module() {
    log_info "Unloading kernel module..."
    
    # Check if module is loaded
    if lsmod | grep -q "^${MODULE_NAME}"; then
        # Check for users of the module
        local users
        users=$(lsmod | grep "^${MODULE_NAME}" | awk '{print $3}')
        
        if [[ "$users" != "0" && -n "$users" ]]; then
            log_warning "Module is in use by $users processes"
            log_info "Attempting to force unload..."
        fi
        
        if rmmod "$MODULE_NAME" 2>/dev/null; then
            log_success "Kernel module unloaded"
        else
            log_warning "Could not unload module (may require reboot)"
        fi
    else
        log_info "Kernel module was not loaded"
    fi
}

# Remove kernel module files
remove_module() {
    log_info "Removing kernel module files..."
    
    local removed=0
    
    # Remove from standard locations
    for dir in "$MODULE_DIR/extra" "$MODULE_DIR/kernel/drivers/crypto" "$MODULE_DIR/updates"; do
        if [[ -f "$dir/${MODULE_NAME}.ko" ]]; then
            rm -f "$dir/${MODULE_NAME}.ko"
            rm -f "$dir/${MODULE_NAME}.ko.xz"
            rm -f "$dir/${MODULE_NAME}.ko.zst"
            log_success "Removed module from $dir"
            removed=1
        fi
    done
    
    # Remove DKMS module if present
    if command -v dkms &>/dev/null; then
        if dkms status | grep -q "$MODULE_NAME"; then
            log_info "Removing DKMS module..."
            local version
            version=$(dkms status "$MODULE_NAME" | head -1 | awk -F'[,:]' '{print $2}' | tr -d ' ')
            if [[ -n "$version" ]]; then
                dkms remove -m "$MODULE_NAME" -v "$version" --all 2>/dev/null || true
                log_success "DKMS module removed"
            fi
        fi
    fi
    
    # Remove DKMS source directory
    if [[ -d "/usr/src/${MODULE_NAME}-"* ]]; then
        rm -rf /usr/src/${MODULE_NAME}-*
        log_success "Removed DKMS source directory"
    fi
    
    # Update module dependencies
    log_info "Updating module dependencies..."
    depmod -a
    
    if [[ $removed -eq 0 ]]; then
        log_info "No module files found to remove"
    fi
}

# Remove udev rules
remove_udev_rules() {
    log_info "Removing udev rules..."
    
    if [[ -f "$UDEV_RULES_DIR/$UDEV_RULES_FILE" ]]; then
        rm -f "$UDEV_RULES_DIR/$UDEV_RULES_FILE"
        log_success "Removed $UDEV_RULES_FILE"
        
        # Reload udev rules
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
    else
        log_info "Udev rules file not found"
    fi
}

# Remove systemd service file
remove_service() {
    log_info "Removing systemd service..."
    
    if [[ -f "$SYSTEMD_DIR/$SERVICE_NAME" ]]; then
        rm -f "$SYSTEMD_DIR/$SERVICE_NAME"
        systemctl daemon-reload
        log_success "Removed systemd service file"
    else
        log_info "Systemd service file not found"
    fi
}

# Remove firmware files
remove_firmware() {
    log_info "Removing firmware files..."
    
    if [[ -d "$FIRMWARE_DIR" ]]; then
        rm -rf "$FIRMWARE_DIR"
        log_success "Removed firmware directory"
    else
        log_info "Firmware directory not found"
    fi
}

# Remove configuration files (only with --purge)
remove_config() {
    if [[ $PURGE -eq 1 ]]; then
        log_info "Removing configuration files (purge mode)..."
        
        # Remove config directory
        if [[ -d "$CONFIG_DIR" ]]; then
            rm -rf "$CONFIG_DIR"
            log_success "Removed configuration directory: $CONFIG_DIR"
        fi
        
        # Remove sysconfig/default files
        if [[ -f "$SYSCONFIG_FILE" ]]; then
            rm -f "$SYSCONFIG_FILE"
            log_success "Removed $SYSCONFIG_FILE"
        fi
        
        if [[ -f "$DEFAULT_FILE" ]]; then
            rm -f "$DEFAULT_FILE"
            log_success "Removed $DEFAULT_FILE"
        fi
        
        # Remove log directory
        if [[ -d "$LOG_DIR" ]]; then
            rm -rf "$LOG_DIR"
            log_success "Removed log directory: $LOG_DIR"
        fi
        
        # Remove modprobe configuration
        if [[ -f "/etc/modprobe.d/quac100.conf" ]]; then
            rm -f "/etc/modprobe.d/quac100.conf"
            log_success "Removed modprobe configuration"
        fi
        
        # Remove modules-load configuration
        if [[ -f "/etc/modules-load.d/quac100.conf" ]]; then
            rm -f "/etc/modules-load.d/quac100.conf"
            log_success "Removed modules-load configuration"
        fi
    else
        log_info "Configuration files preserved (use --purge to remove)"
    fi
}

# Remove quac100 group if empty
remove_group() {
    log_info "Checking quac100 group..."
    
    if getent group quac100 &>/dev/null; then
        # Check if any users are in the group
        local members
        members=$(getent group quac100 | cut -d: -f4)
        
        if [[ -z "$members" ]]; then
            if [[ $PURGE -eq 1 ]]; then
                groupdel quac100 2>/dev/null || true
                log_success "Removed quac100 group"
            else
                log_info "quac100 group preserved (use --purge to remove)"
            fi
        else
            log_warning "quac100 group has members ($members), not removing"
        fi
    else
        log_info "quac100 group not found"
    fi
}

# Clean up device nodes
cleanup_devices() {
    log_info "Cleaning up device nodes..."
    
    # Remove any stale device nodes
    for dev in /dev/quac100_*; do
        if [[ -e "$dev" ]]; then
            rm -f "$dev"
            log_success "Removed stale device node: $dev"
        fi
    done
}

# Remove SDK libraries and headers (optional)
remove_sdk() {
    log_info "Checking for SDK installation..."
    
    local sdk_removed=0
    
    # Check standard library locations
    for lib in /usr/lib/libquac100.so* /usr/lib64/libquac100.so* /usr/local/lib/libquac100.so*; do
        if [[ -e "$lib" ]]; then
            rm -f "$lib"
            sdk_removed=1
        fi
    done
    
    # Check header locations
    for header_dir in /usr/include/quac100 /usr/local/include/quac100; do
        if [[ -d "$header_dir" ]]; then
            rm -rf "$header_dir"
            sdk_removed=1
        fi
    done
    
    # Remove pkg-config file
    for pc in /usr/lib/pkgconfig/quac100.pc /usr/lib64/pkgconfig/quac100.pc /usr/local/lib/pkgconfig/quac100.pc; do
        if [[ -f "$pc" ]]; then
            rm -f "$pc"
            sdk_removed=1
        fi
    done
    
    if [[ $sdk_removed -eq 1 ]]; then
        ldconfig 2>/dev/null || true
        log_success "SDK libraries and headers removed"
    else
        log_info "SDK libraries not found in standard locations"
    fi
}

# Verify uninstallation
verify_uninstall() {
    log_info "Verifying uninstallation..."
    
    local errors=0
    
    # Check module is not loaded
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_warning "Kernel module is still loaded (reboot may be required)"
        errors=$((errors + 1))
    fi
    
    # Check service is not running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_warning "Service is still running"
        errors=$((errors + 1))
    fi
    
    # Check device nodes are removed
    if ls /dev/quac100_* 2>/dev/null | grep -q .; then
        log_warning "Device nodes still exist"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "Uninstallation verified successfully"
    else
        log_warning "$errors issue(s) found - reboot may be required"
    fi
    
    return $errors
}

# Main uninstallation sequence
main() {
    print_banner
    check_root
    
    log_info "Starting QUAC 100 driver uninstallation..."
    echo ""
    
    # Confirmation prompt
    if [[ $PURGE -eq 1 ]]; then
        log_warning "PURGE mode enabled - all configuration and logs will be removed!"
    fi
    
    read -p "Do you want to continue with uninstallation? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    echo ""
    
    # Uninstallation steps
    stop_service
    unload_module
    remove_module
    remove_udev_rules
    remove_service
    remove_firmware
    remove_config
    remove_group
    cleanup_devices
    remove_sdk
    
    echo ""
    verify_uninstall
    
    echo ""
    echo "========================================================"
    log_success "QUAC 100 driver uninstallation complete"
    echo "========================================================"
    echo ""
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_warning "A system reboot is recommended to complete removal"
    fi
}

# Run main function
main "$@"