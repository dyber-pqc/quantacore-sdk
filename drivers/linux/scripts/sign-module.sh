#!/bin/bash
#=============================================================================
# QUAC 100 Module Signing Script
#
# Signs the kernel module for Secure Boot compatibility.
#
# Usage: sudo ./sign-module.sh [options]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

set -e

#-----------------------------------------------------------------------------
# Configuration
#-----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${DRIVER_DIR}/keys"

MODULE_NAME="quac100"
SIGN_KEY="${KEYS_DIR}/signing_key.pem"
SIGN_CERT="${KEYS_DIR}/signing_key.x509"
SIGN_DER="${KEYS_DIR}/signing_key.der"

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
QUAC 100 Module Signing Script

Usage: sudo $(basename "$0") [options]

Options:
    -h, --help           Show this help message
    --generate-keys      Generate new signing keys
    --key FILE           Path to private key file
    --cert FILE          Path to certificate file
    --module FILE        Path to module file (auto-detect if not specified)
    --enroll             Enroll key with MOK after generation
    --check              Check if module is already signed
    --verify             Verify module signature
    -k, --kernel VER     Sign module for specific kernel

Key Management:
    --export-cert        Export certificate for MOK enrollment
    --show-fingerprint   Show certificate fingerprint
    --list-mok           List enrolled MOK keys

Examples:
    sudo $(basename "$0") --generate-keys       # Generate signing keys
    sudo $(basename "$0")                       # Sign module (auto-detect)
    sudo $(basename "$0") --enroll              # Generate keys and enroll
    sudo $(basename "$0") --check               # Check signature status

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

GENERATE_KEYS=false
ENROLL_KEY=false
CHECK_ONLY=false
VERIFY_ONLY=false
EXPORT_CERT=false
SHOW_FINGERPRINT=false
LIST_MOK=false
MODULE_FILE=""
KERNEL_VER="$(uname -r)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        --generate-keys) GENERATE_KEYS=true; shift ;;
        --key) SIGN_KEY="$2"; shift 2 ;;
        --cert) SIGN_CERT="$2"; shift 2 ;;
        --module) MODULE_FILE="$2"; shift 2 ;;
        --enroll) ENROLL_KEY=true; GENERATE_KEYS=true; shift ;;
        --check) CHECK_ONLY=true; shift ;;
        --verify) VERIFY_ONLY=true; shift ;;
        -k|--kernel) KERNEL_VER="$2"; shift 2 ;;
        --export-cert) EXPORT_CERT=true; shift ;;
        --show-fingerprint) SHOW_FINGERPRINT=true; shift ;;
        --list-mok) LIST_MOK=true; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

#-----------------------------------------------------------------------------
# Find Module
#-----------------------------------------------------------------------------

find_module() {
    if [ -n "$MODULE_FILE" ] && [ -f "$MODULE_FILE" ]; then
        echo "$MODULE_FILE"
        return 0
    fi
    
    # Search in common locations
    local search_paths=(
        "/lib/modules/${KERNEL_VER}/updates/dkms/${MODULE_NAME}.ko"
        "/lib/modules/${KERNEL_VER}/updates/dkms/${MODULE_NAME}.ko.xz"
        "/lib/modules/${KERNEL_VER}/updates/dkms/${MODULE_NAME}.ko.zst"
        "/lib/modules/${KERNEL_VER}/extra/${MODULE_NAME}.ko"
        "/lib/modules/${KERNEL_VER}/extra/${MODULE_NAME}.ko.xz"
        "/lib/modules/${KERNEL_VER}/extra/${MODULE_NAME}.ko.zst"
        "${DRIVER_DIR}/src/${MODULE_NAME}.ko"
    )
    
    for path in "${search_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    # Try find
    local found=$(find /lib/modules/${KERNEL_VER} -name "${MODULE_NAME}.ko*" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "$found"
        return 0
    fi
    
    return 1
}

#-----------------------------------------------------------------------------
# Check Prerequisites
#-----------------------------------------------------------------------------

check_prerequisites() {
    local missing=()
    
    for cmd in openssl; do
        if ! command -v $cmd &>/dev/null; then
            missing+=($cmd)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
    
    # Find sign-file
    SIGN_FILE=""
    if [ -f "/lib/modules/${KERNEL_VER}/build/scripts/sign-file" ]; then
        SIGN_FILE="/lib/modules/${KERNEL_VER}/build/scripts/sign-file"
    elif [ -f "/usr/src/linux-headers-${KERNEL_VER}/scripts/sign-file" ]; then
        SIGN_FILE="/usr/src/linux-headers-${KERNEL_VER}/scripts/sign-file"
    fi
    
    if [ -z "$SIGN_FILE" ] && ! $GENERATE_KEYS && ! $CHECK_ONLY && ! $LIST_MOK; then
        log_error "Cannot find sign-file script"
        echo "Install kernel headers: linux-headers-${KERNEL_VER}"
        exit 1
    fi
}

#-----------------------------------------------------------------------------
# Generate Keys
#-----------------------------------------------------------------------------

generate_keys() {
    log_info "Generating signing keys..."
    
    mkdir -p "${KEYS_DIR}"
    
    # Check if keys already exist
    if [ -f "$SIGN_KEY" ]; then
        log_warn "Signing key already exists: $SIGN_KEY"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing keys"
            return 0
        fi
    fi
    
    # Create OpenSSL config
    local config=$(mktemp)
    cat > "$config" << EOF
[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[ req_distinguished_name ]
CN = QUAC 100 Module Signing Key
O = Dyber Inc
OU = QuantaCore SDK

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
EOF

    # Generate key pair
    openssl req -new -x509 -newkey rsa:4096 \
        -keyout "$SIGN_KEY" \
        -out "$SIGN_CERT" \
        -days 3650 \
        -nodes \
        -config "$config"
    
    rm -f "$config"
    
    # Set permissions
    chmod 600 "$SIGN_KEY"
    chmod 644 "$SIGN_CERT"
    
    # Convert to DER format for MOK enrollment
    openssl x509 -in "$SIGN_CERT" -outform DER -out "$SIGN_DER"
    chmod 644 "$SIGN_DER"
    
    log_success "Signing keys generated"
    echo ""
    echo "Files created:"
    echo "  Private key: $SIGN_KEY"
    echo "  Certificate: $SIGN_CERT"
    echo "  DER format:  $SIGN_DER"
    echo ""
    
    # Show fingerprint
    show_fingerprint
}

#-----------------------------------------------------------------------------
# Enroll Key with MOK
#-----------------------------------------------------------------------------

enroll_mok() {
    log_info "Enrolling key with MOK..."
    
    if ! command -v mokutil &>/dev/null; then
        log_error "mokutil not found"
        echo "Install with: sudo apt-get install mokutil"
        exit 1
    fi
    
    if [ ! -f "$SIGN_DER" ]; then
        log_error "DER certificate not found: $SIGN_DER"
        exit 1
    fi
    
    echo ""
    echo "You will be prompted to create a password."
    echo "Remember this password - you'll need it during the next boot."
    echo ""
    
    if mokutil --import "$SIGN_DER"; then
        log_success "Key enrolled with MOK"
        echo ""
        echo "IMPORTANT: To complete enrollment:"
        echo "  1. Reboot your system"
        echo "  2. MOK Manager will appear during boot"
        echo "  3. Select 'Enroll MOK' -> 'Continue'"
        echo "  4. Enter the password you just created"
        echo "  5. Select 'Reboot'"
        echo ""
    else
        log_error "Failed to enroll key"
        exit 1
    fi
}

#-----------------------------------------------------------------------------
# Sign Module
#-----------------------------------------------------------------------------

sign_module() {
    local module_path="$1"
    
    log_info "Signing module: $module_path"
    
    # Check if keys exist
    if [ ! -f "$SIGN_KEY" ] || [ ! -f "$SIGN_CERT" ]; then
        log_error "Signing keys not found"
        echo "Generate keys with: $0 --generate-keys"
        exit 1
    fi
    
    # Decompress if needed
    local temp_module=""
    if [[ "$module_path" == *.xz ]]; then
        log_info "Decompressing module..."
        temp_module="${module_path%.xz}"
        xz -dk "$module_path"
        module_path="$temp_module"
    elif [[ "$module_path" == *.zst ]]; then
        log_info "Decompressing module..."
        temp_module="${module_path%.zst}"
        zstd -dk "$module_path"
        module_path="$temp_module"
    fi
    
    # Sign
    if "$SIGN_FILE" sha256 "$SIGN_KEY" "$SIGN_CERT" "$module_path"; then
        log_success "Module signed successfully"
        
        # Re-compress if needed
        if [ -n "$temp_module" ]; then
            if [[ "$1" == *.xz ]]; then
                xz -f "$module_path"
            elif [[ "$1" == *.zst ]]; then
                zstd -f "$module_path"
                rm -f "$module_path"
            fi
        fi
    else
        log_error "Failed to sign module"
        [ -n "$temp_module" ] && rm -f "$temp_module"
        exit 1
    fi
}

#-----------------------------------------------------------------------------
# Check Module Signature
#-----------------------------------------------------------------------------

check_signature() {
    local module_path="$1"
    
    log_info "Checking module signature: $module_path"
    
    # Check for signature
    if modinfo "$module_path" 2>/dev/null | grep -q "^sig_id:"; then
        local sig_id=$(modinfo "$module_path" 2>/dev/null | grep "^sig_id:" | awk '{print $2}')
        local signer=$(modinfo "$module_path" 2>/dev/null | grep "^signer:" | cut -d: -f2-)
        
        log_success "Module is signed"
        echo "  Signature ID: $sig_id"
        echo "  Signer: $signer"
        return 0
    else
        log_warn "Module is NOT signed"
        return 1
    fi
}

#-----------------------------------------------------------------------------
# Verify Module Signature
#-----------------------------------------------------------------------------

verify_signature() {
    local module_path="$1"
    
    log_info "Verifying module signature: $module_path"
    
    # Check signature presence first
    if ! check_signature "$module_path"; then
        exit 1
    fi
    
    # Try to load to verify
    log_info "Testing module loading..."
    
    if modprobe "${MODULE_NAME}" 2>/dev/null; then
        modprobe -r "${MODULE_NAME}" 2>/dev/null
        log_success "Module signature verified (loads successfully)"
        return 0
    else
        log_warn "Module failed to load (signature may not be trusted)"
        return 1
    fi
}

#-----------------------------------------------------------------------------
# Show Fingerprint
#-----------------------------------------------------------------------------

show_fingerprint() {
    if [ ! -f "$SIGN_CERT" ]; then
        log_error "Certificate not found: $SIGN_CERT"
        return 1
    fi
    
    log_info "Certificate fingerprint:"
    openssl x509 -in "$SIGN_CERT" -fingerprint -sha256 -noout
    echo ""
    
    log_info "Certificate subject:"
    openssl x509 -in "$SIGN_CERT" -subject -noout
}

#-----------------------------------------------------------------------------
# Export Certificate
#-----------------------------------------------------------------------------

export_cert() {
    if [ ! -f "$SIGN_CERT" ]; then
        log_error "Certificate not found: $SIGN_CERT"
        return 1
    fi
    
    local output_dir="${HOME}/quac100-signing-cert"
    mkdir -p "$output_dir"
    
    cp "$SIGN_CERT" "${output_dir}/"
    cp "$SIGN_DER" "${output_dir}/" 2>/dev/null || \
        openssl x509 -in "$SIGN_CERT" -outform DER -out "${output_dir}/signing_key.der"
    
    log_success "Certificate exported to: $output_dir"
    echo ""
    echo "To enroll on another machine:"
    echo "  sudo mokutil --import ${output_dir}/signing_key.der"
}

#-----------------------------------------------------------------------------
# List MOK Keys
#-----------------------------------------------------------------------------

list_mok() {
    if ! command -v mokutil &>/dev/null; then
        log_error "mokutil not found"
        exit 1
    fi
    
    log_info "Secure Boot status:"
    mokutil --sb-state 2>/dev/null || echo "Unable to determine"
    echo ""
    
    log_info "Enrolled MOK keys:"
    mokutil --list-enrolled 2>/dev/null || echo "No keys enrolled"
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    echo "========================================"
    echo " QUAC 100 Module Signing Tool"
    echo "========================================"
    echo ""
    
    check_prerequisites
    
    if $LIST_MOK; then
        list_mok
        exit 0
    fi
    
    if $SHOW_FINGERPRINT; then
        show_fingerprint
        exit 0
    fi
    
    if $EXPORT_CERT; then
        export_cert
        exit 0
    fi
    
    if $GENERATE_KEYS; then
        check_root
        generate_keys
        
        if $ENROLL_KEY; then
            enroll_mok
        fi
        exit 0
    fi
    
    # Find module
    local module=$(find_module)
    if [ -z "$module" ]; then
        log_error "Cannot find module for kernel ${KERNEL_VER}"
        echo "Build the module first or specify --module FILE"
        exit 1
    fi
    
    log_info "Found module: $module"
    
    if $CHECK_ONLY; then
        check_signature "$module"
        exit $?
    fi
    
    if $VERIFY_ONLY; then
        verify_signature "$module"
        exit $?
    fi
    
    # Sign module
    check_root
    sign_module "$module"
    
    echo ""
    check_signature "$module"
    
    echo ""
    log_success "Module signing complete!"
}

main "$@"