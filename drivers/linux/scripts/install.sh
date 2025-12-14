#!/bin/bash
#=============================================================================
# QUAC 100 Driver Installation Script
#
# Comprehensive installation script that handles:
# - Dependency installation
# - Driver compilation
# - Module installation
# - Secure Boot signing (optional)
# - Configuration setup
# - Service enablement
#
# Usage: sudo ./install.sh [options]
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
KEYS_DIR="${DRIVER_DIR}/keys"

MODULE_NAME="quac100"
MODULE_VERSION="1.0.0"

# Installation paths
INSTALL_MODULE_DIR="/lib/modules/$(uname -r)/extra"
INSTALL_MODPROBE_DIR="/etc/modprobe.d"
INSTALL_UDEV_DIR="/etc/udev/rules.d"
INSTALL_SYSTEMD_DIR="/lib/systemd/system"
INSTALL_DOC_DIR="/usr/share/doc/${MODULE_NAME}"
INSTALL_SCRIPT_DIR="/usr/share/${MODULE_NAME}/scripts"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_step() {
    echo ""
    echo -e "${CYAN}>>> $1${NC}"
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
QUAC 100 Driver Installation Script

Usage: sudo $(basename "$0") [options]

Options:
    -h, --help          Show this help message
    --dkms              Use DKMS for installation (recommended)
    --no-dkms           Install directly without DKMS
    --sign              Sign module for Secure Boot
    --sign-key FILE     Path to signing key
    --sign-cert FILE    Path to signing certificate
    --skip-deps         Skip dependency installation
    --skip-config       Skip configuration file installation
    --skip-load         Don't load module after installation
    -y, --yes           Assume yes to all prompts

Examples:
    sudo $(basename "$0")                 # Standard installation with DKMS
    sudo $(basename "$0") --no-dkms       # Direct installation (no DKMS)
    sudo $(basename "$0") --sign          # Install and sign for Secure Boot

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

USE_DKMS=true
SIGN_MODULE=false
SIGN_KEY=""
SIGN_CERT=""
SKIP_DEPS=false
SKIP_CONFIG=false
LOAD_MODULE=true
ASSUME_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        --dkms) USE_DKMS=true; shift ;;
        --no-dkms) USE_DKMS=false; shift ;;
        --sign) SIGN_MODULE=true; shift ;;
        --sign-key) SIGN_KEY="$2"; shift 2 ;;
        --sign-cert) SIGN_CERT="$2"; shift 2 ;;
        --skip-deps) SKIP_DEPS=true; shift ;;
        --skip-config) SKIP_CONFIG=true; shift ;;
        --skip-load) LOAD_MODULE=false; shift ;;
        -y|--yes) ASSUME_YES=true; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

#-----------------------------------------------------------------------------
# Detect Distribution
#-----------------------------------------------------------------------------

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_VERSION="$VERSION_ID"
        DISTRO_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_NAME=$(cat /etc/redhat-release)
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown Distribution"
    fi
    
    log_info "Detected distribution: $DISTRO_NAME"
}

#-----------------------------------------------------------------------------
# Install Dependencies
#-----------------------------------------------------------------------------

install_dependencies() {
    if $SKIP_DEPS; then
        log_info "Skipping dependency installation"
        return
    fi
    
    log_step "Installing dependencies"
    
    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop)
            log_info "Installing dependencies for Debian-based system..."
            apt-get update -qq
            apt-get install -y \
                build-essential \
                linux-headers-$(uname -r) \
                dkms \
                mokutil \
                openssl
            ;;
        fedora|rhel|centos|rocky|almalinux)
            log_info "Installing dependencies for Red Hat-based system..."
            if command -v dnf &>/dev/null; then
                dnf install -y \
                    kernel-devel-$(uname -r) \
                    kernel-headers-$(uname -r) \
                    dkms \
                    gcc \
                    make \
                    mokutil \
                    openssl
            else
                yum install -y \
                    kernel-devel-$(uname -r) \
                    kernel-headers-$(uname -r) \
                    dkms \
                    gcc \
                    make \
                    mokutil \
                    openssl
            fi
            ;;
        arch|manjaro)
            log_info "Installing dependencies for Arch-based system..."
            pacman -S --noconfirm --needed \
                linux-headers \
                dkms \
                base-devel \
                openssl
            ;;
        opensuse*|suse*)
            log_info "Installing dependencies for SUSE-based system..."
            zypper install -y \
                kernel-default-devel \
                dkms \
                gcc \
                make \
                mokutil \
                openssl
            ;;
        *)
            log_warn "Unknown distribution. Please install these packages manually:"
            echo "  - kernel headers for $(uname -r)"
            echo "  - gcc, make, dkms"
            echo "  - mokutil, openssl (for Secure Boot)"
            if ! $ASSUME_YES; then
                read -p "Continue anyway? [y/N] " -n 1 -r
                echo
                [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
            fi
            ;;
    esac
    
    log_success "Dependencies installed"
}

#-----------------------------------------------------------------------------
# Check Secure Boot
#-----------------------------------------------------------------------------

check_secure_boot() {
    log_step "Checking Secure Boot status"
    
    if command -v mokutil &>/dev/null; then
        local sb_state=$(mokutil --sb-state 2>/dev/null || echo "Unknown")
        log_info "Secure Boot: $sb_state"
        
        if echo "$sb_state" | grep -qi "enabled"; then
            SECURE_BOOT_ENABLED=true
            
            if ! $SIGN_MODULE; then
                log_warn "Secure Boot is enabled!"
                echo ""
                echo "The module must be signed to load with Secure Boot enabled."
                echo "Options:"
                echo "  1. Sign the module (recommended)"
                echo "  2. Disable Secure Boot in BIOS"
                echo "  3. Install anyway (module may not load)"
                echo ""
                
                if ! $ASSUME_YES; then
                    read -p "Enable module signing? [Y/n] " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                        SIGN_MODULE=true
                    fi
                fi
            fi
        else
            SECURE_BOOT_ENABLED=false
        fi
    else
        log_info "Cannot determine Secure Boot status (mokutil not available)"
        SECURE_BOOT_ENABLED=false
    fi
}

#-----------------------------------------------------------------------------
# Generate Signing Keys
#-----------------------------------------------------------------------------

generate_signing_keys() {
    if [ -z "$SIGN_KEY" ] || [ -z "$SIGN_CERT" ]; then
        SIGN_KEY="${KEYS_DIR}/signing_key.pem"
        SIGN_CERT="${KEYS_DIR}/signing_key.x509"
        
        if [ ! -f "$SIGN_KEY" ] || [ ! -f "$SIGN_CERT" ]; then
            log_info "Generating signing keys..."
            
            mkdir -p "${KEYS_DIR}"
            
            # Generate self-signed certificate
            openssl req -new -x509 -newkey rsa:4096 \
                -keyout "$SIGN_KEY" \
                -out "$SIGN_CERT" \
                -days 3650 \
                -nodes \
                -subj "/CN=QUAC 100 Module Signing Key/O=Dyber Inc/OU=QuantaCore SDK"
            
            chmod 600 "$SIGN_KEY"
            chmod 644 "$SIGN_CERT"
            
            log_success "Signing keys generated"
            
            # Generate DER format for MOK enrollment
            local sign_der="${KEYS_DIR}/signing_key.der"
            openssl x509 -in "$SIGN_CERT" -outform DER -out "$sign_der"
            
            echo ""
            log_warn "You must enroll the signing key with MOK:"
            echo "  sudo mokutil --import ${sign_der}"
            echo ""
            echo "Then reboot and complete MOK enrollment."
            echo ""
        fi
    fi
}

#-----------------------------------------------------------------------------
# Sign Module
#-----------------------------------------------------------------------------

sign_module() {
    local module_path="$1"
    
    log_info "Signing module..."
    
    # Find sign-file script
    local sign_file=""
    if [ -f "/lib/modules/$(uname -r)/build/scripts/sign-file" ]; then
        sign_file="/lib/modules/$(uname -r)/build/scripts/sign-file"
    elif [ -f "/usr/src/linux-headers-$(uname -r)/scripts/sign-file" ]; then
        sign_file="/usr/src/linux-headers-$(uname -r)/scripts/sign-file"
    else
        log_error "Cannot find sign-file script"
        return 1
    fi
    
    if "$sign_file" sha256 "$SIGN_KEY" "$SIGN_CERT" "$module_path"; then
        log_success "Module signed"
    else
        log_error "Failed to sign module"
        return 1
    fi
}

#-----------------------------------------------------------------------------
# Build Module (Direct Installation)
#-----------------------------------------------------------------------------

build_module_direct() {
    log_step "Building kernel module"
    
    cd "${SRC_DIR}"
    
    # Clean first
    make clean 2>/dev/null || true
    
    # Build
    if make -j$(nproc); then
        log_success "Module built successfully"
    else
        log_error "Build failed"
        exit 1
    fi
    
    cd - >/dev/null
}

#-----------------------------------------------------------------------------
# Install Module (Direct Installation)
#-----------------------------------------------------------------------------

install_module_direct() {
    log_step "Installing kernel module"
    
    mkdir -p "${INSTALL_MODULE_DIR}"
    
    local module_path="${SRC_DIR}/${MODULE_NAME}.ko"
    
    if $SIGN_MODULE; then
        generate_signing_keys
        sign_module "$module_path"
    fi
    
    # Install module
    cp "$module_path" "${INSTALL_MODULE_DIR}/"
    
    # Compress module (if supported)
    if command -v xz &>/dev/null; then
        xz -f "${INSTALL_MODULE_DIR}/${MODULE_NAME}.ko"
    fi
    
    # Update module dependencies
    depmod -a
    
    log_success "Module installed to ${INSTALL_MODULE_DIR}"
}

#-----------------------------------------------------------------------------
# Install via DKMS
#-----------------------------------------------------------------------------

install_dkms() {
    log_step "Installing via DKMS"
    
    # Run DKMS installation script
    if [ -f "${SCRIPT_DIR}/dkms-install.sh" ]; then
        if $ASSUME_YES; then
            "${SCRIPT_DIR}/dkms-install.sh" -v "${MODULE_VERSION}" -y
        else
            "${SCRIPT_DIR}/dkms-install.sh" -v "${MODULE_VERSION}"
        fi
    else
        log_error "DKMS installation script not found"
        exit 1
    fi
    
    # Sign if requested
    if $SIGN_MODULE; then
        generate_signing_keys
        
        local module_path="/lib/modules/$(uname -r)/updates/dkms/${MODULE_NAME}.ko"
        if [ ! -f "$module_path" ]; then
            module_path="/lib/modules/$(uname -r)/extra/${MODULE_NAME}.ko"
        fi
        if [ ! -f "$module_path" ]; then
            module_path=$(find /lib/modules/$(uname -r) -name "${MODULE_NAME}.ko*" | head -1)
        fi
        
        if [ -f "$module_path" ]; then
            sign_module "$module_path"
        else
            log_warn "Could not find module to sign"
        fi
    fi
}

#-----------------------------------------------------------------------------
# Install Configuration Files
#-----------------------------------------------------------------------------

install_config_files() {
    if $SKIP_CONFIG; then
        log_info "Skipping configuration file installation"
        return
    fi
    
    log_step "Installing configuration files"
    
    # modprobe configuration
    if [ -f "${DRIVER_DIR}/modprobe/quac100.conf" ]; then
        mkdir -p "${INSTALL_MODPROBE_DIR}"
        cp "${DRIVER_DIR}/modprobe/quac100.conf" "${INSTALL_MODPROBE_DIR}/"
        log_info "Installed: ${INSTALL_MODPROBE_DIR}/quac100.conf"
    fi
    
    # udev rules
    if [ -f "${DRIVER_DIR}/udev/99-quac100.rules" ]; then
        mkdir -p "${INSTALL_UDEV_DIR}"
        cp "${DRIVER_DIR}/udev/99-quac100.rules" "${INSTALL_UDEV_DIR}/"
        log_info "Installed: ${INSTALL_UDEV_DIR}/99-quac100.rules"
        
        # Reload udev rules
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
    fi
    
    # systemd service
    if [ -f "${DRIVER_DIR}/systemd/quac100.service" ]; then
        mkdir -p "${INSTALL_SYSTEMD_DIR}"
        cp "${DRIVER_DIR}/systemd/quac100.service" "${INSTALL_SYSTEMD_DIR}/"
        log_info "Installed: ${INSTALL_SYSTEMD_DIR}/quac100.service"
        
        # Enable service
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable quac100.service 2>/dev/null || true
    fi
    
    # Documentation
    mkdir -p "${INSTALL_DOC_DIR}"
    cp "${DRIVER_DIR}/README.md" "${INSTALL_DOC_DIR}/" 2>/dev/null || true
    
    # Scripts
    mkdir -p "${INSTALL_SCRIPT_DIR}"
    cp "${SCRIPT_DIR}/"*.sh "${INSTALL_SCRIPT_DIR}/" 2>/dev/null || true
    chmod +x "${INSTALL_SCRIPT_DIR}/"*.sh 2>/dev/null || true
    
    log_success "Configuration files installed"
}

#-----------------------------------------------------------------------------
# Load Module
#-----------------------------------------------------------------------------

load_module() {
    if ! $LOAD_MODULE; then
        log_info "Skipping module load (--skip-load specified)"
        return
    fi
    
    log_step "Loading kernel module"
    
    # Unload if already loaded
    if lsmod | grep -q "^${MODULE_NAME}"; then
        log_info "Unloading existing module..."
        modprobe -r "${MODULE_NAME}" 2>/dev/null || true
    fi
    
    # Load module
    if modprobe "${MODULE_NAME}"; then
        log_success "Module loaded"
        
        # Check for hardware
        if [ -d "/sys/class/quac100" ]; then
            log_success "QUAC 100 hardware detected!"
        else
            log_info "Module loaded but no hardware detected"
        fi
    else
        if $SECURE_BOOT_ENABLED && ! $SIGN_MODULE; then
            log_error "Failed to load module (Secure Boot may be blocking unsigned modules)"
        else
            log_warn "Failed to load module (hardware may not be present)"
        fi
    fi
}

#-----------------------------------------------------------------------------
# Show Summary
#-----------------------------------------------------------------------------

show_summary() {
    echo ""
    echo "========================================"
    echo " Installation Summary"
    echo "========================================"
    echo ""
    echo "Module: ${MODULE_NAME} version ${MODULE_VERSION}"
    echo "Kernel: $(uname -r)"
    echo ""
    
    if $USE_DKMS; then
        echo "Installation method: DKMS"
        dkms status "${MODULE_NAME}" 2>/dev/null || echo "DKMS status unavailable"
    else
        echo "Installation method: Direct"
    fi
    echo ""
    
    if lsmod | grep -q "^${MODULE_NAME}"; then
        echo "Module status: Loaded"
        modinfo "${MODULE_NAME}" 2>/dev/null | grep -E "^(version|filename):" || true
    else
        echo "Module status: Not loaded"
    fi
    echo ""
    
    if [ -d "/sys/class/quac100" ]; then
        echo "Hardware: Detected"
        ls -1 /sys/class/quac100/ 2>/dev/null || true
    else
        echo "Hardware: Not detected"
    fi
    echo ""
    echo "========================================"
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    echo "========================================"
    echo " QUAC 100 Driver Installation"
    echo " Version: ${MODULE_VERSION}"
    echo "========================================"
    echo ""
    
    check_root
    detect_distro
    install_dependencies
    check_secure_boot
    
    if $USE_DKMS; then
        install_dkms
    else
        build_module_direct
        install_module_direct
    fi
    
    install_config_files
    load_module
    show_summary
    
    log_success "Installation complete!"
    echo ""
    echo "Documentation: ${INSTALL_DOC_DIR}"
    echo "Scripts: ${INSTALL_SCRIPT_DIR}"
    echo ""
}

main "$@"