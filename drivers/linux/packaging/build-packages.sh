#!/bin/bash
#=============================================================================
# QUAC 100 Driver Package Build Script
# 
# Builds DEB and RPM packages for the QUAC 100 Linux driver.
#
# Usage: ./build-packages.sh [options]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

set -e

#-----------------------------------------------------------------------------
# Configuration
#-----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${DRIVER_DIR}/build"
DIST_DIR="${DRIVER_DIR}/dist"

PACKAGE_NAME="quac100-dkms"
VERSION="1.0.0"
RELEASE="1"
MAINTAINER="Dyber Inc <support@dyber.io>"
DESCRIPTION="QUAC 100 Post-Quantum Cryptographic Accelerator Driver (DKMS)"
URL="https://www.dyber.io/quantacore"
LICENSE="Proprietary"

# Colors for output
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

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command not found: $1"
        return 1
    fi
    return 0
}

usage() {
    cat << EOF
QUAC 100 Driver Package Build Script

Usage: $(basename "$0") [options]

Options:
    -h, --help          Show this help message
    -v, --version VER   Set package version (default: ${VERSION})
    -r, --release REL   Set release number (default: ${RELEASE})
    --deb               Build DEB package only
    --rpm               Build RPM package only
    --all               Build all package formats (default)
    --clean             Clean build artifacts
    --sign              Sign packages (requires GPG key)
    --gpg-key KEY       GPG key ID for signing
    -o, --output DIR    Output directory (default: ${DIST_DIR})

Examples:
    $(basename "$0")                    # Build all packages
    $(basename "$0") --deb              # Build DEB only
    $(basename "$0") --rpm              # Build RPM only
    $(basename "$0") -v 1.0.1 --all     # Build version 1.0.1
    $(basename "$0") --sign --gpg-key ABCD1234  # Build and sign

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

BUILD_DEB=false
BUILD_RPM=false
DO_CLEAN=false
DO_SIGN=false
GPG_KEY=""
OUTPUT_DIR="${DIST_DIR}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        -r|--release) RELEASE="$2"; shift 2 ;;
        --deb) BUILD_DEB=true; shift ;;
        --rpm) BUILD_RPM=true; shift ;;
        --all) BUILD_DEB=true; BUILD_RPM=true; shift ;;
        --clean) DO_CLEAN=true; shift ;;
        --sign) DO_SIGN=true; shift ;;
        --gpg-key) GPG_KEY="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if ! $BUILD_DEB && ! $BUILD_RPM && ! $DO_CLEAN; then
    BUILD_DEB=true
    BUILD_RPM=true
fi

#-----------------------------------------------------------------------------
# Clean Function
#-----------------------------------------------------------------------------

clean_build() {
    log_info "Cleaning build artifacts..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${DIST_DIR}"
    log_success "Clean complete"
}

#-----------------------------------------------------------------------------
# Build DEB Package
#-----------------------------------------------------------------------------

build_deb() {
    log_info "Building DEB package..."
    
    if ! check_command dpkg-deb; then
        log_error "dpkg-deb not found. Install: sudo apt-get install dpkg-dev"
        return 1
    fi
    
    local pkg_name="${PACKAGE_NAME}_${VERSION}-${RELEASE}"
    local pkg_dir="${BUILD_DIR}/deb/${pkg_name}"
    local dkms_src="/usr/src/quac100-${VERSION}"
    
    mkdir -p "${pkg_dir}/DEBIAN"
    mkdir -p "${pkg_dir}${dkms_src}"
    mkdir -p "${pkg_dir}/etc/modprobe.d"
    mkdir -p "${pkg_dir}/etc/udev/rules.d"
    mkdir -p "${pkg_dir}/lib/systemd/system"
    mkdir -p "${pkg_dir}/usr/share/doc/${PACKAGE_NAME}"
    mkdir -p "${pkg_dir}/usr/share/quac100/scripts"
    
    cp -r "${DRIVER_DIR}/src/"* "${pkg_dir}${dkms_src}/"
    cp "${DRIVER_DIR}/dkms/dkms.conf" "${pkg_dir}${dkms_src}/"
    sed -i "s/PACKAGE_VERSION=\"[^\"]*\"/PACKAGE_VERSION=\"${VERSION}\"/" "${pkg_dir}${dkms_src}/dkms.conf"
    
    cp "${DRIVER_DIR}/modprobe/quac100.conf" "${pkg_dir}/etc/modprobe.d/"
    cp "${DRIVER_DIR}/udev/99-quac100.rules" "${pkg_dir}/etc/udev/rules.d/"
    cp "${DRIVER_DIR}/systemd/quac100.service" "${pkg_dir}/lib/systemd/system/"
    cp "${DRIVER_DIR}/README.md" "${pkg_dir}/usr/share/doc/${PACKAGE_NAME}/"
    
    for script in "${DRIVER_DIR}/scripts/"*.sh; do
        [ -f "$script" ] && cp "$script" "${pkg_dir}/usr/share/quac100/scripts/"
    done
    chmod +x "${pkg_dir}/usr/share/quac100/scripts/"*.sh 2>/dev/null || true
    
    local installed_size=$(du -sk "${pkg_dir}" | cut -f1)
    
    cat > "${pkg_dir}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}-${RELEASE}
Section: kernel
Priority: optional
Architecture: all
Depends: dkms (>= 2.2.0), linux-headers-generic | linux-headers-amd64 | linux-headers, build-essential
Recommends: mokutil
Maintainer: ${MAINTAINER}
Homepage: ${URL}
Installed-Size: ${installed_size}
Description: ${DESCRIPTION}
 The QUAC 100 is a PCIe-based post-quantum cryptographic accelerator
 supporting ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+).
 .
 This package contains the DKMS source for the QUAC 100 kernel driver.
EOF

    cat > "${pkg_dir}/DEBIAN/conffiles" << EOF
/etc/modprobe.d/quac100.conf
EOF

    cp "${SCRIPT_DIR}/deb/postinst" "${pkg_dir}/DEBIAN/"
    cp "${SCRIPT_DIR}/deb/prerm" "${pkg_dir}/DEBIAN/"
    sed -i "s/DKMS_VERSION=\"[^\"]*\"/DKMS_VERSION=\"${VERSION}\"/" "${pkg_dir}/DEBIAN/postinst"
    sed -i "s/DKMS_VERSION=\"[^\"]*\"/DKMS_VERSION=\"${VERSION}\"/" "${pkg_dir}/DEBIAN/prerm"
    chmod 755 "${pkg_dir}/DEBIAN/postinst"
    chmod 755 "${pkg_dir}/DEBIAN/prerm"
    
    cd "${BUILD_DIR}/deb"
    fakeroot dpkg-deb --build "${pkg_name}" 2>/dev/null || dpkg-deb --build "${pkg_name}"
    
    mkdir -p "${OUTPUT_DIR}"
    mv "${pkg_name}.deb" "${OUTPUT_DIR}/"
    
    if $DO_SIGN && [ -n "$GPG_KEY" ]; then
        log_info "Signing DEB package..."
        dpkg-sig -k "$GPG_KEY" --sign builder "${OUTPUT_DIR}/${pkg_name}.deb" 2>/dev/null || log_warn "Signing failed"
    fi
    
    log_success "DEB package created: ${OUTPUT_DIR}/${pkg_name}.deb"
}

#-----------------------------------------------------------------------------
# Build RPM Package
#-----------------------------------------------------------------------------

build_rpm() {
    log_info "Building RPM package..."
    
    if ! check_command rpmbuild; then
        log_error "rpmbuild not found. Install: sudo dnf install rpm-build"
        return 1
    fi
    
    local rpm_root="${BUILD_DIR}/rpm"
    
    mkdir -p "${rpm_root}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    
    local src_dir="${rpm_root}/SOURCES/quac100-${VERSION}"
    mkdir -p "${src_dir}"
    cp -r "${DRIVER_DIR}/src/"* "${src_dir}/"
    cp "${DRIVER_DIR}/dkms/dkms.conf" "${src_dir}/"
    sed -i "s/PACKAGE_VERSION=\"[^\"]*\"/PACKAGE_VERSION=\"${VERSION}\"/" "${src_dir}/dkms.conf"
    cp "${DRIVER_DIR}/modprobe/quac100.conf" "${src_dir}/"
    cp "${DRIVER_DIR}/udev/99-quac100.rules" "${src_dir}/"
    cp "${DRIVER_DIR}/systemd/quac100.service" "${src_dir}/"
    cp "${DRIVER_DIR}/README.md" "${src_dir}/"
    
    mkdir -p "${src_dir}/scripts"
    cp "${DRIVER_DIR}/scripts/"*.sh "${src_dir}/scripts/" 2>/dev/null || true
    
    cd "${rpm_root}/SOURCES"
    tar czf "quac100-${VERSION}.tar.gz" "quac100-${VERSION}"
    rm -rf "quac100-${VERSION}"
    
    cp "${SCRIPT_DIR}/rpm/quac100-dkms.spec" "${rpm_root}/SPECS/"
    sed -i "s/^Version:.*/Version:        ${VERSION}/" "${rpm_root}/SPECS/quac100-dkms.spec"
    sed -i "s/^Release:.*/Release:        ${RELEASE}%{?dist}/" "${rpm_root}/SPECS/quac100-dkms.spec"
    
    rpmbuild --define "_topdir ${rpm_root}" -ba "${rpm_root}/SPECS/quac100-dkms.spec"
    
    mkdir -p "${OUTPUT_DIR}"
    find "${rpm_root}/RPMS" -name "*.rpm" -exec mv {} "${OUTPUT_DIR}/" \;
    find "${rpm_root}/SRPMS" -name "*.rpm" -exec mv {} "${OUTPUT_DIR}/" \;
    
    if $DO_SIGN && [ -n "$GPG_KEY" ]; then
        log_info "Signing RPM packages..."
        for rpm in "${OUTPUT_DIR}"/*.rpm; do
            [ -f "$rpm" ] && rpm --addsign --define "_gpg_name ${GPG_KEY}" "$rpm" 2>/dev/null || true
        done
    fi
    
    log_success "RPM packages created in: ${OUTPUT_DIR}"
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    echo "========================================"
    echo " QUAC 100 Driver Package Builder"
    echo " Version: ${VERSION}"
    echo "========================================"
    echo
    
    if $DO_CLEAN; then
        clean_build
        exit 0
    fi
    
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${OUTPUT_DIR}"
    
    $BUILD_DEB && { build_deb; echo; }
    $BUILD_RPM && { build_rpm; echo; }
    
    echo "========================================"
    log_success "Build complete!"
    log_info "Packages available in: ${OUTPUT_DIR}"
    ls -la "${OUTPUT_DIR}"/*.deb "${OUTPUT_DIR}"/*.rpm 2>/dev/null || true
    echo "========================================"
}

main "$@"
