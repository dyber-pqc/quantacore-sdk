#=============================================================================
# QUAC 100 DKMS Package - RPM Spec File
#
# This file defines how the RPM package is built for Red Hat based systems.
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

Name:           quac100-dkms
Version:        1.0.0
Release:        1%{?dist}
Summary:        QUAC 100 Post-Quantum Cryptographic Accelerator Driver (DKMS)

License:        Proprietary
URL:            https://www.dyber.io/quantacore
Source0:        quac100-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  sed

Requires:       dkms >= 2.2.0
Requires:       kernel-devel
Requires:       kernel-headers
Requires:       gcc
Requires:       make
Recommends:     mokutil

Provides:       quac100-kmod = %{version}
Provides:       kmod(quac100.ko) = %{version}

%description
The QUAC 100 is a PCIe-based post-quantum cryptographic accelerator
supporting NIST standardized algorithms for post-quantum cryptography.

Supported algorithms:
  - ML-KEM (Kyber): 512, 768, 1024 parameter sets
  - ML-DSA (Dilithium): Level 2, 3, 5
  - SLH-DSA (SPHINCS+): 128s/f, 192s/f, 256s/f

Features:
  - Hardware quantum random number generation (2 Gbps)
  - PCIe Gen4 x8 interface with DMA
  - MSI-X interrupts (up to 32 vectors)
  - SR-IOV virtualization (up to 16 VFs)
  - FIPS 140-3 compliant operation mode

This package contains the DKMS source for automatic compilation
against your running kernel.

%prep
%setup -q -n quac100-%{version}

%build
# Nothing to build - DKMS handles compilation

%install
rm -rf %{buildroot}

# Create directories
install -d %{buildroot}/usr/src/quac100-%{version}
install -d %{buildroot}/etc/modprobe.d
install -d %{buildroot}/etc/udev/rules.d
install -d %{buildroot}/usr/lib/systemd/system
install -d %{buildroot}/usr/share/doc/%{name}
install -d %{buildroot}/usr/share/quac100/scripts

# Install DKMS source files
install -m 644 *.c %{buildroot}/usr/src/quac100-%{version}/
install -m 644 *.h %{buildroot}/usr/src/quac100-%{version}/
install -m 644 Makefile %{buildroot}/usr/src/quac100-%{version}/
install -m 644 Kbuild %{buildroot}/usr/src/quac100-%{version}/
install -m 644 dkms.conf %{buildroot}/usr/src/quac100-%{version}/

# Update version in dkms.conf
sed -i 's/PACKAGE_VERSION="[^"]*"/PACKAGE_VERSION="%{version}"/' \
    %{buildroot}/usr/src/quac100-%{version}/dkms.conf

# Install configuration files
install -m 644 quac100.conf %{buildroot}/etc/modprobe.d/
install -m 644 99-quac100.rules %{buildroot}/etc/udev/rules.d/
install -m 644 quac100.service %{buildroot}/usr/lib/systemd/system/

# Install documentation
install -m 644 README.md %{buildroot}/usr/share/doc/%{name}/

# Install scripts
install -d %{buildroot}/usr/share/quac100/scripts
if [ -d scripts ]; then
    install -m 755 scripts/*.sh %{buildroot}/usr/share/quac100/scripts/ 2>/dev/null || true
fi

%post
echo "Configuring QUAC 100 driver..."

# Add to DKMS
dkms add -m quac100 -v %{version} --rpm_safe_upgrade 2>/dev/null || true

# Build for current kernel
echo "Building QUAC 100 driver for kernel $(uname -r)..."
dkms build -m quac100 -v %{version} 2>/dev/null || \
    echo "Warning: Build failed. Install kernel-devel for your kernel."

# Install module
dkms install -m quac100 -v %{version} --force 2>/dev/null || \
    echo "Warning: Installation failed."

# Reload udev rules
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger 2>/dev/null || true

# Enable systemd service
systemctl daemon-reload 2>/dev/null || true
systemctl enable quac100.service 2>/dev/null || true

# Load module
modprobe quac100 2>/dev/null || \
    echo "Note: Could not load module. Hardware may not be present."

echo "QUAC 100 driver installation complete."

%preun
if [ $1 -eq 0 ]; then
    echo "Removing QUAC 100 driver..."
    
    # Unload module
    modprobe -r quac100 2>/dev/null || true
    
    # Stop and disable service
    systemctl stop quac100.service 2>/dev/null || true
    systemctl disable quac100.service 2>/dev/null || true
    
    # Remove from DKMS
    dkms remove -m quac100 -v %{version} --all 2>/dev/null || true
fi

%postun
if [ $1 -eq 0 ]; then
    # Final cleanup on complete removal
    systemctl daemon-reload 2>/dev/null || true
    udevadm control --reload-rules 2>/dev/null || true
    depmod -a 2>/dev/null || true
fi

%files
%defattr(-,root,root,-)

# DKMS source
%dir /usr/src/quac100-%{version}
/usr/src/quac100-%{version}/*

# Configuration files
%config(noreplace) /etc/modprobe.d/quac100.conf
/etc/udev/rules.d/99-quac100.rules
/usr/lib/systemd/system/quac100.service

# Documentation
%doc /usr/share/doc/%{name}/README.md

# Scripts
%dir /usr/share/quac100
%dir /usr/share/quac100/scripts
/usr/share/quac100/scripts/*

%changelog
* Mon Jan 01 2025 Dyber Inc <support@dyber.io> - 1.0.0-1
- Initial release
- ML-KEM (Kyber) support: 512, 768, 1024 parameter sets
- ML-DSA (Dilithium) support: Level 2, 3, 5
- SLH-DSA (SPHINCS+) support: SHA2 128s/f, 192s/f, 256s/f
- Hardware QRNG with 2 Gbps entropy generation
- PCIe Gen4 x8 interface with DMA support
- MSI-X interrupt support (up to 32 vectors)
- SR-IOV virtualization support (up to 16 VFs)
- Asynchronous operation support
- Batch operation processing
- DKMS integration for automatic kernel updates
- Systemd service integration
- Comprehensive sysfs interface
- FIPS 140-3 self-test framework
