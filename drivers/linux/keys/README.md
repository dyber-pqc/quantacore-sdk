# QUAC 100 Module Signing Keys

This directory is used to store kernel module signing keys for Secure Boot compatibility.

## Overview

When Secure Boot is enabled, all kernel modules must be signed with a key that is enrolled in the system's MOK (Machine Owner Key) database. This ensures the integrity and authenticity of loaded kernel modules.

## Directory Contents

After key generation, this directory will contain:

| File | Description |
|------|-------------|
| `signing_key.pem` | Private signing key (KEEP SECURE!) |
| `signing_key.x509` | Public certificate for MOK enrollment |
| `signing_key.der` | DER-encoded certificate (for mokutil) |

## Generating Keys

### Automatic Generation

Use the provided script to generate keys:

```bash
../scripts/sign-module.sh --generate-keys
```

### Manual Generation

Generate a self-signed certificate for module signing:

```bash
# Create OpenSSL configuration
cat > x509.conf << EOF
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
    -keyout signing_key.pem \
    -out signing_key.x509 \
    -days 3650 \
    -nodes \
    -config x509.conf

# Convert to DER format for MOK enrollment
openssl x509 -in signing_key.x509 -outform DER -out signing_key.der

# Clean up
rm x509.conf
```

## Enrolling Keys in MOK

### Step 1: Import the Key

```bash
sudo mokutil --import signing_key.der
```

You will be prompted to create a password. Remember this password - you'll need it during the next boot.

### Step 2: Reboot and Enroll

1. Reboot your system
2. The MOK Manager will appear during boot
3. Select "Enroll MOK"
4. Select "Continue"
5. Enter the password you created
6. Select "Reboot"

### Step 3: Verify Enrollment

After reboot, verify the key is enrolled:

```bash
mokutil --list-enrolled | grep "QUAC 100"
```

## Signing Modules

### Automatic Signing (Recommended)

During installation, the module is automatically signed if keys are present:

```bash
sudo ../scripts/install.sh
```

### Manual Signing

Sign the module manually:

```bash
/usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 \
    signing_key.pem \
    signing_key.x509 \
    /lib/modules/$(uname -r)/extra/quac100.ko
```

### Using DKMS Auto-Signing

Configure DKMS to automatically sign modules:

```bash
# /etc/dkms/framework.conf
mok_signing_key="/path/to/signing_key.pem"
mok_certificate="/path/to/signing_key.x509"
sign_tool="/etc/dkms/sign_helper.sh"
```

## Security Considerations

### Private Key Protection

The private key (`signing_key.pem`) should be:

1. **Restricted permissions**: `chmod 600 signing_key.pem`
2. **Owned by root**: `chown root:root signing_key.pem`
3. **Stored securely**: Consider encrypted storage
4. **Backed up**: Keep a secure offline backup

### Key Rotation

For production deployments:

1. Generate new keys periodically (annually recommended)
2. Enroll new keys before revoking old ones
3. Re-sign modules with new keys
4. Revoke old keys after transition

### Enterprise Deployment

For enterprise environments:

1. Use a centralized key management system
2. Consider hardware security modules (HSMs) for key storage
3. Implement key escrow procedures
4. Document key management policies

## Troubleshooting

### Module Fails to Load (Secure Boot)

```
modprobe: ERROR: could not insert 'quac100': Required key not available
```

**Solution**: Ensure the module is signed and the key is enrolled in MOK.

### Check Module Signature

```bash
# Verify module has a signature
modinfo quac100 | grep sig
hexdump -C /lib/modules/$(uname -r)/extra/quac100.ko | tail -20
```

### Check Secure Boot Status

```bash
mokutil --sb-state
```

### List Enrolled Keys

```bash
mokutil --list-enrolled
```

### Re-sign After Kernel Update

If module fails after kernel update:

```bash
sudo dkms remove quac100/1.0.0 --all
sudo dkms install quac100/1.0.0
```

## Pre-Generated Keys for Development

**WARNING**: Pre-generated keys should NEVER be used in production!

For development and testing purposes only, you may find pre-generated keys in:

```
/usr/share/quac100/keys/
```

These keys are:
- Publicly known
- Insecure for production use
- Intended only for development environments without Secure Boot

## References

- [Kernel Module Signing Facility](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [Secure Boot and MOK](https://wiki.ubuntu.com/UEFI/SecureBoot)
- [DKMS Documentation](https://github.com/dell/dkms)
- [mokutil Manual](https://man7.org/linux/man-pages/man1/mokutil.1.html)

## Support

For assistance with module signing:

- Documentation: https://docs.quantacore.io/sdk/signing
- Support: support@dyber.io
- GitHub Issues: https://github.com/dyber/quantacore-sdk/issues
