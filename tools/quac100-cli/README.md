# QUAC 100 Command Line Interface

Interactive command-line tool for the QUAC 100 post-quantum cryptographic accelerator.

## Features

- **Device Management**: List, select, and query QUAC devices
- **KEM Operations**: ML-KEM key generation, encapsulation, decapsulation
- **Signature Operations**: ML-DSA/SLH-DSA key generation, signing, verification
- **Random Generation**: QRNG-based random number generation
- **Key Management**: Import, export, list, and delete keys
- **Interactive Shell**: Full-featured interactive mode with history
- **Scripting Support**: Non-interactive mode for automation

## Building

```bash
cd tools/quac100-cli
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

```
quac100-cli [OPTIONS] <COMMAND> [ARGS...]

Global Options:
  -d, --device <index>      Select device by index (default: 0)
  -s, --simulator           Use software simulator
  -v, --verbose             Verbose output
  -q, --quiet               Quiet mode (errors only)
  -j, --json                JSON output format
  -h, --help                Show help
  -V, --version             Show version

Commands:
  list                      List available devices
  info                      Show device information
  kem                       KEM operations
  sign                      Signature operations
  random                    Generate random bytes
  keys                      Key management
  diag                      Diagnostics
  shell                     Interactive shell
  help                      Show command help
```

## Commands

### Device Commands

```bash
# List all devices
quac100-cli list

# Show detailed device info
quac100-cli info
quac100-cli info -d 1

# Use simulator
quac100-cli -s info
```

### KEM Operations

```bash
# Generate keypair
quac100-cli kem keygen -a ml-kem-768 -o keypair.bin
quac100-cli kem keygen -a ml-kem-768 --pk public.bin --sk secret.bin

# Encapsulate (generate ciphertext and shared secret)
quac100-cli kem encaps -a ml-kem-768 -p public.bin -o encaps.bin

# Decapsulate (recover shared secret)
quac100-cli kem decaps -a ml-kem-768 -c ciphertext.bin -s secret.bin -o shared.bin

# Full KEM demo
quac100-cli kem demo -a ml-kem-768
```

**KEM Algorithms:**
- `ml-kem-512` - FIPS 203 ML-KEM-512
- `ml-kem-768` - FIPS 203 ML-KEM-768 (recommended)
- `ml-kem-1024` - FIPS 203 ML-KEM-1024

### Signature Operations

```bash
# Generate keypair
quac100-cli sign keygen -a ml-dsa-65 -o keypair.bin
quac100-cli sign keygen -a ml-dsa-65 --pk public.bin --sk secret.bin

# Sign a message/file
quac100-cli sign sign -a ml-dsa-65 -s secret.bin -m message.txt -o signature.bin
echo "Hello" | quac100-cli sign sign -a ml-dsa-65 -s secret.bin -o sig.bin

# Verify a signature
quac100-cli sign verify -a ml-dsa-65 -p public.bin -m message.txt -g signature.bin

# Full signature demo
quac100-cli sign demo -a ml-dsa-65
```

**Signature Algorithms:**
- `ml-dsa-44` - FIPS 204 ML-DSA-44
- `ml-dsa-65` - FIPS 204 ML-DSA-65 (recommended)
- `ml-dsa-87` - FIPS 204 ML-DSA-87
- `slh-dsa-128f` - FIPS 205 SLH-DSA-SHA2-128f
- `slh-dsa-128s` - FIPS 205 SLH-DSA-SHA2-128s
- `slh-dsa-192f` - FIPS 205 SLH-DSA-SHA2-192f
- `slh-dsa-192s` - FIPS 205 SLH-DSA-SHA2-192s
- `slh-dsa-256f` - FIPS 205 SLH-DSA-SHA2-256f
- `slh-dsa-256s` - FIPS 205 SLH-DSA-SHA2-256s

### Random Number Generation

```bash
# Generate random bytes (hex output)
quac100-cli random 32
quac100-cli random 64 --hex

# Generate random bytes (binary output)
quac100-cli random 1024 -o random.bin

# Generate random bytes (base64 output)
quac100-cli random 32 --base64

# Specify quality level
quac100-cli random 32 --quality high
```

### Key Management

```bash
# List keys on device
quac100-cli keys list

# Import key to device
quac100-cli keys import -f keypair.bin -n "my-kem-key" -t kem

# Export key from device
quac100-cli keys export -n "my-kem-key" -o exported.bin

# Delete key
quac100-cli keys delete -n "my-kem-key"

# Show key info
quac100-cli keys info -n "my-kem-key"
```

### Diagnostics

```bash
# Run self-test
quac100-cli diag selftest

# Check device health
quac100-cli diag health

# Show statistics
quac100-cli diag stats

# Reset statistics
quac100-cli diag reset-stats

# Firmware info
quac100-cli diag firmware
```

### Interactive Shell

```bash
# Start interactive shell
quac100-cli shell

# Shell commands
quac> help
quac> list
quac> select 0
quac> info
quac> kem keygen ml-kem-768
quac> random 32
quac> exit
```

## Output Formats

### Default (Human-Readable)

```
Device: QUAC 100 PCIe
Index: 0
Firmware: 1.2.3
Serial: QC100-2025-00001
Status: Ready
```

### JSON (`-j` or `--json`)

```json
{
  "device": {
    "name": "QUAC 100 PCIe",
    "index": 0,
    "firmware": "1.2.3",
    "serial": "QC100-2025-00001",
    "status": "ready"
  }
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `QUAC_DEVICE` | Default device index |
| `QUAC_SIMULATOR` | Use simulator if set to "1" |
| `QUAC_VERBOSE` | Enable verbose output if set to "1" |
| `QUAC_JSON` | Enable JSON output if set to "1" |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Device not found |
| 4 | Device error |
| 5 | Operation failed |
| 6 | File I/O error |
| 7 | Key not found |

## Examples

### Complete KEM Workflow

```bash
# Generate keypair
quac100-cli kem keygen -a ml-kem-768 --pk alice_pk.bin --sk alice_sk.bin

# Alice sends public key to Bob...

# Bob encapsulates to Alice's public key
quac100-cli kem encaps -a ml-kem-768 -p alice_pk.bin \
    --ct ciphertext.bin --ss bob_shared.bin

# Bob sends ciphertext to Alice...

# Alice decapsulates
quac100-cli kem decaps -a ml-kem-768 -c ciphertext.bin -s alice_sk.bin \
    --ss alice_shared.bin

# Both now have the same shared secret
diff alice_shared.bin bob_shared.bin && echo "Shared secrets match!"
```

### Complete Signature Workflow

```bash
# Generate keypair
quac100-cli sign keygen -a ml-dsa-65 --pk signer_pk.bin --sk signer_sk.bin

# Sign a document
quac100-cli sign sign -a ml-dsa-65 -s signer_sk.bin -m document.pdf -o signature.bin

# Distribute public key, document, and signature...

# Verify signature
quac100-cli sign verify -a ml-dsa-65 -p signer_pk.bin -m document.pdf -g signature.bin
echo "Signature valid: $?"
```

### Scripting Example

```bash
#!/bin/bash
# Generate 1000 random keys and save to files

for i in $(seq 1 1000); do
    quac100-cli -q random 32 -o "keys/key_${i}.bin"
done
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.