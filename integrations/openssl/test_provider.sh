#!/bin/bash
# =============================================================================
# QUAC 100 OpenSSL Provider Test Script
# =============================================================================
#
# This script tests the QUAC 100 OpenSSL provider functionality.
#
# Usage:
#   ./test_provider.sh [provider_path]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Provider path (can be overridden by argument)
PROVIDER_PATH="${1:-./build}"

echo "================================================="
echo "QUAC 100 OpenSSL Provider Test Script"
echo "================================================="
echo ""

# Check for OpenSSL 3.x
echo -e "${BLUE}[Checking OpenSSL version]${NC}"
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
OPENSSL_MAJOR=$(echo "$OPENSSL_VERSION" | cut -d. -f1)

if [ "$OPENSSL_MAJOR" -lt 3 ]; then
    echo -e "${RED}Error: OpenSSL 3.x required (found $OPENSSL_VERSION)${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} OpenSSL $OPENSSL_VERSION"
echo ""

# Check provider exists
echo -e "${BLUE}[Checking provider module]${NC}"
if [ -f "$PROVIDER_PATH/quac100.so" ]; then
    PROVIDER_MODULE="$PROVIDER_PATH/quac100.so"
elif [ -f "$PROVIDER_PATH/quac100.dylib" ]; then
    PROVIDER_MODULE="$PROVIDER_PATH/quac100.dylib"
elif [ -f "$PROVIDER_PATH/quac100.dll" ]; then
    PROVIDER_MODULE="$PROVIDER_PATH/quac100.dll"
else
    echo -e "${RED}Error: Provider module not found in $PROVIDER_PATH${NC}"
    echo "Build the provider first: mkdir build && cd build && cmake .. && make"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Found: $PROVIDER_MODULE"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    
    if eval "$command" > /tmp/test_output.txt 2>&1; then
        echo -e "  ${GREEN}✓${NC} $test_name"
        ((PASSED++))
        return 0
    else
        echo -e "  ${RED}✗${NC} $test_name"
        echo -e "    ${YELLOW}Output:${NC}"
        cat /tmp/test_output.txt | sed 's/^/      /'
        ((FAILED++))
        return 1
    fi
}

# Create temp directory for test files
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# =============================================================================
# Test: Provider Loading
# =============================================================================
echo -e "${BLUE}[Provider Loading Tests]${NC}"

run_test "Load provider" \
    "openssl list -providers -provider-path '$PROVIDER_PATH' -provider quac100 | grep -q quac100"

run_test "Query provider info" \
    "openssl list -providers -provider-path '$PROVIDER_PATH' -provider quac100 -verbose | grep -q 'version'"

echo ""

# =============================================================================
# Test: Algorithm Listing
# =============================================================================
echo -e "${BLUE}[Algorithm Listing Tests]${NC}"

run_test "List KEM algorithms" \
    "openssl list -kem-algorithms -provider-path '$PROVIDER_PATH' -provider quac100 | grep -q 'ML-KEM'"

run_test "List signature algorithms" \
    "openssl list -signature-algorithms -provider-path '$PROVIDER_PATH' -provider quac100 | grep -q 'ML-DSA'"

echo ""

# =============================================================================
# Test: ML-KEM Operations
# =============================================================================
echo -e "${BLUE}[ML-KEM Tests]${NC}"

for ALG in "ML-KEM-512" "ML-KEM-768" "ML-KEM-1024"; do
    # Generate keypair
    run_test "$ALG keygen" \
        "openssl genpkey -provider-path '$PROVIDER_PATH' -provider quac100 -algorithm '$ALG' -out '$TMPDIR/${ALG}.pem'"
    
    # Extract public key
    run_test "$ALG extract pubkey" \
        "openssl pkey -provider-path '$PROVIDER_PATH' -provider quac100 -in '$TMPDIR/${ALG}.pem' -pubout -out '$TMPDIR/${ALG}_pub.pem'"
done

echo ""

# =============================================================================
# Test: ML-DSA Operations
# =============================================================================
echo -e "${BLUE}[ML-DSA Tests]${NC}"

# Test message
echo "Test message for digital signature" > "$TMPDIR/message.txt"

for ALG in "ML-DSA-44" "ML-DSA-65" "ML-DSA-87"; do
    # Generate keypair
    run_test "$ALG keygen" \
        "openssl genpkey -provider-path '$PROVIDER_PATH' -provider quac100 -algorithm '$ALG' -out '$TMPDIR/${ALG}.pem'"
    
    # Extract public key
    run_test "$ALG extract pubkey" \
        "openssl pkey -provider-path '$PROVIDER_PATH' -provider quac100 -in '$TMPDIR/${ALG}.pem' -pubout -out '$TMPDIR/${ALG}_pub.pem'"
    
    # Sign (using pkeyutl)
    run_test "$ALG sign" \
        "openssl pkeyutl -provider-path '$PROVIDER_PATH' -provider quac100 -sign -inkey '$TMPDIR/${ALG}.pem' -in '$TMPDIR/message.txt' -out '$TMPDIR/${ALG}.sig'"
    
    # Verify
    run_test "$ALG verify" \
        "openssl pkeyutl -provider-path '$PROVIDER_PATH' -provider quac100 -verify -pubin -inkey '$TMPDIR/${ALG}_pub.pem' -in '$TMPDIR/message.txt' -sigfile '$TMPDIR/${ALG}.sig'"
    
    # Tamper detection
    echo "Tampered message" > "$TMPDIR/tampered.txt"
    run_test "$ALG tamper detection" \
        "! openssl pkeyutl -provider-path '$PROVIDER_PATH' -provider quac100 -verify -pubin -inkey '$TMPDIR/${ALG}_pub.pem' -in '$TMPDIR/tampered.txt' -sigfile '$TMPDIR/${ALG}.sig' 2>/dev/null"
done

echo ""

# =============================================================================
# Test: QRNG
# =============================================================================
echo -e "${BLUE}[QRNG Tests]${NC}"

run_test "Generate 32 random bytes" \
    "openssl rand -provider-path '$PROVIDER_PATH' -provider quac100 -hex 32 | wc -c | grep -q '65'"  # 64 hex chars + newline

run_test "Generate 1024 random bytes" \
    "openssl rand -provider-path '$PROVIDER_PATH' -provider quac100 -out '$TMPDIR/random.bin' 1024 && [ -s '$TMPDIR/random.bin' ]"

run_test "Random bytes differ" \
    "openssl rand -provider-path '$PROVIDER_PATH' -provider quac100 -hex 32 > '$TMPDIR/rand1.txt' && \
     openssl rand -provider-path '$PROVIDER_PATH' -provider quac100 -hex 32 > '$TMPDIR/rand2.txt' && \
     ! diff -q '$TMPDIR/rand1.txt' '$TMPDIR/rand2.txt' >/dev/null"

echo ""

# =============================================================================
# Test: Key Sizes
# =============================================================================
echo -e "${BLUE}[Key Size Verification]${NC}"

# Expected sizes (approximate, encoded keys may vary slightly)
verify_key_size() {
    local alg="$1"
    local min_size="$2"
    local file="$TMPDIR/${alg}.pem"
    local actual_size=$(wc -c < "$file")
    
    if [ "$actual_size" -ge "$min_size" ]; then
        echo -e "  ${GREEN}✓${NC} $alg key size: $actual_size bytes (min: $min_size)"
        ((PASSED++))
    else
        echo -e "  ${RED}✗${NC} $alg key size: $actual_size bytes (expected min: $min_size)"
        ((FAILED++))
    fi
}

verify_key_size "ML-KEM-512" 2000
verify_key_size "ML-KEM-768" 3000
verify_key_size "ML-KEM-1024" 4500
verify_key_size "ML-DSA-44" 3500
verify_key_size "ML-DSA-65" 5500
verify_key_size "ML-DSA-87" 7000

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "================================================="
echo "Test Summary"
echo "================================================="
echo -e "  ${GREEN}Passed:${NC} $PASSED"
echo -e "  ${RED}Failed:${NC} $FAILED"
echo "  Total:  $((PASSED + FAILED))"
echo "================================================="

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi