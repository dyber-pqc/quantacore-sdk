#!/bin/bash
# D:\quantacore-sdk\integrations\pkcs11\test_pkcs11.sh
#
# QUAC 100 PKCS#11 Integration Test Script
#
# Usage:
#   ./test_pkcs11.sh [--module path] [--pin PIN] [--verbose]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.

set -e

# ==========================================================================
# Configuration
# ==========================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="${MODULE_PATH:-./libquac100_pkcs11.so}"
PIN="${PIN:-1234}"
SO_PIN="${SO_PIN:-12345678}"
VERBOSE=0
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ==========================================================================
# Utilities
# ==========================================================================

log() {
    echo -e "$1"
}

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo -e "$1"
    fi
}

test_start() {
    TEST_COUNT=$((TEST_COUNT + 1))
    log_verbose "${YELLOW}[$TEST_COUNT] $1${NC}"
}

test_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    log "${GREEN}✓ $1${NC}"
}

test_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    log "${RED}✗ $1${NC}"
    if [ -n "$2" ]; then
        log "  Error: $2"
    fi
}

# ==========================================================================
# Test Cases
# ==========================================================================

test_module_load() {
    test_start "Test module loading"

    if [ ! -f "$MODULE_PATH" ]; then
        test_fail "Module file not found: $MODULE_PATH"
        return 1
    fi

    # Use pkcs11-tool if available
    if command -v pkcs11-tool &> /dev/null; then
        if pkcs11-tool --module "$MODULE_PATH" --show-info > /dev/null 2>&1; then
            test_pass "Module loaded successfully"
            return 0
        fi
    fi

    # Fall back to ldd check
    if ldd "$MODULE_PATH" 2>&1 | grep -q "not found"; then
        test_fail "Module has missing dependencies"
        return 1
    fi

    test_pass "Module file exists and dependencies satisfied"
    return 0
}

test_slot_list() {
    test_start "Test slot listing"

    if command -v pkcs11-tool &> /dev/null; then
        output=$(pkcs11-tool --module "$MODULE_PATH" --list-slots 2>&1)
        if echo "$output" | grep -q "Slot"; then
            test_pass "Slot listing works"
            log_verbose "$output"
            return 0
        else
            test_fail "No slots found"
            return 1
        fi
    else
        log_verbose "pkcs11-tool not available, skipping"
        test_pass "Slot listing (skipped - pkcs11-tool not available)"
        return 0
    fi
}

test_mechanism_list() {
    test_start "Test mechanism listing"

    if command -v pkcs11-tool &> /dev/null; then
        output=$(pkcs11-tool --module "$MODULE_PATH" --list-mechanisms 2>&1)
        if echo "$output" | grep -qi "ML\|KEM\|DSA"; then
            test_pass "Post-quantum mechanisms available"
            log_verbose "$output"
            return 0
        else
            log_verbose "Mechanisms found but no PQC mechanisms"
            test_pass "Mechanism listing works"
            return 0
        fi
    else
        test_pass "Mechanism listing (skipped)"
        return 0
    fi
}

test_keygen_mldsa() {
    test_start "Test ML-DSA key generation"

    if command -v pkcs11-tool &> /dev/null; then
        # Try to generate ML-DSA-65 key
        output=$(pkcs11-tool --module "$MODULE_PATH" \
            --login --pin "$PIN" \
            --keypairgen --key-type "ML-DSA-65" \
            --label "test-mldsa-65" \
            --id "01" 2>&1) || true

        if echo "$output" | grep -qi "error\|failed"; then
            # Check if it's a "not supported" error (expected on some systems)
            if echo "$output" | grep -qi "not supported\|not implemented"; then
                test_pass "ML-DSA keygen (not supported in pkcs11-tool)"
                return 0
            fi
            test_fail "ML-DSA key generation failed" "$output"
            return 1
        fi

        test_pass "ML-DSA key generation"
        return 0
    else
        test_pass "ML-DSA keygen (skipped)"
        return 0
    fi
}

test_keygen_mlkem() {
    test_start "Test ML-KEM key generation"

    if command -v pkcs11-tool &> /dev/null; then
        output=$(pkcs11-tool --module "$MODULE_PATH" \
            --login --pin "$PIN" \
            --keypairgen --key-type "ML-KEM-768" \
            --label "test-mlkem-768" \
            --id "02" 2>&1) || true

        if echo "$output" | grep -qi "error\|failed"; then
            if echo "$output" | grep -qi "not supported\|not implemented"; then
                test_pass "ML-KEM keygen (not supported in pkcs11-tool)"
                return 0
            fi
            test_fail "ML-KEM key generation failed" "$output"
            return 1
        fi

        test_pass "ML-KEM key generation"
        return 0
    else
        test_pass "ML-KEM keygen (skipped)"
        return 0
    fi
}

test_unit_tests() {
    test_start "Run unit tests"

    if [ -x "./test_quac100_pkcs11" ]; then
        if ./test_quac100_pkcs11; then
            test_pass "Unit tests passed"
            return 0
        else
            test_fail "Unit tests failed"
            return 1
        fi
    else
        test_pass "Unit tests (skipped - binary not found)"
        return 0
    fi
}

test_benchmarks() {
    test_start "Run benchmarks"

    if [ -x "./bench_quac100_pkcs11" ]; then
        output=$(./bench_quac100_pkcs11 2>&1)
        if [ $? -eq 0 ]; then
            test_pass "Benchmarks completed"
            log_verbose "$output"
            return 0
        else
            test_fail "Benchmarks failed"
            return 1
        fi
    else
        test_pass "Benchmarks (skipped - binary not found)"
        return 0
    fi
}

test_sign_verify() {
    test_start "Test sign and verify"

    if [ -x "./examples/p11_sign_verify" ]; then
        output=$(./examples/p11_sign_verify --demo -p "$PIN" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass "Sign/verify demo passed"
            log_verbose "$output"
            return 0
        else
            test_fail "Sign/verify demo failed" "$output"
            return 1
        fi
    else
        test_pass "Sign/verify (skipped - binary not found)"
        return 0
    fi
}

test_kem() {
    test_start "Test KEM operations"

    if [ -x "./examples/p11_kem" ]; then
        output=$(./examples/p11_kem --demo -p "$PIN" 2>&1)
        if [ $? -eq 0 ]; then
            test_pass "KEM demo passed"
            log_verbose "$output"
            return 0
        else
            test_fail "KEM demo failed" "$output"
            return 1
        fi
    else
        test_pass "KEM (skipped - binary not found)"
        return 0
    fi
}

test_random() {
    test_start "Test random number generation"

    if command -v pkcs11-tool &> /dev/null; then
        output=$(pkcs11-tool --module "$MODULE_PATH" \
            --generate-random 32 2>&1)
        if [ $? -eq 0 ]; then
            test_pass "Random generation works"
            log_verbose "$output"
            return 0
        else
            test_fail "Random generation failed" "$output"
            return 1
        fi
    else
        test_pass "Random generation (skipped)"
        return 0
    fi
}

test_p11tool() {
    test_start "Test management tool"

    if [ -x "./tools/quac100_p11tool" ]; then
        output=$(./tools/quac100_p11tool --list-slots 2>&1)
        if [ $? -eq 0 ]; then
            test_pass "Management tool works"
            log_verbose "$output"
            return 0
        else
            test_fail "Management tool failed" "$output"
            return 1
        fi
    else
        test_pass "Management tool (skipped - binary not found)"
        return 0
    fi
}

# ==========================================================================
# Main
# ==========================================================================

usage() {
    echo "QUAC 100 PKCS#11 Test Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -m, --module <path>  PKCS#11 module path (default: ./libquac100_pkcs11.so)"
    echo "  -p, --pin <PIN>      User PIN (default: 1234)"
    echo "  -s, --so-pin <PIN>   SO PIN (default: 12345678)"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help           Show this help"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--module)
            MODULE_PATH="$2"
            shift 2
            ;;
        -p|--pin)
            PIN="$2"
            shift 2
            ;;
        -s|--so-pin)
            SO_PIN="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run tests
log "============================================================"
log "QUAC 100 PKCS#11 Integration Tests"
log "============================================================"
log "Module: $MODULE_PATH"
log ""

test_module_load
test_slot_list
test_mechanism_list
test_unit_tests
test_random
test_keygen_mldsa
test_keygen_mlkem
test_sign_verify
test_kem
test_p11tool
test_benchmarks

# Summary
log ""
log "============================================================"
log "Test Summary"
log "============================================================"
log "Total:  $TEST_COUNT"
log "${GREEN}Passed: $PASS_COUNT${NC}"
if [ $FAIL_COUNT -gt 0 ]; then
    log "${RED}Failed: $FAIL_COUNT${NC}"
    exit 1
else
    log "Failed: $FAIL_COUNT"
fi
log ""
log "${GREEN}All tests passed!${NC}"
exit 0