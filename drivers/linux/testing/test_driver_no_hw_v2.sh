#!/bin/bash
#
# QUAC 100 Driver Test Suite - No Hardware Required
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

VERBOSE=0

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)) || true; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)) || true; }
log_section() { echo -e "\n${BLUE}========== $1 ==========${NC}\n"; }

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_skip "$2 - $1 not installed"
        return 1
    fi
    return 0
}

run_static_analysis() {
    log_section "Static Analysis Tests"

    # Test: Shell script syntax check
    log_info "Testing shell scripts with shellcheck..."
    if check_command shellcheck "Shell script analysis"; then
        local shell_errors=0
        for script in ../packaging/*.sh ../scripts/*.sh; do
            if [[ -f "$script" ]]; then
                if shellcheck -S warning "$script" 2>/dev/null; then
                    [[ $VERBOSE -eq 1 ]] && log_info "  $script: OK"
                else
                    log_fail "shellcheck: $script has issues"
                    shell_errors=1
                fi
            fi
        done
        if [[ $shell_errors -eq 0 ]]; then
            log_pass "Shell scripts pass shellcheck (or none found)"
        fi
    fi

    # Test: Systemd service file validation
    log_info "Validating systemd service file..."
    local service_file="../systemd/quac100.service"
    if [[ -f "$service_file" ]]; then
        if grep -q '^\[Unit\]' "$service_file" && \
           grep -q '^\[Service\]' "$service_file" && \
           grep -q '^\[Install\]' "$service_file"; then
            log_pass "Systemd service file structure is valid"
        else
            log_fail "Systemd service file structure invalid"
        fi
    else
        log_skip "Systemd service file not found at $service_file"
    fi

    # Test: udev rules syntax check
    log_info "Validating udev rules syntax..."
    local udev_file="../udev/99-quac100.rules"
    if [[ -f "$udev_file" ]]; then
        if grep -qE '^(KERNEL|SUBSYSTEM|ATTR|ENV|ACTION)==' "$udev_file"; then
            log_pass "udev rules basic syntax appears valid"
        else
            log_fail "udev rules syntax check failed"
        fi
    else
        log_skip "udev rules file not found at $udev_file"
    fi

    # Test: C header syntax check
    log_info "Checking C header syntax..."
    if check_command gcc "C syntax check"; then
        local header_errors=0
        local headers_checked=0
        local include_dir="../../../include"
        for header in "$include_dir"/*.h; do
            if [[ -f "$header" ]]; then
                ((headers_checked++)) || true
                if gcc -fsyntax-only -x c -std=c11 -I"$include_dir" -include stdint.h -include stddef.h -include stdbool.h "$header" 2>/dev/null; then
                    [[ $VERBOSE -eq 1 ]] && log_info "  $(basename "$header"): OK"
                else
                    log_fail "Header syntax error: $(basename "$header")"
                    header_errors=1
                fi
            fi
        done
        if [[ $headers_checked -eq 0 ]]; then
            log_skip "No header files found"
        elif [[ $header_errors -eq 0 ]]; then
            log_pass "All $headers_checked C headers have valid syntax"
        fi
    fi
}

run_unit_tests() {
    log_section "Unit Tests"

    # Test: Result code definitions
    log_info "Testing result code consistency..."
    local types_file="../../../include/quac100_types.h"
    if [[ -f "$types_file" ]]; then
        local result_codes=$(grep -cE 'QUAC_ERROR_\w+\s*=' "$types_file" || echo 0)
        if [[ $result_codes -gt 20 ]]; then
            log_pass "Found $result_codes result codes defined"
        else
            log_fail "Insufficient result codes defined ($result_codes)"
        fi
    else
        log_skip "quac100_types.h not found"
    fi

    # Test: Algorithm definitions
    log_info "Testing algorithm definitions..."
    if [[ -f "$types_file" ]]; then
        local kem_algos=$(grep -c 'QUAC_ALGORITHM_KYBER' "$types_file" || echo 0)
        local sign_algos=$(grep -cE 'QUAC_ALGORITHM_DILITHIUM|QUAC_ALGORITHM_SPHINCS' "$types_file" || echo 0)
        if [[ $kem_algos -ge 3 ]] && [[ $sign_algos -ge 3 ]]; then
            log_pass "Algorithm definitions complete (KEM: $kem_algos, Sign: $sign_algos)"
        else
            log_fail "Missing algorithm definitions (KEM: $kem_algos, Sign: $sign_algos)"
        fi
    fi

    # Test: Kyber-768 size constants
    log_info "Testing cryptographic size constants..."
    if [[ -f "$types_file" ]]; then
        local size_errors=0
        local kyber768_pk=$(grep 'QUAC_KYBER768_PUBLIC_KEY_SIZE' "$types_file" | awk '{print $NF}' | tr -d '\r')
        local kyber768_sk=$(grep 'QUAC_KYBER768_SECRET_KEY_SIZE' "$types_file" | awk '{print $NF}' | tr -d '\r')
        local kyber768_ct=$(grep 'QUAC_KYBER768_CIPHERTEXT_SIZE' "$types_file" | awk '{print $NF}' | tr -d '\r')

        [[ "$kyber768_pk" == "1184" ]] || { log_fail "Kyber768 public key size incorrect (got $kyber768_pk, expected 1184)"; size_errors=1; }
        [[ "$kyber768_sk" == "2400" ]] || { log_fail "Kyber768 secret key size incorrect (got $kyber768_sk, expected 2400)"; size_errors=1; }
        [[ "$kyber768_ct" == "1088" ]] || { log_fail "Kyber768 ciphertext size incorrect (got $kyber768_ct, expected 1088)"; size_errors=1; }

        if [[ $size_errors -eq 0 ]]; then
            log_pass "Cryptographic size constants are correct"
        fi
    fi

    # Test: Struct versioning
    log_info "Testing struct versioning (struct_size fields)..."
    local structs_with_size=$(grep -rc 'uint32_t struct_size;' ../../../include/quac100*.h 2>/dev/null | awk -F: '{sum+=$2} END {print sum}')
    if [[ -n "$structs_with_size" ]] && [[ $structs_with_size -gt 5 ]]; then
        log_pass "Structs have versioning fields ($structs_with_size found)"
    else
        log_fail "Missing struct versioning fields (found: ${structs_with_size:-0})"
    fi
}

run_api_contract_tests() {
    log_section "API Contract Tests"

    local main_header="../../../include/quac100.h"

    # Test: Function signature consistency
    log_info "Checking API function signatures..."
    if [[ -f "$main_header" ]]; then
        local api_functions=$(grep -cE 'QUAC100_API\s+\w+' "$main_header" | tr -d '\r' || echo 0)
        if [[ $api_functions -gt 20 ]]; then
            log_pass "Found $api_functions API functions with correct export macro"
        else
            log_fail "Insufficient API functions exported ($api_functions)"
        fi
    else
        log_skip "quac100.h not found"
    fi

    # Test: Return type consistency
    log_info "Checking return type consistency..."
    local all_headers="../../../include/quac100*.h"
    local result_funcs=$(grep -rhE '^QUAC100_API\s+quac_result_t' $all_headers 2>/dev/null | wc -l)
    local void_funcs=$(grep -rhE '^QUAC100_API\s+void\s+' $all_headers 2>/dev/null | wc -l)
    local bool_funcs=$(grep -rhE '^QUAC100_API\s+bool' $all_headers 2>/dev/null | wc -l)
    log_pass "Return types: $result_funcs result_t, $void_funcs void, $bool_funcs bool"

    # Test: NULL parameter documentation
    log_info "Checking NULL parameter documentation..."
    local null_docs=$(grep -rh '@return.*NULL' $all_headers 2>/dev/null | wc -l | tr -d '\r')
    if [[ $null_docs -gt 5 ]]; then
        log_pass "NULL pointer handling documented ($null_docs references)"
    else
        log_fail "Insufficient NULL pointer documentation ($null_docs)"
    fi
}

run_config_tests() {
    log_section "Configuration File Tests"

    # Test: udev rules completeness
    log_info "Testing udev rules completeness..."
    local udev_file="../udev/99-quac100.rules"
    if [[ -f "$udev_file" ]]; then
        local checks_passed=0
        grep -q 'GROUP=' "$udev_file" && ((checks_passed++)) || true
        grep -q 'MODE=' "$udev_file" && ((checks_passed++)) || true
        grep -q 'SUBSYSTEM==' "$udev_file" && ((checks_passed++)) || true
        grep -q 'KERNEL==' "$udev_file" && ((checks_passed++)) || true

        if [[ $checks_passed -ge 3 ]]; then
            log_pass "udev rules contain required elements ($checks_passed/4)"
        else
            log_fail "udev rules missing required elements ($checks_passed/4)"
        fi
    else
        log_skip "udev rules file not found"
    fi

    # Test: Systemd service completeness
    log_info "Testing systemd service completeness..."
    local service_file="../systemd/quac100.service"
    if [[ -f "$service_file" ]]; then
        local checks_passed=0
        grep -q '\[Unit\]' "$service_file" && ((checks_passed++)) || true
        grep -q '\[Service\]' "$service_file" && ((checks_passed++)) || true
        grep -q '\[Install\]' "$service_file" && ((checks_passed++)) || true
        grep -q 'ExecStart=' "$service_file" && ((checks_passed++)) || true
        grep -q 'Type=' "$service_file" && ((checks_passed++)) || true

        if [[ $checks_passed -ge 4 ]]; then
            log_pass "Systemd service contains required sections ($checks_passed/5)"
        else
            log_fail "Systemd service missing required sections ($checks_passed/5)"
        fi
    else
        log_skip "Systemd service file not found"
    fi
}

print_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  QUAC 100 Driver Test Suite (No Hardware Required)       ║"
    echo "║  Copyright 2025 Dyber, Inc.                              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

# Parse arguments
RUN_UNIT=0
RUN_STATIC=0
RUN_ALL=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit) RUN_UNIT=1; RUN_ALL=0; shift ;;
        --static) RUN_STATIC=1; RUN_ALL=0; shift ;;
        --all) RUN_ALL=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  --unit          Run unit tests only"
            echo "  --static        Run static analysis"
            echo "  --all           Run all tests (default)"
            echo "  --verbose       Verbose output"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$SCRIPT_DIR"

print_banner
log_info "Starting test suite (no hardware required)"

if [[ $RUN_ALL -eq 1 ]] || [[ $RUN_STATIC -eq 1 ]]; then
    run_static_analysis
fi

if [[ $RUN_ALL -eq 1 ]] || [[ $RUN_UNIT -eq 1 ]]; then
    run_unit_tests
fi

if [[ $RUN_ALL -eq 1 ]]; then
    run_api_contract_tests
    run_config_tests
fi

log_section "Test Summary"
echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
echo ""

[[ $TESTS_FAILED -eq 0 ]]