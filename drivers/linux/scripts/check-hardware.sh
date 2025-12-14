#!/bin/bash
#=============================================================================
# QUAC 100 Hardware Detection Script
#
# Checks for QUAC 100 hardware presence and provides diagnostic information.
#
# Usage: ./check-hardware.sh [options]
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#=============================================================================

set -e

#-----------------------------------------------------------------------------
# Configuration
#-----------------------------------------------------------------------------

# QUAC 100 PCI IDs (placeholder - actual IDs TBD)
VENDOR_ID="1DYB"
DEVICE_ID="0100"
DEVICE_NAME="QUAC 100 Post-Quantum Cryptographic Accelerator"

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
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}=== $1 ===${NC}"
}

usage() {
    cat << EOF
QUAC 100 Hardware Detection Script

Usage: $(basename "$0") [options]

Options:
    -h, --help          Show this help message
    -v, --verbose       Verbose output
    -q, --quiet         Quiet mode (exit code only)
    -j, --json          Output in JSON format
    --full              Full diagnostic report

Exit Codes:
    0 - Hardware detected and operational
    1 - Hardware not found
    2 - Hardware found but driver not loaded
    3 - Hardware found but in error state
    4 - System error (missing tools)

EOF
    exit 0
}

#-----------------------------------------------------------------------------
# Parse Arguments
#-----------------------------------------------------------------------------

VERBOSE=false
QUIET=false
JSON_OUTPUT=false
FULL_REPORT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -q|--quiet) QUIET=true; shift ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        --full) FULL_REPORT=true; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

#-----------------------------------------------------------------------------
# Check Prerequisites
#-----------------------------------------------------------------------------

check_prerequisites() {
    local missing_tools=()
    
    for tool in lspci modinfo uname; do
        if ! command -v $tool &>/dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: sudo apt-get install pciutils kmod"
        exit 4
    fi
}

#-----------------------------------------------------------------------------
# Detect Hardware
#-----------------------------------------------------------------------------

detect_hardware() {
    local devices=()
    local count=0
    
    # Search for QUAC 100 devices by vendor:device ID
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            devices+=("$line")
            ((count++))
        fi
    done < <(lspci -d "${VENDOR_ID}:${DEVICE_ID}" 2>/dev/null)
    
    # Also search by class (encryption controller)
    # Class 10 = Encryption controller, Subclass 80 = Other
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ ! " ${devices[*]} " =~ " ${line} " ]]; then
            if echo "$line" | grep -qi "quac\|quantacore\|dyber"; then
                devices+=("$line")
                ((count++))
            fi
        fi
    done < <(lspci -d ::1080 2>/dev/null)
    
    DETECTED_COUNT=$count
    DETECTED_DEVICES=("${devices[@]}")
}

#-----------------------------------------------------------------------------
# Get Device Details
#-----------------------------------------------------------------------------

get_device_details() {
    local slot="$1"
    
    # Get verbose device info
    lspci -v -s "$slot" 2>/dev/null
}

get_device_tree() {
    local slot="$1"
    
    # Get device tree info
    lspci -tv 2>/dev/null | grep -A2 -B2 "$slot"
}

#-----------------------------------------------------------------------------
# Check Driver Status
#-----------------------------------------------------------------------------

check_driver() {
    DRIVER_LOADED=false
    DRIVER_VERSION=""
    DRIVER_PATH=""
    
    # Check if module is loaded
    if lsmod | grep -q "^quac100"; then
        DRIVER_LOADED=true
        
        # Get module info
        if modinfo quac100 &>/dev/null; then
            DRIVER_VERSION=$(modinfo quac100 | grep "^version:" | awk '{print $2}')
            DRIVER_PATH=$(modinfo quac100 | grep "^filename:" | awk '{print $2}')
        fi
    fi
    
    # Check if module file exists
    DRIVER_AVAILABLE=false
    if modinfo quac100 &>/dev/null; then
        DRIVER_AVAILABLE=true
    fi
}

#-----------------------------------------------------------------------------
# Check Device Status
#-----------------------------------------------------------------------------

check_device_status() {
    DEVICE_STATUS="unknown"
    DEVICE_INFO=""
    
    if [ -d "/sys/class/quac100" ]; then
        DEVICE_STATUS="active"
        
        # Get device info from sysfs
        for dev in /sys/class/quac100/quac100_*; do
            if [ -d "$dev" ]; then
                local name=$(basename "$dev")
                local status="unknown"
                local temp="N/A"
                local entropy="N/A"
                
                [ -f "$dev/status" ] && status=$(cat "$dev/status")
                [ -f "$dev/temperature" ] && temp=$(cat "$dev/temperature")
                [ -f "$dev/entropy_available" ] && entropy=$(cat "$dev/entropy_available")
                
                DEVICE_INFO+="$name: status=$status, temp=${temp}C, entropy=${entropy}\n"
            fi
        done
    elif [ -c "/dev/quac100_0" ]; then
        DEVICE_STATUS="ready"
    fi
}

#-----------------------------------------------------------------------------
# Check PCIe Link Status
#-----------------------------------------------------------------------------

check_pcie_link() {
    local slot="$1"
    
    # Extract BDF from slot
    local bdf=$(echo "$slot" | grep -oE '[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]')
    
    if [ -n "$bdf" ] && [ -d "/sys/bus/pci/devices/0000:${bdf}" ]; then
        local link_speed=""
        local link_width=""
        local max_speed=""
        local max_width=""
        
        # Read link capabilities
        if [ -f "/sys/bus/pci/devices/0000:${bdf}/current_link_speed" ]; then
            link_speed=$(cat "/sys/bus/pci/devices/0000:${bdf}/current_link_speed")
        fi
        if [ -f "/sys/bus/pci/devices/0000:${bdf}/current_link_width" ]; then
            link_width=$(cat "/sys/bus/pci/devices/0000:${bdf}/current_link_width")
        fi
        if [ -f "/sys/bus/pci/devices/0000:${bdf}/max_link_speed" ]; then
            max_speed=$(cat "/sys/bus/pci/devices/0000:${bdf}/max_link_speed")
        fi
        if [ -f "/sys/bus/pci/devices/0000:${bdf}/max_link_width" ]; then
            max_width=$(cat "/sys/bus/pci/devices/0000:${bdf}/max_link_width")
        fi
        
        echo "Link: ${link_speed} x${link_width} (max: ${max_speed} x${max_width})"
    fi
}

#-----------------------------------------------------------------------------
# JSON Output
#-----------------------------------------------------------------------------

output_json() {
    cat << EOF
{
    "timestamp": "$(date -Iseconds)",
    "hardware": {
        "detected": $DETECTED_COUNT,
        "vendor_id": "${VENDOR_ID}",
        "device_id": "${DEVICE_ID}",
        "devices": [
$(for i in "${!DETECTED_DEVICES[@]}"; do
    echo "            \"${DETECTED_DEVICES[$i]}\""
    [ $i -lt $((DETECTED_COUNT-1)) ] && echo ","
done)
        ]
    },
    "driver": {
        "loaded": $DRIVER_LOADED,
        "available": $DRIVER_AVAILABLE,
        "version": "${DRIVER_VERSION:-null}",
        "path": "${DRIVER_PATH:-null}"
    },
    "status": {
        "device_status": "${DEVICE_STATUS}",
        "operational": $([ "$DEVICE_STATUS" = "active" ] && echo "true" || echo "false")
    }
}
EOF
}

#-----------------------------------------------------------------------------
# Text Output
#-----------------------------------------------------------------------------

output_text() {
    echo "========================================"
    echo " QUAC 100 Hardware Detection Report"
    echo " $(date)"
    echo "========================================"
    
    log_section "Hardware Detection"
    
    if [ $DETECTED_COUNT -gt 0 ]; then
        log_success "Found $DETECTED_COUNT QUAC 100 device(s)"
        echo ""
        for device in "${DETECTED_DEVICES[@]}"; do
            echo "  $device"
            if $VERBOSE; then
                local slot=$(echo "$device" | awk '{print $1}')
                check_pcie_link "$slot"
            fi
        done
    else
        log_error "No QUAC 100 hardware detected"
        echo ""
        echo "  Searched for PCI ID: ${VENDOR_ID}:${DEVICE_ID}"
        echo ""
        echo "  Troubleshooting:"
        echo "    1. Ensure device is properly seated in PCIe slot"
        echo "    2. Check system BIOS for PCIe settings"
        echo "    3. Verify device is not disabled in BIOS"
        echo "    4. Check for hardware damage or compatibility"
    fi
    
    log_section "Driver Status"
    
    if $DRIVER_LOADED; then
        log_success "Driver loaded: quac100"
        echo "  Version: ${DRIVER_VERSION:-unknown}"
        if $VERBOSE; then
            echo "  Path: ${DRIVER_PATH:-unknown}"
        fi
    elif $DRIVER_AVAILABLE; then
        log_warn "Driver available but not loaded"
        echo "  Load with: sudo modprobe quac100"
    else
        log_error "Driver not installed"
        echo "  Install with: sudo dkms install quac100/1.0.0"
    fi
    
    log_section "Device Status"
    
    case "$DEVICE_STATUS" in
        active)
            log_success "Device(s) operational"
            echo -e "$DEVICE_INFO"
            ;;
        ready)
            log_success "Device node(s) ready"
            ls -la /dev/quac100_* 2>/dev/null
            ;;
        *)
            log_warn "Device status: $DEVICE_STATUS"
            ;;
    esac
    
    if $FULL_REPORT; then
        log_section "System Information"
        echo "  Kernel: $(uname -r)"
        echo "  Architecture: $(uname -m)"
        echo "  Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
        
        log_section "IOMMU Status"
        if [ -d "/sys/class/iommu" ]; then
            log_success "IOMMU enabled"
            dmesg | grep -i iommu | tail -5 2>/dev/null
        else
            log_info "IOMMU not detected (not required)"
        fi
        
        log_section "Secure Boot Status"
        if command -v mokutil &>/dev/null; then
            mokutil --sb-state 2>/dev/null || echo "  Unable to determine"
        else
            echo "  mokutil not installed"
        fi
    fi
    
    echo ""
    echo "========================================"
}

#-----------------------------------------------------------------------------
# Determine Exit Code
#-----------------------------------------------------------------------------

determine_exit_code() {
    if [ $DETECTED_COUNT -eq 0 ]; then
        return 1  # Hardware not found
    elif ! $DRIVER_LOADED; then
        return 2  # Hardware found but driver not loaded
    elif [ "$DEVICE_STATUS" != "active" ] && [ "$DEVICE_STATUS" != "ready" ]; then
        return 3  # Hardware found but in error state
    else
        return 0  # All good
    fi
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

main() {
    check_prerequisites
    
    detect_hardware
    check_driver
    check_device_status
    
    if $QUIET; then
        determine_exit_code
        exit $?
    fi
    
    if $JSON_OUTPUT; then
        output_json
    else
        output_text
    fi
    
    determine_exit_code
    exit $?
}

main "$@"