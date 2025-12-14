# QUAC 100 Mock Driver Makefile
#
# Build the mock kernel module for testing without hardware
#
# Usage:
#   make              - Build the module
#   make clean        - Clean build artifacts
#   make install      - Install module (requires root)
#   make load         - Load the module
#   make unload       - Unload the module
#   make test         - Run basic tests after loading
#

obj-m := quac100_mock.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module parameters for testing
NUM_DEVICES ?= 2
SIM_LATENCY ?= 100
FAIL_RATE ?= 0
DEBUG_LEVEL ?= 4

.PHONY: all clean install load unload test status help

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

install: all
	sudo cp quac100_mock.ko /lib/modules/$(shell uname -r)/extra/
	sudo depmod -a

load: all
	@if lsmod | grep -q quac100_mock; then \
		echo "Module already loaded, reloading..."; \
		sudo rmmod quac100_mock; \
	fi
	sudo insmod quac100_mock.ko \
		num_devices=$(NUM_DEVICES) \
		sim_latency_us=$(SIM_LATENCY) \
		fail_rate=$(FAIL_RATE) \
		debug_level=$(DEBUG_LEVEL)
	@echo "Module loaded. Devices:"
	@ls -la /dev/quac100_* 2>/dev/null || echo "  (no devices created)"
	@echo ""
	@dmesg | tail -10

unload:
	@if lsmod | grep -q quac100_mock; then \
		sudo rmmod quac100_mock; \
		echo "Module unloaded"; \
		dmesg | tail -5; \
	else \
		echo "Module not loaded"; \
	fi

status:
	@echo "=== Module Status ==="
	@lsmod | grep quac100 || echo "Module not loaded"
	@echo ""
	@echo "=== Devices ==="
	@ls -la /dev/quac100_* 2>/dev/null || echo "No devices"
	@echo ""
	@echo "=== Sysfs Attributes ==="
	@for dev in /sys/class/quac100/quac100_*; do \
		if [ -d "$$dev" ]; then \
			echo "$$dev:"; \
			cat "$$dev/temperature" 2>/dev/null && echo "  temperature: $$(cat $$dev/temperature)°C"; \
			cat "$$dev/entropy" 2>/dev/null && echo "  entropy: $$(cat $$dev/entropy) bits"; \
			cat "$$dev/simulator" 2>/dev/null && echo "  simulator: $$(cat $$dev/simulator)"; \
		fi \
	done 2>/dev/null || echo "No sysfs entries"

test: load
	@echo ""
	@echo "=== Running Basic Tests ==="
	@echo ""
	@# Test 1: Check devices exist
	@echo "Test 1: Device nodes..."
	@if [ -c /dev/quac100_0 ]; then \
		echo "  PASS: /dev/quac100_0 exists"; \
	else \
		echo "  FAIL: /dev/quac100_0 not found"; \
	fi
	@echo ""
	@# Test 2: Check sysfs
	@echo "Test 2: Sysfs attributes..."
	@if [ -f /sys/class/quac100/quac100_0/temperature ]; then \
		echo "  PASS: sysfs temperature readable: $$(cat /sys/class/quac100/quac100_0/temperature)°C"; \
	else \
		echo "  FAIL: sysfs not accessible"; \
	fi
	@echo ""
	@# Test 3: Check simulator flag
	@echo "Test 3: Simulator mode..."
	@if [ "$$(cat /sys/class/quac100/quac100_0/simulator 2>/dev/null)" = "1" ]; then \
		echo "  PASS: Running in simulator mode"; \
	else \
		echo "  FAIL: Simulator flag not set"; \
	fi
	@echo ""
	@echo "=== Basic Tests Complete ==="

help:
	@echo "QUAC 100 Mock Driver Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the kernel module"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system modules directory"
	@echo "  load     - Load the module with test parameters"
	@echo "  unload   - Unload the module"
	@echo "  status   - Show module and device status"
	@echo "  test     - Load module and run basic tests"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Parameters (set with make VAR=value):"
	@echo "  NUM_DEVICES  - Number of mock devices (default: 2)"
	@echo "  SIM_LATENCY  - Operation latency in μs (default: 100)"
	@echo "  FAIL_RATE    - Failures per 10000 ops (default: 0)"
	@echo "  DEBUG_LEVEL  - Debug verbosity 0-7 (default: 4)"
	@echo ""
	@echo "Examples:"
	@echo "  make load NUM_DEVICES=4"
	@echo "  make test FAIL_RATE=100"