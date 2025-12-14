# SPDX-License-Identifier: GPL-2.0-only
#
# QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
# Linux Kernel Driver - Makefile
#
# Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
#

# Module name
MODULE_NAME := quac100

# Kernel source directory
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD := $(shell pwd)

# Module version
VERSION := 1.0.0

# Build flags
ccflags-y := -DQUAC100_VERSION=\"$(VERSION)\"
ccflags-$(CONFIG_DEBUG_INFO) += -g

# Default target
all: modules

# Build kernel module
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

# Install module
install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a $(KVER)

# Uninstall module
uninstall:
	rm -f /lib/modules/$(KVER)/extra/$(MODULE_NAME).ko
	depmod -a $(KVER)

# Load module
load:
	modprobe $(MODULE_NAME)

# Unload module
unload:
	modprobe -r $(MODULE_NAME)

# Reload module
reload: unload load

# Check module info
info:
	modinfo $(MODULE_NAME).ko

# Run checkpatch
checkpatch:
	$(KDIR)/scripts/checkpatch.pl --no-tree -f *.c *.h

# Generate compile_commands.json for IDE support
compile_commands:
	$(MAKE) -C $(KDIR) M=$(PWD) compile_commands.json

# Help target
help:
	@echo "QuantaCore QUAC 100 Driver Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build kernel module (default)"
	@echo "  modules     - Build kernel module"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install module to system"
	@echo "  uninstall   - Remove module from system"
	@echo "  load        - Load module into running kernel"
	@echo "  unload      - Unload module from running kernel"
	@echo "  reload      - Reload module (unload + load)"
	@echo "  info        - Show module information"
	@echo "  checkpatch  - Run kernel checkpatch script"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Build options:"
	@echo "  KVER=<version>   - Kernel version (default: current)"
	@echo "  KDIR=<path>      - Kernel source directory"
	@echo ""
	@echo "Example:"
	@echo "  make KVER=5.15.0-generic"

.PHONY: all modules clean install uninstall load unload reload info checkpatch compile_commands help