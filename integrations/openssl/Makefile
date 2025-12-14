# =============================================================================
# QUAC 100 OpenSSL Provider Makefile
# =============================================================================
#
# Simple Makefile alternative to CMake for building the provider.
#
# Usage:
#   make              - Build the provider
#   make test         - Run tests
#   make install      - Install provider
#   make clean        - Clean build artifacts
#
# Options:
#   QUAC_SDK_PATH     - Path to QUAC 100 SDK (enables hardware support)
#   OPENSSL_PATH      - Path to OpenSSL installation
#   DEBUG=1           - Build with debug symbols
#   PREFIX            - Installation prefix (default: /usr/local)
#
# Examples:
#   make
#   make QUAC_SDK_PATH=/opt/quantacore-sdk
#   make DEBUG=1
#   sudo make install PREFIX=/usr
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := Linux
    LIB_EXT := .so
    SHARED_FLAGS := -shared -fPIC
endif
ifeq ($(UNAME_S),Darwin)
    OS := macOS
    LIB_EXT := .dylib
    SHARED_FLAGS := -dynamiclib -fPIC
endif
ifeq ($(OS),Windows_NT)
    OS := Windows
    LIB_EXT := .dll
    SHARED_FLAGS := -shared
endif

# =============================================================================
# Configuration
# =============================================================================

# Compiler
CC ?= gcc
AR ?= ar

# Installation prefix
PREFIX ?= /usr/local

# OpenSSL paths
OPENSSL_PATH ?= $(shell pkg-config --variable=prefix openssl 2>/dev/null || echo /usr)
OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
OPENSSL_LIB ?= $(OPENSSL_PATH)/lib
OPENSSL_MODULES ?= $(OPENSSL_LIB)/ossl-modules

# QUAC SDK (optional)
ifdef QUAC_SDK_PATH
    QUAC_INCLUDE := $(QUAC_SDK_PATH)/include
    QUAC_LIB := $(QUAC_SDK_PATH)/lib
    QUAC_CFLAGS := -I$(QUAC_INCLUDE) -DQUAC_HAS_HARDWARE=1
    QUAC_LDFLAGS := -L$(QUAC_LIB) -lquac100
else
    QUAC_CFLAGS :=
    QUAC_LDFLAGS :=
endif

# =============================================================================
# Compiler Flags
# =============================================================================

CFLAGS := -Wall -Wextra -Wpedantic -std=c11 -fvisibility=hidden
CFLAGS += -I$(OPENSSL_INCLUDE) -I.
CFLAGS += $(QUAC_CFLAGS)

LDFLAGS := -L$(OPENSSL_LIB)
LDFLAGS += -lssl -lcrypto
LDFLAGS += $(QUAC_LDFLAGS)

# Debug/Release
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# =============================================================================
# Source Files
# =============================================================================

PROVIDER_SOURCES := \
    quac100_provider.c \
    quac100_kem_alg.c \
    quac100_sig_alg.c \
    quac100_rand.c \
    quac100_encoder.c \
    quac100_store.c \
    quac100_keyexch.c \
    quac100_bench.c

PROVIDER_OBJECTS := $(PROVIDER_SOURCES:.c=.o)
PROVIDER_NAME := quac100$(LIB_EXT)

TEST_SOURCES := test_provider.c
TEST_BINARY := test_provider

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean install uninstall test check help

all: $(PROVIDER_NAME)

# Provider shared library
$(PROVIDER_NAME): $(PROVIDER_OBJECTS)
	$(CC) $(SHARED_FLAGS) -o $@ $^ $(LDFLAGS)
ifeq ($(OS),Linux)
	# Create version script to export only OSSL_provider_init
	@echo "Limiting exported symbols..."
endif

# Object files
%.o: %.c quac100_provider.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Test binary
$(TEST_BINARY): test_provider.c $(PROVIDER_NAME)
	$(CC) $(CFLAGS) -o $@ $< -L. -lssl -lcrypto -Wl,-rpath,.

# =============================================================================
# Testing
# =============================================================================

test: $(PROVIDER_NAME) $(TEST_BINARY)
	@echo "=== Running Provider Tests ==="
	./$(TEST_BINARY) .
	@echo ""
	@echo "=== Running Shell Tests ==="
	./test_provider.sh .

check: test

# Quick smoke test
smoke: $(PROVIDER_NAME)
	@echo "=== Smoke Test ==="
	OPENSSL_MODULES=. openssl list -providers -provider quac100
	@echo "Provider loaded successfully!"

# =============================================================================
# Installation
# =============================================================================

install: $(PROVIDER_NAME)
	@echo "Installing to $(DESTDIR)$(OPENSSL_MODULES)..."
	install -d $(DESTDIR)$(OPENSSL_MODULES)
	install -m 755 $(PROVIDER_NAME) $(DESTDIR)$(OPENSSL_MODULES)/
	install -d $(DESTDIR)$(PREFIX)/share/quac100
	install -m 644 openssl.cnf.example $(DESTDIR)$(PREFIX)/share/quac100/
	install -m 644 README.md $(DESTDIR)$(PREFIX)/share/quac100/
	@echo "Installation complete."
	@echo ""
	@echo "To use the provider, add to openssl.cnf:"
	@echo "  [provider_sect]"
	@echo "  quac100 = quac100_sect"
	@echo "  [quac100_sect]"
	@echo "  module = $(OPENSSL_MODULES)/$(PROVIDER_NAME)"
	@echo "  activate = 1"

uninstall:
	rm -f $(DESTDIR)$(OPENSSL_MODULES)/$(PROVIDER_NAME)
	rm -rf $(DESTDIR)$(PREFIX)/share/quac100

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -f $(PROVIDER_OBJECTS) $(PROVIDER_NAME) $(TEST_BINARY)
	rm -f *.o *.so *.dylib *.dll
	rm -f test_*.pem test_*.sig test_*.bin

distclean: clean
	rm -f config.log config.status

# =============================================================================
# Development Helpers
# =============================================================================

# Show configuration
info:
	@echo "=== Build Configuration ==="
	@echo "OS:            $(OS)"
	@echo "CC:            $(CC)"
	@echo "CFLAGS:        $(CFLAGS)"
	@echo "LDFLAGS:       $(LDFLAGS)"
	@echo "PREFIX:        $(PREFIX)"
	@echo "OPENSSL_PATH:  $(OPENSSL_PATH)"
	@echo "OPENSSL_MODULES: $(OPENSSL_MODULES)"
ifdef QUAC_SDK_PATH
	@echo "QUAC_SDK_PATH: $(QUAC_SDK_PATH)"
	@echo "Hardware:      ENABLED"
else
	@echo "Hardware:      DISABLED (simulator only)"
endif

# Format code
format:
	clang-format -i *.c *.h

# Static analysis
analyze:
	cppcheck --enable=all --std=c11 $(PROVIDER_SOURCES)

# Generate compile_commands.json for IDEs
compile_commands:
	@echo "[" > compile_commands.json
	@for f in $(PROVIDER_SOURCES); do \
		echo "  {\"directory\": \"$(PWD)\", \"command\": \"$(CC) $(CFLAGS) -c $$f\", \"file\": \"$$f\"},"; \
	done >> compile_commands.json
	@echo "  {}" >> compile_commands.json
	@echo "]" >> compile_commands.json

# =============================================================================
# Help
# =============================================================================

help:
	@echo "QUAC 100 OpenSSL Provider Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the provider (default)"
	@echo "  test       - Run all tests"
	@echo "  smoke      - Quick smoke test"
	@echo "  install    - Install provider to system"
	@echo "  uninstall  - Remove installed provider"
	@echo "  clean      - Remove build artifacts"
	@echo "  info       - Show build configuration"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  QUAC_SDK_PATH=/path  - Enable hardware support"
	@echo "  OPENSSL_PATH=/path   - Specify OpenSSL location"
	@echo "  DEBUG=1              - Build with debug symbols"
	@echo "  PREFIX=/path         - Installation prefix"
	@echo ""
	@echo "Examples:"
	@echo "  make"
	@echo "  make QUAC_SDK_PATH=/opt/quantacore-sdk"
	@echo "  make DEBUG=1 test"
	@echo "  sudo make install"

# =============================================================================
# Dependencies (auto-generated)
# =============================================================================

quac100_provider.o: quac100_provider.c quac100_provider.h
quac100_kem_alg.o: quac100_kem_alg.c quac100_provider.h
quac100_sig_alg.o: quac100_sig_alg.c quac100_provider.h
quac100_rand.o: quac100_rand.c quac100_provider.h
quac100_encoder.o: quac100_encoder.c quac100_provider.h
quac100_store.o: quac100_store.c quac100_provider.h
quac100_keyexch.o: quac100_keyexch.c quac100_provider.h
quac100_bench.o: quac100_bench.c quac100_provider.h