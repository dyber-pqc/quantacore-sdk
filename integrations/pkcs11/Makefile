# =============================================================================
# QUAC 100 PKCS#11 Module - Makefile
# =============================================================================
#
# Build system for the QUAC 100 PKCS#11 cryptographic token interface.
#
# Usage:
#   make                    # Build shared library
#   make test               # Build and run tests
#   make example            # Build example programs
#   make bench              # Build benchmark
#   make install            # Install to system
#   make clean              # Clean build artifacts
#
# Options:
#   QUAC_SDK_PATH=/path     Enable hardware acceleration
#   DEBUG=1                 Build with debug symbols
#   PREFIX=/usr/local       Installation prefix
#
# Examples:
#   make
#   make QUAC_SDK_PATH=/opt/quac-sdk
#   make DEBUG=1 test
#   make PREFIX=/usr install
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# Installation prefix
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

# QUAC SDK path (optional, for hardware acceleration)
QUAC_SDK_PATH ?=

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := linux
    SHARED_EXT := .so
    LDFLAGS_SHARED := -shared -Wl,-soname,libquac100_pkcs11.so.1
endif
ifeq ($(UNAME_S),Darwin)
    OS := macos
    SHARED_EXT := .dylib
    LDFLAGS_SHARED := -dynamiclib -install_name @rpath/libquac100_pkcs11.1.dylib
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
    OS := windows
    SHARED_EXT := .dll
    LDFLAGS_SHARED := -shared
endif
ifneq (,$(findstring MSYS,$(UNAME_S)))
    OS := windows
    SHARED_EXT := .dll
    LDFLAGS_SHARED := -shared
endif

# Compiler settings
CC ?= gcc
AR ?= ar

# Base flags
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -fPIC
CFLAGS += -fvisibility=hidden

# Debug/Release flags
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O3 -DNDEBUG
endif

# Include paths
CFLAGS += -I.

# OpenSSL (required for software simulation)
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null)

ifeq ($(OPENSSL_LIBS),)
    # Fallback if pkg-config not available
    OPENSSL_LIBS := -lssl -lcrypto
endif

CFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

# pthreads
ifneq ($(OS),windows)
    LDFLAGS += -lpthread
endif

# QUAC SDK (optional)
ifneq ($(QUAC_SDK_PATH),)
    CFLAGS += -DQUAC_HAS_HARDWARE -I$(QUAC_SDK_PATH)/include
    LDFLAGS += -L$(QUAC_SDK_PATH)/lib -lquac100
endif

# Dynamic loading (for tests/examples)
ifneq ($(OS),windows)
    LDFLAGS_DL := -ldl
endif

# -----------------------------------------------------------------------------
# Source Files
# -----------------------------------------------------------------------------

SOURCES := \
    quac100_pkcs11.c \
    quac100_pkcs11_slot.c \
    quac100_pkcs11_session.c \
    quac100_pkcs11_object.c \
    quac100_pkcs11_crypto.c

HEADERS := \
    quac100_pkcs11.h \
    quac100_pkcs11_internal.h

OBJECTS := $(SOURCES:.c=.o)

# -----------------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------------

# Library names
LIB_SHARED := libquac100_pkcs11$(SHARED_EXT)
LIB_STATIC := libquac100_pkcs11.a

# Default target
.PHONY: all
all: $(LIB_SHARED) $(LIB_STATIC)

# Shared library
$(LIB_SHARED): $(OBJECTS)
	$(CC) $(LDFLAGS_SHARED) -o $@ $^ $(LDFLAGS)
ifeq ($(OS),linux)
	ln -sf $@ libquac100_pkcs11.so.1
	ln -sf $@ libquac100_pkcs11.so
endif
ifeq ($(OS),macos)
	ln -sf $@ libquac100_pkcs11.1.dylib
	ln -sf $@ libquac100_pkcs11.dylib
endif

# Static library
$(LIB_STATIC): $(OBJECTS)
	$(AR) rcs $@ $^

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# -----------------------------------------------------------------------------
# Test Suite
# -----------------------------------------------------------------------------

TEST_SRC := test_quac100_pkcs11.c
TEST_BIN := test_quac100_pkcs11

.PHONY: test
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(LIB_SHARED)
	$(CC) $(CFLAGS) -o $@ $< -L. -lquac100_pkcs11 $(LDFLAGS) $(LDFLAGS_DL) -Wl,-rpath,.

# -----------------------------------------------------------------------------
# Example Programs
# -----------------------------------------------------------------------------

EXAMPLE_SRC := example_pkcs11.c
EXAMPLE_BIN := example_pkcs11

BENCH_SRC := bench_pkcs11.c
BENCH_BIN := bench_pkcs11

.PHONY: example
example: $(EXAMPLE_BIN)

$(EXAMPLE_BIN): $(EXAMPLE_SRC) $(LIB_SHARED)
	$(CC) $(CFLAGS) -o $@ $< -L. -lquac100_pkcs11 $(LDFLAGS_DL) -Wl,-rpath,.

.PHONY: bench
bench: $(BENCH_BIN)

$(BENCH_BIN): $(BENCH_SRC) $(LIB_SHARED)
	$(CC) $(CFLAGS) -o $@ $< -L. -lquac100_pkcs11 $(LDFLAGS_DL) -Wl,-rpath,.

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------

.PHONY: install
install: $(LIB_SHARED) $(LIB_STATIC)
	@echo "Installing to $(PREFIX)..."
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 755 $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/
	install -m 644 $(LIB_STATIC) $(DESTDIR)$(LIBDIR)/
	install -m 644 quac100_pkcs11.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 quac100_pkcs11_internal.h $(DESTDIR)$(INCLUDEDIR)/
ifeq ($(OS),linux)
	ln -sf $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/libquac100_pkcs11.so.1
	ln -sf $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/libquac100_pkcs11.so
	ldconfig -n $(DESTDIR)$(LIBDIR) 2>/dev/null || true
endif
ifeq ($(OS),macos)
	ln -sf $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/libquac100_pkcs11.1.dylib
	ln -sf $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/libquac100_pkcs11.dylib
endif
	@echo "Installation complete."

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/libquac100_pkcs11*
	rm -f $(DESTDIR)$(INCLUDEDIR)/quac100_pkcs11.h
	rm -f $(DESTDIR)$(INCLUDEDIR)/quac100_pkcs11_internal.h

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -f $(OBJECTS)
	rm -f $(LIB_SHARED) $(LIB_STATIC)
	rm -f libquac100_pkcs11.so* libquac100_pkcs11*.dylib
	rm -f $(TEST_BIN) $(EXAMPLE_BIN) $(BENCH_BIN)

.PHONY: distclean
distclean: clean
	rm -rf build/

# -----------------------------------------------------------------------------
# Development Helpers
# -----------------------------------------------------------------------------

.PHONY: format
format:
	clang-format -i $(SOURCES) $(HEADERS)

.PHONY: check
check:
	cppcheck --enable=all --std=c11 $(SOURCES)

.PHONY: docs
docs:
	doxygen Doxyfile

# -----------------------------------------------------------------------------
# Package
# -----------------------------------------------------------------------------

VERSION := 1.0.0
PACKAGE := quac100-pkcs11-$(VERSION)

.PHONY: dist
dist:
	mkdir -p $(PACKAGE)
	cp -r $(SOURCES) $(HEADERS) Makefile CMakeLists.txt README.md $(PACKAGE)/
	cp quac100_pkcs11.def $(PACKAGE)/
	cp test_quac100_pkcs11.c example_pkcs11.c bench_pkcs11.c $(PACKAGE)/
	tar czf $(PACKAGE).tar.gz $(PACKAGE)
	rm -rf $(PACKAGE)

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

.PHONY: help
help:
	@echo "QUAC 100 PKCS#11 Module Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build shared and static libraries (default)"
	@echo "  test      - Build and run test suite"
	@echo "  example   - Build example program"
	@echo "  bench     - Build benchmark program"
	@echo "  install   - Install to system (PREFIX=$(PREFIX))"
	@echo "  uninstall - Remove installed files"
	@echo "  clean     - Remove build artifacts"
	@echo "  dist      - Create distribution tarball"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1                 Build with debug symbols"
	@echo "  QUAC_SDK_PATH=/path     Path to QUAC SDK for hardware support"
	@echo "  PREFIX=/path            Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Examples:"
	@echo "  make"
	@echo "  make DEBUG=1 test"
	@echo "  make QUAC_SDK_PATH=/opt/quac-sdk"
	@echo "  make PREFIX=/usr install"