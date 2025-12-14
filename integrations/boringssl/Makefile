# =============================================================================
# QUAC 100 BoringSSL Integration - Makefile
# =============================================================================
#
# Usage:
#   make                              Build library
#   make BORINGSSL_PATH=/opt/bssl     With custom BoringSSL path
#   make QUAC_SDK_PATH=/opt/quac      Enable hardware support
#   make DEBUG=1                      Debug build
#   make test                         Build and run tests
#   make bench                        Build and run benchmarks
#   make install                      Install library
#   make clean                        Clean build artifacts
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

# Version
VERSION_MAJOR := 1
VERSION_MINOR := 0
VERSION_PATCH := 0
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := linux
    SHLIB_EXT := so
    SHLIB_FLAGS := -shared -Wl,-soname,libquac100_boringssl.so.$(VERSION_MAJOR)
endif
ifeq ($(UNAME_S),Darwin)
    OS := macos
    SHLIB_EXT := dylib
    SHLIB_FLAGS := -dynamiclib -install_name @rpath/libquac100_boringssl.$(VERSION_MAJOR).dylib
endif
ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    OS := windows
    SHLIB_EXT := dll
    SHLIB_FLAGS := -shared
endif
ifeq ($(findstring MSYS,$(UNAME_S)),MSYS)
    OS := windows
    SHLIB_EXT := dll
    SHLIB_FLAGS := -shared
endif

# Paths
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
DOCDIR ?= $(PREFIX)/share/doc/quac100-boringssl

# BoringSSL path (required)
BORINGSSL_PATH ?= /usr/local
BORINGSSL_INCLUDE := $(BORINGSSL_PATH)/include
BORINGSSL_LIB := $(BORINGSSL_PATH)/lib

# QUAC SDK path (optional, for hardware support)
QUAC_SDK_PATH ?=

# Compiler
CC ?= gcc
AR ?= ar

# Base flags
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter
CFLAGS += -fPIC -fvisibility=hidden
CFLAGS += -I. -I$(BORINGSSL_INCLUDE)

LDFLAGS := -L$(BORINGSSL_LIB)
LIBS := -lcrypto -lssl -lpthread

# Debug/Release
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
    BUILD_TYPE := debug
else
    CFLAGS += -O3 -DNDEBUG
    BUILD_TYPE := release
endif

# Hardware support
ifneq ($(QUAC_SDK_PATH),)
    QUAC_INCLUDE := $(QUAC_SDK_PATH)/include
    QUAC_LIB := $(QUAC_SDK_PATH)/lib
    ifneq ($(wildcard $(QUAC_INCLUDE)/quac100/quac.h),)
        CFLAGS += -DQUAC_HAS_HARDWARE -I$(QUAC_INCLUDE)
        LDFLAGS += -L$(QUAC_LIB)
        LIBS += -lquac100
        HAS_HARDWARE := yes
    else
        HAS_HARDWARE := no
    endif
else
    HAS_HARDWARE := no
endif

# Source files
SOURCES := \
    quac100_boringssl.c \
    quac100_kem.c \
    quac100_sig.c \
    quac100_rand.c \
    quac100_evp.c \
    quac100_tls.c \
    quac100_asn1.c

OBJECTS := $(SOURCES:.c=.o)
HEADERS := quac100_boringssl.h

# Output files
STATIC_LIB := libquac100_boringssl.a
SHARED_LIB := libquac100_boringssl.$(SHLIB_EXT)
SHARED_LIB_VERSIONED := libquac100_boringssl.$(SHLIB_EXT).$(VERSION)

TEST_SRC := test_quac100_boringssl.c
TEST_BIN := test_quac100_boringssl

BENCH_SRC := bench_quac100_boringssl.c
BENCH_BIN := bench_quac100_boringssl

# =============================================================================
# Targets
# =============================================================================

.PHONY: all shared static test bench clean install uninstall info help

all: shared static

shared: $(SHARED_LIB)

static: $(STATIC_LIB)

# Shared library
$(SHARED_LIB): $(OBJECTS)
	$(CC) $(SHLIB_FLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
ifeq ($(OS),linux)
	ln -sf $(SHARED_LIB) libquac100_boringssl.so.$(VERSION_MAJOR)
	ln -sf libquac100_boringssl.so.$(VERSION_MAJOR) libquac100_boringssl.so
endif
ifeq ($(OS),macos)
	ln -sf $(SHARED_LIB) libquac100_boringssl.$(VERSION_MAJOR).dylib
	ln -sf libquac100_boringssl.$(VERSION_MAJOR).dylib libquac100_boringssl.dylib
endif

# Static library
$(STATIC_LIB): $(OBJECTS)
	$(AR) rcs $@ $^

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test program
$(TEST_BIN): $(TEST_SRC) $(STATIC_LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lquac100_boringssl $(LDFLAGS) $(LIBS)

test: $(TEST_BIN)
	@echo "Running tests..."
	./$(TEST_BIN)

# Benchmark program
$(BENCH_BIN): $(BENCH_SRC) $(STATIC_LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lquac100_boringssl $(LDFLAGS) $(LIBS)

bench: $(BENCH_BIN)
	@echo "Running benchmarks..."
	./$(BENCH_BIN)

# Clean
clean:
	rm -f $(OBJECTS)
	rm -f $(STATIC_LIB) $(SHARED_LIB)
	rm -f libquac100_boringssl.so* libquac100_boringssl.dylib*
	rm -f $(TEST_BIN) $(BENCH_BIN)
	rm -f *.pem *.der

# Install
install: shared static
	@echo "Installing to $(PREFIX)..."
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)/quac100
	install -d $(DESTDIR)$(DOCDIR)
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/
ifeq ($(OS),linux)
	cd $(DESTDIR)$(LIBDIR) && ln -sf $(SHARED_LIB) libquac100_boringssl.so.$(VERSION_MAJOR)
	cd $(DESTDIR)$(LIBDIR) && ln -sf libquac100_boringssl.so.$(VERSION_MAJOR) libquac100_boringssl.so
endif
ifeq ($(OS),macos)
	cd $(DESTDIR)$(LIBDIR) && ln -sf $(SHARED_LIB) libquac100_boringssl.$(VERSION_MAJOR).dylib
	cd $(DESTDIR)$(LIBDIR) && ln -sf libquac100_boringssl.$(VERSION_MAJOR).dylib libquac100_boringssl.dylib
endif
	install -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/quac100/
	install -m 644 README.md $(DESTDIR)$(DOCDIR)/
	@echo "Installation complete."

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/libquac100_boringssl.*
	rm -f $(DESTDIR)$(INCLUDEDIR)/quac100/quac100_boringssl.h
	rm -rf $(DESTDIR)$(DOCDIR)

# Info
info:
	@echo "=== QUAC 100 BoringSSL Integration ==="
	@echo "Version:          $(VERSION)"
	@echo "OS:               $(OS)"
	@echo "Build type:       $(BUILD_TYPE)"
	@echo "Compiler:         $(CC)"
	@echo "BoringSSL path:   $(BORINGSSL_PATH)"
	@echo "Hardware support: $(HAS_HARDWARE)"
	@echo "Install prefix:   $(PREFIX)"
	@echo ""
	@echo "Source files:"
	@for f in $(SOURCES); do echo "  $$f"; done

help:
	@echo "QUAC 100 BoringSSL Integration - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build shared and static libraries (default)"
	@echo "  shared   - Build shared library only"
	@echo "  static   - Build static library only"
	@echo "  test     - Build and run tests"
	@echo "  bench    - Build and run benchmarks"
	@echo "  install  - Install libraries and headers"
	@echo "  uninstall- Remove installed files"
	@echo "  clean    - Remove build artifacts"
	@echo "  info     - Show build configuration"
	@echo ""
	@echo "Variables:"
	@echo "  BORINGSSL_PATH  - Path to BoringSSL (default: /usr/local)"
	@echo "  QUAC_SDK_PATH   - Path to QUAC SDK for hardware support"
	@echo "  PREFIX          - Install prefix (default: /usr/local)"
	@echo "  DEBUG=1         - Enable debug build"
	@echo ""
	@echo "Examples:"
	@echo "  make BORINGSSL_PATH=/opt/boringssl"
	@echo "  make QUAC_SDK_PATH=/opt/quantacore-sdk"
	@echo "  sudo make install PREFIX=/usr"