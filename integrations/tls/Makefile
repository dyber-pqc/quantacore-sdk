# ==============================================================================
# QUAC 100 TLS Integration - Makefile
# ==============================================================================
#
# Build system for QUAC TLS library with post-quantum cryptography support.
#
# Targets:
#   all       - Build library, tests, examples, and benchmarks
#   lib       - Build shared and static libraries
#   test      - Build and run test suite
#   bench     - Build and run benchmarks
#   example   - Build example programs
#   tools     - Build utility tools (quac-tls-keygen)
#   install   - Install library, headers, and tools
#   clean     - Remove build artifacts
#
# Options:
#   DEBUG=1           - Build with debug symbols and assertions
#   QUAC_SDK_PATH=    - Path to QUAC 100 SDK (enables hardware acceleration)
#   OPENSSL_PATH=     - Path to OpenSSL installation
#   PREFIX=           - Installation prefix (default: /usr/local)
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# ==============================================================================

# Library version
VERSION_MAJOR := 1
VERSION_MINOR := 0
VERSION_PATCH := 0
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

# Directories
SRCDIR := .
BUILDDIR := build
OBJDIR := $(BUILDDIR)/obj
BINDIR := $(BUILDDIR)/bin
LIBDIR := $(BUILDDIR)/lib
TESTDIR := tests
EXAMPLEDIR := examples
TOOLSDIR := tools

# Installation directories
PREFIX ?= /usr/local
INSTALL_LIBDIR := $(PREFIX)/lib
INSTALL_INCDIR := $(PREFIX)/include/quac
INSTALL_BINDIR := $(PREFIX)/bin

# ==============================================================================
# Platform Detection
# ==============================================================================

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := linux
    SHARED_EXT := so
    SHARED_FLAGS := -shared -Wl,-soname,libquac_tls.so.$(VERSION_MAJOR)
    LDFLAGS_EXTRA := -Wl,-rpath,'$$ORIGIN'
    EXE_EXT :=
endif
ifeq ($(UNAME_S),Darwin)
    OS := macos
    SHARED_EXT := dylib
    SHARED_FLAGS := -dynamiclib -install_name @rpath/libquac_tls.$(VERSION_MAJOR).dylib
    LDFLAGS_EXTRA := -Wl,-rpath,@loader_path
    EXE_EXT :=
endif
ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    OS := windows
    SHARED_EXT := dll
    SHARED_FLAGS := -shared
    LDFLAGS_EXTRA :=
    EXE_EXT := .exe
endif
ifeq ($(findstring MSYS,$(UNAME_S)),MSYS)
    OS := windows
    SHARED_EXT := dll
    SHARED_FLAGS := -shared
    LDFLAGS_EXTRA :=
    EXE_EXT := .exe
endif

# ==============================================================================
# Compiler Configuration
# ==============================================================================

CC := gcc
CXX := g++
AR := ar

CFLAGS := -Wall -Wextra -Wpedantic -std=c11 -fPIC
CXXFLAGS := -Wall -Wextra -Wpedantic -std=c++17 -fPIC
LDFLAGS := -lpthread

# Debug/Release configuration
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
    CXXFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
    LDFLAGS += -fsanitize=address,undefined
else
    CFLAGS += -O3 -DNDEBUG -fomit-frame-pointer
    CXXFLAGS += -O3 -DNDEBUG -fomit-frame-pointer
endif

# ==============================================================================
# OpenSSL Configuration
# ==============================================================================

ifdef OPENSSL_PATH
    CFLAGS += -I$(OPENSSL_PATH)/include
    LDFLAGS += -L$(OPENSSL_PATH)/lib -L$(OPENSSL_PATH)/lib64
endif

# Try pkg-config for OpenSSL
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(OPENSSL_LIBS),)
    OPENSSL_LIBS := -lssl -lcrypto
endif
CFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

# ==============================================================================
# QUAC SDK Configuration (Optional Hardware Acceleration)
# ==============================================================================

ifdef QUAC_SDK_PATH
    CFLAGS += -I$(QUAC_SDK_PATH)/include -DQUAC_HAS_HARDWARE
    LDFLAGS += -L$(QUAC_SDK_PATH)/lib -lquac100
    HW_STATUS := enabled
else
    HW_STATUS := disabled (software fallback)
endif

# ==============================================================================
# Library Names
# ==============================================================================

LIB_NAME := quac_tls
SHARED_LIB := lib$(LIB_NAME).$(SHARED_EXT)
STATIC_LIB := lib$(LIB_NAME).a

ifeq ($(OS),linux)
    SHARED_LIB_VERSIONED := lib$(LIB_NAME).$(SHARED_EXT).$(VERSION)
    SHARED_LIB_SONAME := lib$(LIB_NAME).$(SHARED_EXT).$(VERSION_MAJOR)
endif
ifeq ($(OS),macos)
    SHARED_LIB_VERSIONED := lib$(LIB_NAME).$(VERSION).$(SHARED_EXT)
    SHARED_LIB_SONAME := lib$(LIB_NAME).$(VERSION_MAJOR).$(SHARED_EXT)
endif

# ==============================================================================
# Source Files
# ==============================================================================

LIB_SRCS := quac_tls.c quac_tls_pqc.c
LIB_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LIB_SRCS))

TEST_BIN := $(BINDIR)/test_quac_tls$(EXE_EXT)
BENCH_BIN := $(BINDIR)/bench_quac_tls$(EXE_EXT)
EXAMPLE_SERVER := $(BINDIR)/example_tls_server$(EXE_EXT)
EXAMPLE_CLIENT := $(BINDIR)/example_tls_client$(EXE_EXT)
KEYGEN_BIN := $(BINDIR)/quac-tls-keygen$(EXE_EXT)

# ==============================================================================
# Main Targets
# ==============================================================================

.PHONY: all lib test bench example tools install uninstall clean help info

all: lib test bench example tools
	@echo ""
	@echo "Build complete! Binaries in $(BINDIR)/"
	@echo "Run 'make install' to install to $(PREFIX)"

# Create directories
$(OBJDIR) $(BINDIR) $(LIBDIR):
	@mkdir -p $@

# ==============================================================================
# Library Build
# ==============================================================================

lib: $(LIBDIR)/$(SHARED_LIB) $(LIBDIR)/$(STATIC_LIB)
	@echo "Library built: $(LIBDIR)/$(SHARED_LIB)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(LIBDIR)/$(SHARED_LIB): $(LIB_OBJS) | $(LIBDIR)
	@echo "  LD    $(SHARED_LIB)"
	@$(CC) $(SHARED_FLAGS) -o $@ $^ $(LDFLAGS) $(LDFLAGS_EXTRA)
ifeq ($(OS),linux)
	@cd $(LIBDIR) && ln -sf $(SHARED_LIB) $(SHARED_LIB_SONAME) 2>/dev/null || true
	@cd $(LIBDIR) && ln -sf $(SHARED_LIB_SONAME) lib$(LIB_NAME).$(SHARED_EXT) 2>/dev/null || true
endif
ifeq ($(OS),macos)
	@cd $(LIBDIR) && ln -sf $(SHARED_LIB) $(SHARED_LIB_SONAME) 2>/dev/null || true
	@cd $(LIBDIR) && ln -sf $(SHARED_LIB_SONAME) lib$(LIB_NAME).$(SHARED_EXT) 2>/dev/null || true
endif

$(LIBDIR)/$(STATIC_LIB): $(LIB_OBJS) | $(LIBDIR)
	@echo "  AR    $(STATIC_LIB)"
	@$(AR) rcs $@ $^

# ==============================================================================
# Test Suite
# ==============================================================================

test: $(TEST_BIN)
	@echo ""
	@echo "============================================"
	@echo "Running QUAC TLS Test Suite"
	@echo "============================================"
	@LD_LIBRARY_PATH=$(LIBDIR):$$LD_LIBRARY_PATH DYLD_LIBRARY_PATH=$(LIBDIR):$$DYLD_LIBRARY_PATH $(TEST_BIN)

$(TEST_BIN): $(OBJDIR)/test_quac_tls.o $(LIBDIR)/$(SHARED_LIB) | $(BINDIR)
	@echo "  LD    test_quac_tls"
	@$(CC) -o $@ $< -L$(LIBDIR) -l$(LIB_NAME) $(LDFLAGS) $(LDFLAGS_EXTRA)

$(OBJDIR)/test_quac_tls.o: $(TESTDIR)/test_quac_tls.c | $(OBJDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# ==============================================================================
# Benchmarks
# ==============================================================================

bench: $(BENCH_BIN)
	@echo ""
	@echo "============================================"
	@echo "Running QUAC TLS Benchmarks"
	@echo "============================================"
	@LD_LIBRARY_PATH=$(LIBDIR):$$LD_LIBRARY_PATH DYLD_LIBRARY_PATH=$(LIBDIR):$$DYLD_LIBRARY_PATH $(BENCH_BIN)

$(BENCH_BIN): $(OBJDIR)/bench_quac_tls.o $(LIBDIR)/$(SHARED_LIB) | $(BINDIR)
	@echo "  LD    bench_quac_tls"
	@$(CC) -o $@ $< -L$(LIBDIR) -l$(LIB_NAME) $(LDFLAGS) $(LDFLAGS_EXTRA) -lm

$(OBJDIR)/bench_quac_tls.o: $(TESTDIR)/bench_quac_tls.c | $(OBJDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# ==============================================================================
# Examples
# ==============================================================================

example: $(EXAMPLE_SERVER) $(EXAMPLE_CLIENT)
	@echo "Examples built: $(EXAMPLE_SERVER) $(EXAMPLE_CLIENT)"

$(EXAMPLE_SERVER): $(OBJDIR)/example_tls_server.o $(LIBDIR)/$(SHARED_LIB) | $(BINDIR)
	@echo "  LD    example_tls_server"
	@$(CC) -o $@ $< -L$(LIBDIR) -l$(LIB_NAME) $(LDFLAGS) $(LDFLAGS_EXTRA)

$(EXAMPLE_CLIENT): $(OBJDIR)/example_tls_client.o $(LIBDIR)/$(SHARED_LIB) | $(BINDIR)
	@echo "  LD    example_tls_client"
	@$(CC) -o $@ $< -L$(LIBDIR) -l$(LIB_NAME) $(LDFLAGS) $(LDFLAGS_EXTRA)

$(OBJDIR)/example_%.o: $(EXAMPLEDIR)/example_%.c | $(OBJDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# ==============================================================================
# Tools
# ==============================================================================

tools: $(KEYGEN_BIN)
	@echo "Tools built: $(KEYGEN_BIN)"

$(KEYGEN_BIN): $(OBJDIR)/quac_tls_keygen.o $(LIBDIR)/$(SHARED_LIB) | $(BINDIR)
	@echo "  LD    quac-tls-keygen"
	@$(CC) -o $@ $< -L$(LIBDIR) -l$(LIB_NAME) $(LDFLAGS) $(LDFLAGS_EXTRA)

$(OBJDIR)/quac_tls_keygen.o: $(TOOLSDIR)/quac_tls_keygen.c | $(OBJDIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# ==============================================================================
# Installation
# ==============================================================================

install: lib tools
	@echo "Installing QUAC TLS to $(PREFIX)..."
	@install -d $(INSTALL_LIBDIR) $(INSTALL_INCDIR) $(INSTALL_BINDIR)
	@install -m 644 $(LIBDIR)/$(STATIC_LIB) $(INSTALL_LIBDIR)/
	@install -m 755 $(LIBDIR)/$(SHARED_LIB) $(INSTALL_LIBDIR)/
ifeq ($(OS),linux)
	@cd $(INSTALL_LIBDIR) && ln -sf $(SHARED_LIB) $(SHARED_LIB_SONAME)
	@cd $(INSTALL_LIBDIR) && ln -sf $(SHARED_LIB_SONAME) lib$(LIB_NAME).$(SHARED_EXT)
endif
ifeq ($(OS),macos)
	@cd $(INSTALL_LIBDIR) && ln -sf $(SHARED_LIB) $(SHARED_LIB_SONAME)
	@cd $(INSTALL_LIBDIR) && ln -sf $(SHARED_LIB_SONAME) lib$(LIB_NAME).$(SHARED_EXT)
endif
	@install -m 644 quac_tls.h $(INSTALL_INCDIR)/
	@install -m 644 quac_tls_internal.h $(INSTALL_INCDIR)/
	@install -m 755 $(KEYGEN_BIN) $(INSTALL_BINDIR)/
	@ldconfig 2>/dev/null || true
	@echo "Installation complete!"
	@echo "  Libraries: $(INSTALL_LIBDIR)"
	@echo "  Headers:   $(INSTALL_INCDIR)"
	@echo "  Tools:     $(INSTALL_BINDIR)"

uninstall:
	@echo "Uninstalling from $(PREFIX)..."
	@rm -f $(INSTALL_LIBDIR)/lib$(LIB_NAME).*
	@rm -f $(INSTALL_INCDIR)/quac_tls.h
	@rm -f $(INSTALL_INCDIR)/quac_tls_internal.h
	@rm -f $(INSTALL_BINDIR)/quac-tls-keygen
	@rmdir $(INSTALL_INCDIR) 2>/dev/null || true
	@ldconfig 2>/dev/null || true
	@echo "Uninstallation complete."

# ==============================================================================
# Clean
# ==============================================================================

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILDDIR)
	@rm -f *.o *.so *.dylib *.dll *.a
	@echo "Clean complete."

# ==============================================================================
# Help & Info
# ==============================================================================

help:
	@echo "QUAC 100 TLS Integration - Build System"
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  lib       - Build shared and static libraries"
	@echo "  test      - Build and run test suite"
	@echo "  bench     - Build and run benchmarks"
	@echo "  example   - Build example programs"
	@echo "  tools     - Build utility tools"
	@echo "  install   - Install to PREFIX (default: /usr/local)"
	@echo "  uninstall - Remove installed files"
	@echo "  clean     - Remove build artifacts"
	@echo "  info      - Show build configuration"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1             Build with debug symbols"
	@echo "  QUAC_SDK_PATH=path  Path to QUAC 100 SDK (enables hardware)"
	@echo "  OPENSSL_PATH=path   Path to OpenSSL installation"
	@echo "  PREFIX=path         Installation prefix"
	@echo ""
	@echo "Examples:"
	@echo "  make                               # Standard build"
	@echo "  make DEBUG=1                       # Debug build"
	@echo "  make QUAC_SDK_PATH=/opt/quac-sdk   # With hardware acceleration"
	@echo "  sudo make install PREFIX=/usr      # Install to /usr"

info:
	@echo "QUAC TLS Build Configuration"
	@echo "============================"
	@echo "  Version:      $(VERSION)"
	@echo "  OS:           $(OS)"
	@echo "  Compiler:     $(CC)"
	@echo "  CFLAGS:       $(CFLAGS)"
	@echo "  LDFLAGS:      $(LDFLAGS)"
	@echo "  Install:      $(PREFIX)"
	@echo "  Hardware:     $(HW_STATUS)"
ifdef QUAC_SDK_PATH
	@echo "  QUAC SDK:     $(QUAC_SDK_PATH)"
endif
ifdef OPENSSL_PATH
	@echo "  OpenSSL:      $(OPENSSL_PATH)"
endif