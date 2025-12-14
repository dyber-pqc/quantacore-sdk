# QUAC 100 C Examples Makefile
# Copyright 2025 Dyber, Inc. All Rights Reserved.

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../../include
LDFLAGS = -L../../lib -lquac100 -lpthread -lm

# Optional OpenSSL support
ifdef HAVE_OPENSSL
CFLAGS += -DHAVE_OPENSSL
LDFLAGS += -lssl -lcrypto
endif

# Targets
TARGETS = hello_quac kyber_demo dilithium_sign tls_server

.PHONY: all clean

all: $(TARGETS)

hello_quac: hello_quac.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

kyber_demo: kyber_demo.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

dilithium_sign: dilithium_sign.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

tls_server: tls_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

# Run examples
run-hello: hello_quac
	./hello_quac

run-kyber: kyber_demo
	./kyber_demo 768

run-dilithium: dilithium_sign
	./dilithium_sign 65

run-tls: tls_server
	./tls_server 8443

run-all: all
	@echo "=== Hello QUAC ===" && ./hello_quac
	@echo "\n=== Kyber Demo ===" && ./kyber_demo 768
	@echo "\n=== Dilithium Sign ===" && ./dilithium_sign 65
	@echo "\n=== TLS Server ===" && ./tls_server 8443