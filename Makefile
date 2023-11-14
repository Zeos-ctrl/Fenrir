# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2

# RELIC library paths
RELIC_INCLUDE = /usr/local/include/relic
RELIC_LIB = /usr/local/lib

# OpenSSL library paths
OPENSSL_INCLUDE = /usr/include/openssl
OPENSSL_LIB = /usr/lib

# Program source files
SRC_MAIN = src/main.c
SRC_TEST = tests/test_crypto.c

# Program executable name
TARGET_MAIN = Fenrir
TARGET_TEST = tests/Tests

all: $(TARGET_MAIN) $(TARGET_TEST)

$(TARGET_MAIN): $(SRC_MAIN)
	$(CC) $(CFLAGS) -I$(RELIC_INCLUDE) -I$(OPENSSL_INCLUDE) -o $@ $^ -L$(RELIC_LIB) -L$(OPENSSL_LIB) -lrelic -lssl -lcrypto

$(TARGET_TEST): $(SRC_TEST)
	$(CC) $(CFLAGS) -I$(RELIC_INCLUDE) -I$(OPENSSL_INCLUDE) -o $@ $^ -L$(RELIC_LIB) -L$(OPENSSL_LIB) -lrelic -lssl -lcrypto

clean:
	rm -f $(TARGET_MAIN) $(TARGET_TEST)
