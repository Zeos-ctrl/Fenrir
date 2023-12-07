# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2

# RELIC library paths
RELIC_INCLUDE = /usr/local/include
RELIC_LIB = /usr/local/lib

# OpenSSL library paths
OPENSSL_INCLUDE = /usr/include/openssl
OPENSSL_LIB = /usr/lib

# Ascon library paths
ASCON_INCLUDE = /usr/local/include
ASCON_LIB = /usr/local/lib

# Program source files
SRC_MAIN = src/fenrir.c
SRC_TEST = tests/test_crypto.c

# Program executable name
TARGET_MAIN = Fenrir
TARGET_TEST = Test

all: $(TARGET_MAIN) $(TARGET_TEST)

$(TARGET_MAIN): $(SRC_MAIN)
	$(CC) $(CFLAGS) -I$(RELIC_INCLUDE) -I$(OPENSSL_INCLUDE) -I$(ASCON_INCLUDE) -o $@ $^ -L$(RELIC_LIB) -L$(OPENSSL_LIB) -L$(ASCON_LIB) -lrelic -lssl -lcrypto -lasconfull

$(TARGET_TEST): $(SRC_TEST)
	$(CC) $(CFLAGS) -I$(RELIC_INCLUDE) -I$(OPENSSL_INCLUDE) -I$(ASCON_INCLUDE) -o $@ $^ -L$(RELIC_LIB) -L$(OPENSSL_LIB) -L$(ASCON_LIB) -lrelic -lssl -lcrypto -lasconfull

clean:
	rm -f $(TARGET_MAIN) $(TARGET_TEST)
