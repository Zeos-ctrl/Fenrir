# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -pg -g

# Platform x86 or arm
PLATFORM = x86

# Common paths
INCLUDE_DIRS = -I./include -I/usr/include/openssl
LIB_DIRS = -L./lib/$(PLATFORM) -L/usr/lib

# Libraries to link
LIBS = -lrelic -lssl -lcrypto -lasconfull

# Program source files
SRC_MAIN = src/fenrir.c
SRC_TEST = tests/test_crypto.c

# Program executable names
TARGET_MAIN = fenrir.out
TARGET_TEST = test.out

all: $(TARGET_MAIN) $(TARGET_TEST)

$(TARGET_MAIN): $(SRC_MAIN)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LIB_DIRS) $(LIBS)

$(TARGET_TEST): $(SRC_TEST)
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -o $@ $^ $(LIB_DIRS) $(LIBS)

clean:
	rm -f $(TARGET_MAIN) $(TARGET_TEST)
