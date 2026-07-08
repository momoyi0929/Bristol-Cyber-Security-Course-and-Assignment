# ==================== Makefile for File Integrity Checker ====================
# Author: Yi Li
# Student no: 282996
# Module: Foundations of Cyber Security (MSc)
# Date: October 2025
#
# Usage:
#   make          - Build the executable
#   make clean    - Remove build artifacts
#   make rebuild  - Clean and rebuild
# ==============================================================================

# -------------------- Compiler Configuration --------------------
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto

# -------------------- Project Files --------------------
TARGET = filehash
SOURCES = filehash.c

# -------------------- Default Target --------------------
.PHONY: all
all: $(TARGET)

# -------------------- Build Executable (direct compilation) --------------------
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# -------------------- Clean Build Artifacts --------------------
.PHONY: clean
clean:
	rm -f $(TARGET)

# -------------------- Rebuild from Scratch --------------------
.PHONY: rebuild
rebuild: clean all