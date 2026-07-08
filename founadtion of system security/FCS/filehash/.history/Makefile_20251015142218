# ==================== Makefile for File Integrity Checker ====================
# Author: [Your Name]
# Module: Foundations of Cyber Security (MSc)
# Date: October 2025
#
# Usage:
#   make          - Build the executable
#   make clean    - Remove build artifacts
#   make rebuild  - Clean and rebuild
#   make help     - Show available targets
# ==============================================================================

# -------------------- Compiler Configuration --------------------
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -std=c11
LDFLAGS = -lssl -lcrypto

# -------------------- Project Files --------------------
TARGET = filehash
SOURCES = filehash.c
OBJECTS = $(SOURCES:.c=.o)

# -------------------- Colors for Output --------------------
GREEN = \033[1;32m
YELLOW = \033[1;33m
BLUE = \033[1;34m
RESET = \033[0m

# -------------------- Default Target --------------------
.PHONY: all
all: $(TARGET)
	@echo "$(GREEN)✓ Build complete: $(TARGET)$(RESET)"
	@echo "$(BLUE)Run './$(TARGET) --help' for usage information$(RESET)"

# -------------------- Build Executable --------------------
$(TARGET): $(OBJECTS)
	@echo "$(YELLOW)Linking $(TARGET)...$(RESET)"
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

# -------------------- Compile Object Files --------------------
%.o: %.c
	@echo "$(YELLOW)Compiling $<...$(RESET)"
	$(CC) $(CFLAGS) -c $< -o $@

# -------------------- Clean Build Artifacts --------------------
.PHONY: clean
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	rm -f $(OBJECTS) $(TARGET)
	@echo "$(GREEN)✓ Clean complete$(RESET)"

# -------------------- Rebuild from Scratch --------------------
.PHONY: rebuild
rebuild: clean all

# -------------------- Show Help --------------------
.PHONY: help
help:
	@echo "$(BLUE)============================================$(RESET)"
	@echo "$(BLUE)  File Integrity Checker - Makefile Help  $(RESET)"
	@echo "$(BLUE)============================================$(RESET)"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "  $(GREEN)make$(RESET)              - Build the executable"
	@echo "  $(GREEN)make clean$(RESET)        - Remove build artifacts"
	@echo "  $(GREEN)make rebuild$(RESET)      - Clean and rebuild"
	@echo "  $(GREEN)make help$(RESET)         - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  $(YELLOW)make$(RESET)"
	@echo "  $(YELLOW)make clean$(RESET)"
	@echo "  $(YELLOW)make rebuild$(RESET)"
	@echo "  $(YELLOW)./$(TARGET) myfile.txt$(RESET)"
	@echo "  $(YELLOW)./$(TARGET) -a sha512 myfile.txt$(RESET)"
	@echo ""