# Compiler and flags
CC = gcc - 
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

# Target executable
TARGET = filehash

# Source files
SOURCES = filehash.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	@echo "Build successful: $(TARGET)"

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean successful"

# Run tests
test: $(TARGET)
	@echo "Creating test file..."
	@echo "Hello, World!" > test.txt
	@echo "\n=== Test 1: SHA-256 (default) ==="
	./$(TARGET) test.txt
	@echo "\n=== Test 2: SHA-512 ==="
	./$(TARGET) -a sha512 test.txt
	@echo "\n=== Test 3: Hash verification (should PASS) ==="
	SHA256_HASH=$$(./$(TARGET) test.txt | grep "Computed hash:" | awk '{print $$3}') && \
	./$(TARGET) test.txt $$SHA256_HASH
	@echo "\n=== Test 4: Hash verification (should FAIL) ==="
	./$(TARGET) test.txt "0000000000000000000000000000000000000000000000000000000000000000" || true
	@echo "\n=== Test 5: Invalid algorithm ==="
	./$(TARGET) -a md5 test.txt || true
	@echo "\n=== Test 6: Non-existent file ==="
	./$(TARGET) nonexistent.txt || true
	@rm test.txt

# Phony targets
.PHONY: all clean test