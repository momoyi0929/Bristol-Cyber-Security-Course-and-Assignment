# Compiler and flags
CC = gcc - w
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


# Phony targets
.PHONY: all clean test