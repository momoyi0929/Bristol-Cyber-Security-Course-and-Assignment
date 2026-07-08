/**
 * File Integrity Checker
 * 
 * A command-line tool for computing and verifying cryptographic hashes of files.
 * Uses OpenSSL's low-level API (SHA256/SHA512) with streaming for large file support.
 * 
 * Features:
 *   - Supports SHA-256 and SHA-512 hashing algorithms
 *   - Streams files in 4KB(4096) chunks for constant memory usage
 *   - Verifies file integrity against expected hash values
 *   - Comprehensive error handling and input validation
 * 
 * Author: Yi Li
 * Module: Foundations of Cyber Security (MSc)
 * Date: October 2025
 # Student no: 282996
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <ctype.h>

// Used for printing color
#define GREEN "\033[1;32m"
#define RED   "\033[1;31m"
#define RESET "\033[0m"

#define BUFFER_SIZE 4096
#define MAX_HASH_LEN 64  // SHA-512 produces 64 bytes

// Core logic functions
int parse_arguments(int argc, char *argv[], const char **algorithm, const char **filename, const char **expected_hash);
int validate_inputs(const char *algorithm, const char *expected_hash);
int run_hash_process(const char *filename, const char *algorithm, const char *expected_hash);

// Hashing functions
int is_valid_algorithm(const char *algorithm);
int compute_file_hash(const char *filename, const char *algorithm, unsigned char *hash, unsigned int *hash_len);
void print_hash_hex(const unsigned char *hash, unsigned int hash_len);
int verify_hash(const unsigned char *computed_hash, unsigned int computed_len, const char *expected_hash);

// Utility functions
void print_usage(const char *program_name);
void print_supported_algorithms(void);

//
// ======================= MAIN FUNCTION =======================
//
/**
 * ===================================================================
 * Main entry point for the File Integrity Checker application
 * 
 * This function orchestrates the entire file hashing and verification process:
 * 1. Parses command-line arguments to determine user's intent
 * 2. Validates all inputs for correctness and safety
 * 3. Executes the core hashing/verification logic and return the result
 * 
 * @return int Program exit status:
 *            - 0: Success (hash computed or verification passed)
 *            - 1: Error occurred (invalid input, file error, or verification failed)
 * ===================================================================
 */
int main(int argc, char *argv[]) {
    const char *algorithm = "sha256";
    const char *filename = NULL;
    const char *expected_hash = NULL;

    // Step 1: Parse arguments
    if (!parse_arguments(argc, argv, &algorithm, &filename, &expected_hash)) {
        return 1;
    }

    // Step 2: Validate inputs
    if (!validate_inputs(algorithm, expected_hash)) {
        return 1;
    }

    // Step 3: Execute hashing and verification
    return run_hash_process(filename, algorithm, expected_hash);
}

//
// ======================= CORE LOGIC FUNCTIONS =======================
//
/**
 * ===================================================================
 * Parse and validate command-line arguments
 * 
 * This function supports:
 * - Algorithm selection via -a flag
 * - Help requests via -h or --help flags  
 * - Filename and expected hash extraction
 * 
 * @param argc        Argument count from main (includes program name)
 * @param argv        Argument vector from main (array of string arguments)
 * @param algorithm   Output: pointer to store selected algorithm (default: sha256)
 * @param filename    Output: pointer to store filename (required)
 * @param expected_hash Output: pointer to store expected hash (optional)
 * 
 * @return int        1 if parsing successful, 0 if errors occurred
 * 
 * Error Handling:
 * - Missing algorithm after -a flag
 * - Too many arguments provided
 * - No filename specified
 * - Help request (triggers immediate exit with usage info)
 * ===================================================================
 */
int parse_arguments(int argc, char *argv[], const char **algorithm, const char **filename, const char **expected_hash) {
    // Iterate through all command-line arguments starting from index 1
    for (int i = 1; i < argc; i++) {
        // Recoginze algorithm selection flag (-a)
        if (strcmp(argv[i], "-a") == 0) {
            // Check if there's a next argument for the algorithm name
            if (i + 1 < argc) {
                *algorithm = argv[++i];
            } else {
                fprintf(stderr, RED "Error: -a option requires an algorithm name\n" RESET);
                print_usage(argv[0]); // Show correct usage
                return 0;
            }
        // response help requests
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);  // Display usage information
            exit(0);
        // Check filename (first non-option argument)
        } else if (*filename == NULL) {
            *filename = argv[i]; // Assign first non-option as filename
        // Check expected hash (second non-option argument)  
        } else if (*expected_hash == NULL) {
            *expected_hash = argv[i]; // Assign second non-option as expected hash
        } else {
            fprintf(stderr, RED "Error: Too many arguments\n" RESET);
            print_usage(argv[0]);
            return 0;
        }
    }
    // Ensure a filename was provided (required parameter)
    if (*filename == NULL) {
        fprintf(stderr, RED "Error: No filename provided\n" RESET);
        print_usage(argv[0]);
        return 0;
    }

    return 1;  // Successful parsing
}

/**
 * ===================================================================
 * This function performs comprehensive validation of user inputs to ensure:
 * - The requested hashing algorithm is supported by the program
 * - The expected hash (if provided) contains only valid hexadecimal characters
 * 
 * @param algorithm      sha256/sha512
 * @param expected_hash  The expected hash value (must be hex)
 * 
 * @return int           1 if all inputs are valid, 0 if any validation fails
 * 
 * Validation Rules:
 * - Algorithm must be either "sha256" or "sha512" (case-insensitive)
 * - Expected hash (if provided) must contain only hexadecimal digits (0-9, a-f, A-F)
 * - Filename is currently accepted without validation (file existence checked later)
 * ===================================================================
 */
int validate_inputs(const char *algorithm, const char *expected_hash) {
    // Ensure it's one of our supported hashing algorithms
    if (!is_valid_algorithm(algorithm)) {
        fprintf(stderr, RED "Error: Unsupported algorithm '%s'\n" RESET, algorithm);
        fprintf(stderr, "Supported algorithms:\n");
        print_supported_algorithms();
        return 0;
    }
    // Validate expected hash format
    if (expected_hash && strlen(expected_hash) > 0) {
        for (size_t i = 0; i < strlen(expected_hash); i++) {
            if (!isxdigit(expected_hash[i])) {
                fprintf(stderr, RED "Error: Expected hash contains non-hex characters\n" RESET);
                return 0;
            }
        }
    }

    return 1;
}

/**
 * ===================================================================
 * This function serves as the central coordinator for the main business logic,
 * executing the complete file integrity checking process from start to finish.
 * 
 * The function follows a clear pipeline: compute hash → optionally verify → report results.
 * This separation makes the code testable, maintainable, and easy to reason about.
 * 
 * @param filename       Path to the file to process (already validated)
 * @param algorithm      Hashing algorithm to use (already validated)
 * @param expected_hash  Expected hash value for verification (optional, NULL if not verifying)
 * 
 * @return int           Program exit status:
 *                      - 0: Success (hash computed or verification passed)
 *                      - 1: Failure (hash computation failed or verification mismatch)
 * 
 * Workflow Steps:
 * 1. Display processing information to user
 * 2. Compute cryptographic hash of the file
 * 3. Display computed hash to user
 * 4. If expected hash provided, verify against computed hash
 * 5. Return appropriate exit code based on verification result
 * 
 * Error Propagation:
 * - Hash computation failures immediately terminate with error code
 * - Verification failures return distinct error code without stopping execution
 * - All errors include descriptive messages for user understanding
 * ===================================================================
 */
int run_hash_process(const char *filename, const char *algorithm, const char *expected_hash) {
    unsigned char computed_hash[MAX_HASH_LEN];
    unsigned int hash_length = 0;

    // Step 1: Inform user of processing parameters
    printf("Using algorithm: %s\n", algorithm);
    printf("Processing file: %s\n", filename);
    if (expected_hash) printf("Expected hash: %s\n", expected_hash);

    // Step 2: Compute file hash - this is the core cryptographic operation
    if (compute_file_hash(filename, algorithm, computed_hash, &hash_length) != 0) {
        fprintf(stderr, RED "Failed to compute hash for file '%s'\n" RESET, filename);
        return 1;
    }

    // Step 3: Display computed hash to user
    printf("Computed hash: ");
    print_hash_hex(computed_hash, hash_length);
    printf("\n");

    // Step 4: Conditional verification if expected hash was provided
    if (expected_hash) {
        if (verify_hash(computed_hash, hash_length, expected_hash) == 0) {
            printf(GREEN "Integrity check: PASS - File is intact\n" RESET);
            return 0;
        } else {
            printf(RED "Integrity check: FAIL - Hash mismatch\n" RESET);
            return 1;
        }
    }
     // Step 5: Return
    return 0;
}

//
// ======================= HASHING FUNCTIONS =======================
//
/**
 * ===================================================================
 * This function checks if the requested algorithm is supported by the program.
 * 
 * @param algorithm The algorithm name (e.g., "sha256", "SHA512", "Sha256")
 * 
 * @return int      Validation result: 
 *                 - 1 if algorithm is supported
 *                 - 0 if algorithm is NULL or unsupported
 * ===================================================================
 */
int is_valid_algorithm(const char *algorithm) {
    if (algorithm == NULL) return 0;

    return (strcasecmp(algorithm, "sha256") == 0 ||
            strcasecmp(algorithm, "sha512") == 0);
}

/**
 * =================================================================== 
 * This function computes cryptographic hash of a file using streaming processing
 * and calculates the hash of a file by reading it in fixed-size
 * chunks (4KB). This streaming approach ensures constant memory usage regardless of file size,
 * making it suitable for processing very large files efficiently.
 * 
 * @param filename   Path to the file to be hashed (must be readable)
 * @param algorithm  Hashing algorithm to use ("sha256" or "sha512")
 * @param hash       Output buffer to store the computed hash
 * @param hash_len   Output parameter for the actual length of computed hash in bytes
 * 
 * @return int       Operation status:
 *                  - 0: Success (hash computed and stored in output buffer)
 *                  - 1: Error occurred (file I/O error or OpenSSL failure)
 *
 * Performance Characteristics:
 * - Constant memory usage: ~4KB buffer regardless of file size
 * - Linear time complexity: O(n) where n is file size
 * - Minimal memory copies: direct buffer-to-hash updates
 * - Suitable for files from bytes to terabytes in size
 * ===================================================================
 */
int compute_file_hash(const char *filename, const char *algorithm,
                     unsigned char *hash, unsigned int *hash_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    // Fixed-size buffer for streaming file processing
    // 4KB chunk size balances I/O efficiency with memory usage
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;

    // Algorithm-specific hashing implementation
    if (strcasecmp(algorithm, "sha256") == 0) {
        SHA256_CTX ctx; // Stack-allocated context for SHA-256
        *hash_len = SHA256_DIGEST_LENGTH; // 32 bytes for SHA-256

        // Initialize SHA-256 context
        if (!SHA256_Init(&ctx)) { fclose(file); return 1; }

        // Stream processing: read file in chunks and update hash incrementally
        // This approach supports files larger than available memory
        while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            // Update hash with current chunk
            if (!SHA256_Update(&ctx, buffer, bytes_read)) { fclose(file); return 1; }
        }
        // Finalize hash computation and store result in output buffer
        if (!SHA256_Final(hash, &ctx)) { fclose(file); return 1; }

    } else if (strcasecmp(algorithm, "sha512") == 0) {
        SHA512_CTX ctx; // Stack-allocated context for SHA-512
        *hash_len = SHA512_DIGEST_LENGTH; // 64 bytes for SHA-512
        
        // Initialize SHA-512 context
        if (!SHA512_Init(&ctx)) { fclose(file); return 1; }
        while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            if (!SHA512_Update(&ctx, buffer, bytes_read)) { fclose(file); return 1; }
        }
        if (!SHA512_Final(hash, &ctx)) { fclose(file); return 1; }

    } else {
        fprintf(stderr, RED "Error: Unsupported algorithm '%s'\n" RESET, algorithm);
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}

void print_hash_hex(const unsigned char *hash, unsigned int hash_len) {
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
}

int verify_hash(const unsigned char *computed_hash, unsigned int computed_len,
               const char *expected_hash) {
    char computed_hex[computed_len * 2 + 1];
    for (unsigned int i = 0; i < computed_len; i++) {
        sprintf(computed_hex + i * 2, "%02x", computed_hash[i]);
    }
    computed_hex[computed_len * 2] = '\0';

    if (strcasecmp(computed_hex, expected_hash) == 0)
        return 0;
    else {
        printf("Expected: %s\n", expected_hash);
        printf("Computed: %s\n", computed_hex);
        return 1;
    }
}

//
// ======================= UTILITY FUNCTIONS =======================
//

void print_usage(const char *program_name) {
    printf("Usage: %s [-a algorithm] filename [expected_hash]\n\n", program_name);
    printf("Options:\n");
    printf("  -a algorithm  Specify hashing algorithm (default: sha256)\n");
    printf("  -h, --help    Show this help message\n\n");
    printf("Supported algorithms:\n");
    print_supported_algorithms();
    printf("\nExamples:\n");
    printf("  %s myfile.txt\n", program_name);
    printf("  %s -a sha512 myfile.txt\n", program_name);
    printf("  %s myfile.txt 2c26b46911185131006145e7e22b6f651a87667c\n", program_name);
}

void print_supported_algorithms(void) {
    printf("  sha256 (default) - 256-bit hash (64 hex chars)\n");
    printf("  sha512          - 512-bit hash (128 hex chars)\n");
}
