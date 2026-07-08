import os
import random
def generate_random_file(filename, size):
    """Generate a random text file of a specified size"""
    # 1MB = 1024*1024 bytes
    sizes = {
        '1KB': 1024,
        '1MB': 1024*1024,
        '100MB': 100*1024*1024,
        '1GB': 1024*1024*1024
    }
    
    target_size = sizes[size]
    
    with open(filename, 'w') as f:
        chunk_size = 1024  
        written = 0
        
        while written < target_size:
            remaining = target_size - written
            current_chunk = min(chunk_size, remaining)
            
            # Generate random printable characters
            random_chars = ''.join(chr(random.randint(32, 126)) for _ in range(current_chunk))
            f.write(random_chars)
            written += current_chunk
    
    print(f"生成文件: {filename} ({size}), 实际大小: {os.path.getsize(filename)} bytes")

# Generate four test files
generate_random_file("test_1KB.txt", "1KB")
generate_random_file("test_1MB.txt", "1MB") 
generate_random_file("test_100MB.txt", "100MB")
generate_random_file("test_1GB.txt", "1GB")