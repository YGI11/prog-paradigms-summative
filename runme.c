#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "allocator.h"

int tests_passed = 0;
int tests_failed = 0;

void test_pass(const char *test_name) {
    printf("✅ PASS: %s\n", test_name);
    tests_passed++;
}

void test_fail(const char *test_name) {
    printf("❌ FAIL: %s\n", test_name);
    tests_failed++;
}

void check(int condition, const char *test_name) {
    if (condition) {
        test_pass(test_name);
    } else {
        test_fail(test_name);
    }
}

int main(int argc, char *argv[]) {
    size_t heap_size = 8192;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            heap_size = atoi(argv[i + 1]);
        }
    }
    
    uint8_t *heap = malloc(heap_size);
    if (heap == NULL) {
        printf("Failed to allocate heap\n");
        return 1;
    }
    
    // Fill heap with pattern (simulate autograder)
    for (size_t i = 0; i < heap_size; i++) {
        heap[i] = (uint8_t)((i % 5) + 1);
    }
    
    printf("=== MEMORY ALLOCATOR TESTS ===\n");
    printf("Heap size: %zu bytes\n\n", heap_size);
    
    // ==================== TEST 1: mm_init ====================
    printf("--- Test Group: mm_init ---\n");
    
    int init_result = mm_init(heap, heap_size);
    check(init_result == 0, "mm_init returns 0 on success");
    
    check(mm_init(NULL, heap_size) == -1, "mm_init returns -1 for NULL heap");
    
    // Re-init for remaining tests
    mm_init(heap, heap_size);
    
    // ==================== TEST 2: Basic Allocation ====================
    printf("\n--- Test Group: Basic Allocation ---\n");
    
    void *ptr1 = mm_malloc(100);
    check(ptr1 != NULL, "mm_malloc(100) returns non-NULL");
    check(((size_t)ptr1 % 40) == 0, "mm_malloc(100) returns 40-byte aligned pointer");
    
    void *ptr2 = mm_malloc(200);
    check(ptr2 != NULL, "mm_malloc(200) returns non-NULL");
    check(((size_t)ptr2 % 40) == 0, "mm_malloc(200) returns 40-byte aligned pointer");
    check(ptr2 != ptr1, "Second allocation returns different pointer");
    
    void *ptr3 = mm_malloc(40);
    check(ptr3 != NULL, "mm_malloc(40) returns non-NULL");
    check(((size_t)ptr3 % 40) == 0, "mm_malloc(40) returns 40-byte aligned pointer");
    
    // ==================== TEST 3: Edge Cases ====================
    printf("\n--- Test Group: Edge Cases ---\n");
    
    check(mm_malloc(0) == NULL, "mm_malloc(0) returns NULL");
    
    void *ptr_small = mm_malloc(1);
    check(ptr_small != NULL, "mm_malloc(1) returns non-NULL");
    check(((size_t)ptr_small % 40) == 0, "mm_malloc(1) returns 40-byte aligned pointer");
    
    // ==================== TEST 4: mm_write ====================
    printf("\n--- Test Group: mm_write ---\n");
    
    const char *test_data = "Hello, Mars!";
    int write_result = mm_write(ptr1, 0, test_data, strlen(test_data) + 1);
    check(write_result == (int)(strlen(test_data) + 1), "mm_write returns correct length");
    
    check(mm_write(NULL, 0, test_data, 5) == -1, "mm_write returns -1 for NULL ptr");
    check(mm_write(ptr1, 1000, test_data, 5) == -1, "mm_write returns -1 for offset out of bounds");
    
    // Write at offset
    int write_offset = mm_write(ptr1, 50, "Test", 4);
    check(write_offset == 4, "mm_write at offset returns correct length");
    
    // ==================== TEST 5: mm_read ====================
    printf("\n--- Test Group: mm_read ---\n");
    
    char read_buf[50];
    memset(read_buf, 0, sizeof(read_buf));
    int read_result = mm_read(ptr1, 0, read_buf, strlen(test_data) + 1);
    check(read_result == (int)(strlen(test_data) + 1), "mm_read returns correct length");
    check(strcmp(read_buf, test_data) == 0, "mm_read returns correct data");
    
    check(mm_read(NULL, 0, read_buf, 5) == -1, "mm_read returns -1 for NULL ptr");
    check(mm_read(ptr1, 1000, read_buf, 5) == -1, "mm_read returns -1 for offset out of bounds");
    
    // Read at offset
    memset(read_buf, 0, sizeof(read_buf));
    int read_offset = mm_read(ptr1, 50, read_buf, 4);
    check(read_offset == 4, "mm_read at offset returns correct length");
    check(memcmp(read_buf, "Test", 4) == 0, "mm_read at offset returns correct data");
    
    // ==================== TEST 6: mm_free ====================
    printf("\n--- Test Group: mm_free ---\n");
    
    mm_free(ptr1);
    test_pass("mm_free(ptr1) completed without crash");
    
    mm_free(NULL);
    test_pass("mm_free(NULL) completed without crash");
    
    // ==================== TEST 7: Reallocation After Free ====================
    printf("\n--- Test Group: Reallocation After Free ---\n");
    
    void *ptr_realloc = mm_malloc(80);
    check(ptr_realloc != NULL, "mm_malloc after free returns non-NULL");
    check(((size_t)ptr_realloc % 40) == 0, "Reallocated pointer is 40-byte aligned");
    
    // ==================== TEST 8: Coalescing ====================
    printf("\n--- Test Group: Coalescing ---\n");
    
    // Re-init for clean state
    mm_init(heap, heap_size);
    
    void *c1 = mm_malloc(80);
    void *c2 = mm_malloc(80);
    void *c3 = mm_malloc(80);
    
    check(c1 != NULL && c2 != NULL && c3 != NULL, "Three consecutive allocations succeed");
    
    // Free middle
    mm_free(c2);
    test_pass("Free middle block completed");
    
    // Free first (should coalesce with middle)
    mm_free(c1);
    test_pass("Free first block (coalesce backward) completed");
    
    // Free last (should coalesce all)
    mm_free(c3);
    test_pass("Free last block (coalesce all) completed");
    
    // Should be able to allocate large block now
    void *c_big = mm_malloc(200);
    check(c_big != NULL, "Large allocation after coalescing succeeds");
    
    // ==================== TEST 9: Multiple Allocations ====================
    printf("\n--- Test Group: Multiple Allocations ---\n");
    
    // Re-init for clean state
    mm_init(heap, heap_size);
    
    void *ptrs[20];
    int all_success = 1;
    int all_aligned = 1;
    
    for (int i = 0; i < 20; i++) {
        ptrs[i] = mm_malloc(40);
        if (ptrs[i] == NULL) all_success = 0;
        if (((size_t)ptrs[i] % 40) != 0) all_aligned = 0;
    }
    
    check(all_success, "20 consecutive allocations all succeed");
    check(all_aligned, "20 consecutive allocations all 40-byte aligned");
    
    // Free every other one
    for (int i = 0; i < 20; i += 2) {
        mm_free(ptrs[i]);
    }
    test_pass("Free every other block completed");
    
    // Allocate again in freed spots
    int realloc_success = 1;
    for (int i = 0; i < 10; i++) {
        void *p = mm_malloc(40);
        if (p == NULL) realloc_success = 0;
    }
    check(realloc_success, "Reallocation in freed spots succeeds");
    
    // ==================== TEST 10: Write/Read Verification ====================
    printf("\n--- Test Group: Write/Read Verification ---\n");
    
    mm_init(heap, heap_size);
    
    void *data_ptr = mm_malloc(200);
    check(data_ptr != NULL, "Allocation for data test succeeds");
    
    // Write pattern
    uint8_t write_pattern[100];
    for (int i = 0; i < 100; i++) {
        write_pattern[i] = (uint8_t)(i * 3 + 7);
    }
    
    int w = mm_write(data_ptr, 0, write_pattern, 100);
    check(w == 100, "Write 100 bytes returns 100");
    
    // Read and verify
    uint8_t read_pattern[100];
    int r = mm_read(data_ptr, 0, read_pattern, 100);
    check(r == 100, "Read 100 bytes returns 100");
    
    int data_match = (memcmp(write_pattern, read_pattern, 100) == 0);
    check(data_match, "Read data matches written data");
    
    // ==================== TEST 11: Boundary Conditions ====================
    printf("\n--- Test Group: Boundary Conditions ---\n");
    
    mm_init(heap, heap_size);
    
    // Try to allocate more than heap size
    void *too_big = mm_malloc(heap_size);
    check(too_big == NULL, "mm_malloc larger than heap returns NULL");
    
    // Allocate exactly fitting block (minus header)
    void *exact = mm_malloc(heap_size - 80);
    // This may or may not succeed depending on implementation
    if (exact != NULL) {
        check(((size_t)exact % 40) == 0, "Large exact allocation is aligned");
        mm_free(exact);
    }
    
    // ==================== TEST 12: Double Free Detection ====================
    printf("\n--- Test Group: Double Free ---\n");
    
    mm_init(heap, heap_size);
    
    void *df_ptr = mm_malloc(100);
    mm_free(df_ptr);
    mm_free(df_ptr);  // Double free - should not crash
    test_pass("Double free did not crash");
    
    // ==================== TEST 13: Invalid Pointer ====================
    printf("\n--- Test Group: Invalid Pointers ---\n");
    
    mm_free((void *)0x12345678);  // Random invalid pointer
    test_pass("Free of invalid pointer did not crash");
    
    check(mm_read((void *)0x12345678, 0, read_buf, 5) == -1, "mm_read invalid pointer returns -1");
    check(mm_write((void *)0x12345678, 0, "test", 4) == -1, "mm_write invalid pointer returns -1");
    
    // ==================== TEST 14: Stress Test ====================
    printf("\n--- Test Group: Stress Test ---\n");
    
    mm_init(heap, heap_size);
    
    int stress_success = 1;
    for (int round = 0; round < 10; round++) {
        void *stress_ptrs[10];
        
        // Allocate
        for (int i = 0; i < 10; i++) {
            stress_ptrs[i] = mm_malloc(40 + (i * 10));
            if (stress_ptrs[i] == NULL) {
                // May run out of memory, that's ok
            }
        }
        
        // Write
        for (int i = 0; i < 10; i++) {
            if (stress_ptrs[i] != NULL) {
                mm_write(stress_ptrs[i], 0, "STRESS", 6);
            }
        }
        
        // Read
        for (int i = 0; i < 10; i++) {
            if (stress_ptrs[i] != NULL) {
                char buf[10];
                mm_read(stress_ptrs[i], 0, buf, 6);
            }
        }
        
        // Free
        for (int i = 0; i < 10; i++) {
            if (stress_ptrs[i] != NULL) {
                mm_free(stress_ptrs[i]);
            }
        }
    }
    check(stress_success, "Stress test completed without crash");
    
    // ==================== TEST 15: Simulated Corruption ====================
    printf("\n--- Test Group: Simulated Corruption ---\n");
    
    mm_init(heap, heap_size);
    
    void *corrupt_ptr = mm_malloc(100);
    check(corrupt_ptr != NULL, "Allocation for corruption test succeeds");
    
    mm_write(corrupt_ptr, 0, "Important Data", 14);
    
    // Simulate bit flip in header (corrupt the block_size)
    uint8_t *header_bytes = (uint8_t *)corrupt_ptr - 40;  // Go back to header
    header_bytes[0] ^= 0x01;  // Flip one bit in block_size
    
    // Try to read - should detect corruption
    char corrupt_buf[20];
    int corrupt_read = mm_read(corrupt_ptr, 0, corrupt_buf, 14);
    check(corrupt_read == -1, "mm_read detects corruption and returns -1");
    
    // Try to write - should detect corruption
    int corrupt_write = mm_write(corrupt_ptr, 0, "New Data", 8);
    check(corrupt_write == -1, "mm_write detects corruption and returns -1");
    
    // Try to free - should handle gracefully
    mm_free(corrupt_ptr);
    test_pass("mm_free of corrupted block did not crash");
    
    // ==================== TEST 16: Corruption in Different Fields ====================
    printf("\n--- Test Group: Corruption in Different Fields ---\n");
    
    mm_init(heap, heap_size);
    
    void *test_ptr = mm_malloc(100);
    
    // Test canary corruption
    uint8_t *hdr = (uint8_t *)test_ptr - 40;
    
    // Save original values
    uint8_t original[40];
    memcpy(original, hdr, 40);
    
    // Corrupt canary (bytes 21-24 in struct: 8 + 8 + 1 + 4 = 21)
    hdr[21] ^= 0xFF;
    
    int canary_read = mm_read(test_ptr, 0, corrupt_buf, 10);
    check(canary_read == -1, "mm_read detects canary corruption");
    
    // Restore and try checksum corruption
    memcpy(hdr, original, 40);
    
    // Corrupt checksum (bytes 17-20: 8 + 8 + 1 = 17)
    hdr[17] ^= 0xFF;
    
    int checksum_read = mm_read(test_ptr, 0, corrupt_buf, 10);
    check(checksum_read == -1, "mm_read detects checksum corruption");
    
    // ==================== TEST 17: Allocation After Corruption ====================
    printf("\n--- Test Group: Allocation After Corruption ---\n");
    
    mm_init(heap, heap_size);
    
    void *a1 = mm_malloc(80);
    void *a2 = mm_malloc(80);
    void *a3 = mm_malloc(80);
    
    // Corrupt a2's header
    uint8_t *a2_hdr = (uint8_t *)a2 - 40;
    a2_hdr[0] ^= 0x01;
    
    // Free a1 and a3
    mm_free(a1);
    mm_free(a3);
    
    // Try to allocate - should skip corrupted block
    void *new_alloc = mm_malloc(60);
    // May or may not succeed, but should not crash
    test_pass("Allocation with corrupted block in heap did not crash");
    
    // ==================== SUMMARY ====================
    printf("\n=== TEST SUMMARY ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n🎉 ALL TESTS PASSED! 🎉\n");
    } else {
        printf("\n⚠️  SOME TESTS FAILED ⚠️\n");
    }
    
    free(heap);
    return tests_failed > 0 ? 1 : 0;
}