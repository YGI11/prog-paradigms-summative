#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "allocator.h"

#define ALIGNMENT 40
#define CANARY_VALUE 0xDEADBEEF

uint8_t *global_heap_pointer;
size_t global_heap_size;
uint8_t global_pattern[5];

struct __attribute__((packed)) block {
  size_t block_size;          // 8 bytes
  size_t block_size_copy;     // 8 bytes
  size_t requested_size;      // 8 bytes - ORIGINAL size user asked for
  uint8_t is_free;            // 1 byte (0 = allocated, 1 = free, 2 = quarantined)
  uint8_t is_free_copy;       // 1 byte
  uint32_t header_checksum;   // 4 bytes
  uint32_t payload_checksum;  // 4 bytes
  uint32_t canary;            // 4 bytes
  uint8_t padding[2];         // 2 bytes (adjusted for new field)
};  // Total: 40 bytes

/* Function declarations */
static size_t align_size(size_t size);
static void fill_pattern(void *ptr, size_t len);
static uint32_t compute_header_checksum(struct block *header);
static uint32_t compute_payload_checksum(void *payload, size_t len);
static void set_header_fields(struct block *header);
static void set_payload_checksum(struct block *header);
static uint8_t verify_header(struct block *header);
static uint8_t verify_payload(struct block *header);
static void quarantine_block(struct block *header);
static size_t get_safe_skip_size(struct block *header);

/* Compute header checksum using offsetof */
static uint32_t compute_header_checksum(struct block *header) {
  uint8_t *bytes = (uint8_t *)header;
  uint32_t sum = 0;
  
  /* Checksum from block_size through is_free_copy */
  /* This now includes requested_size automatically! */
  size_t start = offsetof(struct block, block_size);
  size_t end = offsetof(struct block, is_free_copy) + sizeof(uint8_t);
  
  for (size_t i = start; i < end; i++) {
    sum = sum * 31 + bytes[i];
  }
  
  return sum;
}

/* Compute payload checksum */
static uint32_t compute_payload_checksum(void *payload, size_t len) {
  uint8_t *p = (uint8_t *)payload;
  uint32_t sum = 0;
  
  for (size_t i = 0; i < len; i++) {
    sum = sum * 31 + p[i];
  }
  
  return sum;
}

/* Set header protection fields */
static void set_header_fields(struct block *header) {
  header->block_size_copy = header->block_size;
  header->is_free_copy = header->is_free;
  header->canary = CANARY_VALUE;
  header->header_checksum = compute_header_checksum(header);
}

/* Set payload checksum */
static void set_payload_checksum(struct block *header) {
  void *payload = (void *)(header + 1);
  header->payload_checksum = compute_payload_checksum(payload, header->block_size);
}

/* Verify header integrity */
static uint8_t verify_header(struct block *header) {
  /* Check canary */
  if (header->canary != CANARY_VALUE) {
    return 0;
  }
  
  /* Check redundant copies */
  if (header->is_free != header->is_free_copy) {
    return 0;
  }
  
  if (header->block_size != header->block_size_copy) {
    return 0;
  }
  
  /* Check header checksum */
  if (header->header_checksum != compute_header_checksum(header)) {
    return 0;
  }
  
  /* Sanity checks */
  if (header->is_free > 2) {
    return 0;
  }
  
  if (header->block_size == 0 || header->block_size > global_heap_size) {
    return 0;
  }
  
  /* Verify requested_size makes sense */
  if (header->is_free == 0 && header->requested_size > header->block_size) {
    return 0;
  }
  
  return 1;
}

/* Verify payload integrity */
static uint8_t verify_payload(struct block *header) {
  void *payload = (void *)(header + 1);
  if (header->payload_checksum != compute_payload_checksum(payload, header->block_size)) {
    return 0;
  }
  return 1;
}

/* Quarantine a corrupted block */
static void quarantine_block(struct block *header) {
  header->is_free = 2;
  header->is_free_copy = 2;
}

/* Get safe skip size for traversal */
static size_t get_safe_skip_size(struct block *header) {
  size_t size = header->block_size;
  
  if (size > 0 && size <= global_heap_size && size % ALIGNMENT == 0) {
    return size;
  }
  
  size = header->block_size_copy;
  
  if (size > 0 && size <= global_heap_size && size % ALIGNMENT == 0) {
    return size;
  }
  
  return 0;
}

/* Initialize allocator with a heap buffer and size */
int mm_init(uint8_t *heap, size_t heap_size) {
  if (heap == NULL) {
    return -1;
  }

  /* Copy 5-byte pattern from heap */
  for (size_t i = 0; i < 5; i++) {
    global_pattern[i] = heap[i];
  }

  global_heap_pointer = heap;
  global_heap_size = heap_size;

  if (global_heap_size < sizeof(struct block) + ALIGNMENT) {
    return -1;
  }

  struct block *header = (struct block *)global_heap_pointer;
  header->is_free = 1;
  header->block_size = global_heap_size - sizeof(struct block);
  header->block_size = (header->block_size / ALIGNMENT) * ALIGNMENT;
  header->requested_size = 0;  /* Free block has no requested size */
  
  set_header_fields(header);
  
  /* Fill payload with pattern and set payload checksum */
  fill_pattern((void *)(header + 1), header->block_size);
  set_payload_checksum(header);

  return 0;
}

/* Allocate a block of memory (aligned) */
void *mm_malloc(size_t size) {
  if (global_heap_pointer == NULL) {
    return NULL;
  }

  if (size == 0) {
    return NULL;
  }

  size_t aligned_size = align_size(size);
  struct block *header = (struct block *)global_heap_pointer;
  uint8_t *heap_end = global_heap_pointer + global_heap_size;

  while ((uint8_t *)header + sizeof(struct block) <= heap_end) {
    
    /* Skip quarantined blocks */
    if (header->is_free == 2) {
      size_t skip = get_safe_skip_size(header);
      if (skip == 0) {
        return NULL;
      }
      header = (struct block *)((uint8_t *)header + sizeof(struct block) + skip);
      continue;
    }
    
    /* Verify header */
    if (!verify_header(header)) {
      quarantine_block(header);
      size_t skip = get_safe_skip_size(header);
      if (skip == 0) {
        return NULL;
      }
      header = (struct block *)((uint8_t *)header + sizeof(struct block) + skip);
      continue;
    }
    
    /* For free blocks, also verify payload */
    if (header->is_free == 1) {
      if (!verify_payload(header)) {
        quarantine_block(header);
        size_t skip = get_safe_skip_size(header);
        if (skip == 0) {
          return NULL;
        }
        header = (struct block *)((uint8_t *)header + sizeof(struct block) + skip);
        continue;
      }
    }
    
    /* Check if free and big enough */
    if (header->is_free == 1 && header->block_size >= aligned_size) {
      /* Split if enough room */
      if (header->block_size > aligned_size + sizeof(struct block)) {
        size_t old_block_size = header->block_size;
        header->block_size = aligned_size;
        header->requested_size = size;  /* Store ORIGINAL requested size */
        set_header_fields(header);

        struct block *new_header = (struct block *)((uint8_t *)header + sizeof(struct block) + aligned_size);
        new_header->block_size = old_block_size - aligned_size - sizeof(struct block);
        new_header->is_free = 1;
        new_header->requested_size = 0;  /* Free block */
        set_header_fields(new_header);
        
        /* Fill new block with pattern and set its payload checksum */
        fill_pattern((void *)(new_header + 1), new_header->block_size);
        set_payload_checksum(new_header);
      } else {
        /* No split - use whole block */
        header->requested_size = size;  /* Store ORIGINAL requested size */
      }

      header->is_free = 0;
      set_header_fields(header);
      set_payload_checksum(header);
      return (void *)(header + 1);
    }

    header = (struct block *)((uint8_t *)header + sizeof(struct block) + header->block_size);
  }

  return NULL;
}

/* Free an allocated block and coalesce if possible */
void mm_free(void *ptr) {
  if (ptr == NULL) {
    return;
  }

  if (global_heap_pointer == NULL) {
    return;
  }

  if (ptr < (void *)global_heap_pointer ||
      ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return;
  }

  struct block *header = (struct block *)ptr - 1;
  
  /* Skip if quarantined */
  if (header->is_free == 2) {
    return;
  }
  
  /* Verify header */
  if (!verify_header(header)) {
    quarantine_block(header);
    return;
  }
  
  /* Verify payload */
  if (!verify_payload(header)) {
    quarantine_block(header);
    return;
  }
  
  /* Check for double free */
  if (header->is_free == 1) {
    return;
  }

  /* Walk heap to find prev_header */
  struct block *curr_header = (struct block *)global_heap_pointer;
  uint8_t *heap_end = global_heap_pointer + global_heap_size;
  struct block *prev_header = NULL;

  while ((uint8_t *)curr_header + sizeof(struct block) <= heap_end) {
    
    /* Skip quarantined */
    if (curr_header->is_free == 2) {
      size_t skip = get_safe_skip_size(curr_header);
      if (skip == 0) {
        return;
      }
      curr_header = (struct block *)((uint8_t *)curr_header + sizeof(struct block) + skip);
      continue;
    }
    
    /* Verify during walk */
    if (!verify_header(curr_header)) {
      quarantine_block(curr_header);
      size_t skip = get_safe_skip_size(curr_header);
      if (skip == 0) {
        return;
      }
      curr_header = (struct block *)((uint8_t *)curr_header + sizeof(struct block) + skip);
      continue;
    }
    
    if (curr_header == header) {
      header->is_free = 1;
      header->requested_size = 0;  /* Free block has no requested size */
      set_header_fields(header);

      /* Coalesce with next blocks */
      struct block *nxt_header = (struct block *)((uint8_t *)header + sizeof(struct block) + header->block_size);

      while ((uint8_t *)nxt_header + sizeof(struct block) <= heap_end) {
        if (nxt_header->is_free == 2) {
          break;
        }
        if (!verify_header(nxt_header)) {
          quarantine_block(nxt_header);
          break;
        }
        if (nxt_header->is_free != 1) {
          break;
        }
        if (!verify_payload(nxt_header)) {
          quarantine_block(nxt_header);
          break;
        }
        
        header->block_size += nxt_header->block_size + sizeof(struct block);
        set_header_fields(header);
        
        nxt_header = (struct block *)((uint8_t *)header + sizeof(struct block) + header->block_size);
      }

      /* Coalesce with prev if free */
      if (prev_header != NULL && prev_header->is_free == 1) {
        prev_header->block_size += header->block_size + sizeof(struct block);
        set_header_fields(prev_header);
        fill_pattern((void *)(prev_header + 1), prev_header->block_size);
        set_payload_checksum(prev_header);
        return;
      }

      fill_pattern(ptr, header->block_size);
      set_payload_checksum(header);
      return;
    }
    
    prev_header = curr_header;
    curr_header = (struct block *)((uint8_t *)curr_header + sizeof(struct block) + curr_header->block_size);
  }
}

/* Write to an allocated block */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
  if (ptr == NULL) {
    return -1;
  }

  if (global_heap_pointer == NULL) {
    return -1;
  }

  if (ptr < (void *)global_heap_pointer ||
      ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return -1;
  }

  struct block *header = (struct block *)ptr - 1;

  /* Skip if quarantined */
  if (header->is_free == 2) {
    return -1;
  }

  /* Verify header */
  if (!verify_header(header)) {
    quarantine_block(header);
    return -1;
  }

  /* Verify payload before write */
  if (!verify_payload(header)) {
    quarantine_block(header);
    return -1;
  }

  /* Must be allocated */
  if (header->is_free != 0) {
    return -1;
  }

  /* BROWNOUT CHECK: Write must match requested size exactly */
  if (offset != 0 || len != header->requested_size) {
    return -1;
  }

  /* Do the write */
  uint8_t *destination = (uint8_t *)ptr + offset;
  for (size_t i = 0; i < len; i++) {
    destination[i] = ((uint8_t *)src)[i];
  }

  /* Update payload checksum after write */
  set_payload_checksum(header);

  return (int)len;
}

/* Read from an allocated block */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
  if (ptr == NULL) {
    return -1;
  }

  if (global_heap_pointer == NULL) {
    return -1;
  }

  if (ptr < (void *)global_heap_pointer ||
      ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return -1;
  }

  struct block *header = (struct block *)ptr - 1;

  /* Skip if quarantined */
  if (header->is_free == 2) {
    return -1;
  }

  /* Verify header */
  if (!verify_header(header)) {
    quarantine_block(header);
    return -1;
  }

  /* Verify payload before read */
  if (!verify_payload(header)) {
    quarantine_block(header);
    return -1;
  }

  /* Must be allocated */
  if (header->is_free != 0) {
    return -1;
  }

  /* BROWNOUT CHECK: Read must match requested size exactly */
  if (offset != 0 || len != header->requested_size) {
    return -1;
  }

  /* Do the read */
  uint8_t *source = (uint8_t *)ptr + offset;
  for (size_t i = 0; i < len; i++) {
    ((uint8_t *)buf)[i] = source[i];
  }

  return (int)len;
}

/* Align size to nearest multiple of ALIGNMENT */
static size_t align_size(size_t size) {
  return size % ALIGNMENT ? size + (ALIGNMENT - (size % ALIGNMENT)) : size;
}

/* Fill block payload with pattern */
static void fill_pattern(void *ptr, size_t len) {
  uint8_t *p = (uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    p[i] = global_pattern[i % 5];
  }
}


