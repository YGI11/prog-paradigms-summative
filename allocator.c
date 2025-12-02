#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "allocator.h"

#define ALIGNMENT 40

uint8_t *global_heap_pointer;
size_t global_heap_size;
uint8_t global_pattern[5];

struct __attribute__((packed)) block {
  /* struct to segment the heap into blocks allowing us to track what
   * space is available and what space is and isn't free.
   */
  size_t block_size; /* size of block */
  uint8_t is_free;   /* 1 = true, 0 = false */
  uint8_t padding[31];
};

/* Function declarations */
static size_t align_size(size_t size);
static void fill_pattern(void *ptr, size_t len);

/* Initialize allocator with a heap buffer and size */
int mm_init(uint8_t *heap, size_t heap_size) {
  if (heap == NULL) {
    return -1;
  }

  /* Copy 5-byte pattern from heap (behaviour retained from original) */
  for (size_t i = 0; i < 5; i++) {
    global_pattern[i] = heap[i];
  }

  /* Set global heap pointer and size */
  global_heap_pointer = heap;
  global_heap_size = heap_size;

  if (global_heap_size < sizeof(struct block)) {
    fprintf(stderr, "Heap size too small\n");
    return -1;
  }

  struct block *header = (struct block *)global_heap_pointer;
  header->is_free = 1;
  header->block_size = global_heap_size - sizeof(struct block);

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
    if (header->block_size >= aligned_size && header->is_free) {
      if (header->block_size > aligned_size + sizeof(struct block)) {
        size_t old_block_size = header->block_size;
        header->block_size = aligned_size;

        uint8_t *temp2 = (uint8_t *)header;
        temp2 += sizeof(struct block) + aligned_size;
        struct block *new_header = (struct block *)temp2;
        new_header->block_size = old_block_size - aligned_size - sizeof(struct block);
        new_header->is_free = 1;
      }

      header->is_free = 0;
      return (void *)(header + 1);
    }

    uint8_t *temp1 = (uint8_t *)header;
    temp1 += sizeof(struct block) + header->block_size;
    header = (struct block *)temp1;
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
  if (header->is_free == 1) {
    return;
  }

  struct block *curr_header = (struct block *)global_heap_pointer;
  uint8_t *heap_end = global_heap_pointer + global_heap_size;
  struct block *prev_header = NULL;
  struct block *nxt_header = NULL;

  while ((uint8_t *)curr_header + sizeof(struct block) <= heap_end) {
    if (curr_header == header) {
      header->is_free = 1;

      uint8_t *temp1 = (uint8_t *)header;
      temp1 += header->block_size + sizeof(struct block);
      nxt_header = (struct block *)temp1;

      while ((uint8_t *)nxt_header + sizeof(struct block) <= heap_end &&
             nxt_header->is_free == 1) {
        header->block_size += nxt_header->block_size + sizeof(struct block);
        uint8_t *temp3 = (uint8_t *)header;
        temp3 += header->block_size + sizeof(struct block);
        nxt_header = (struct block *)temp3;
      }

      if (prev_header != NULL && prev_header->is_free == 1) {
        prev_header->block_size += header->block_size + sizeof(struct block);
        fill_pattern((void *)(prev_header + 1), prev_header->block_size);
        return;
      }

      fill_pattern(ptr, header->block_size);
      return;
    } else {
      prev_header = curr_header;
      uint8_t *temp2 = (uint8_t *)curr_header;
      temp2 += curr_header->block_size + sizeof(struct block);
      curr_header = (struct block *)temp2;
    }
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

  if (header->is_free == 0) {
    if (offset + len <= header->block_size) {
      uint8_t *destination = (uint8_t *)ptr + offset;
      for (size_t i = 0; i < len; i++) {
        destination[i] = ((uint8_t *)src)[i];
      }
      return (int)len;
    } else {
      return -1;
    }
  } else {
    return -1;
  }
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

  if (header->is_free == 0) {
    if (offset + len <= header->block_size) {
      uint8_t *source = (uint8_t *)ptr + offset;
      for (size_t i = 0; i < len; i++) {
        ((uint8_t *)buf)[i] = source[i];
      }
      return (int)len;
    } else {
      return -1;
    }
  } else {
    return -1;
  }
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