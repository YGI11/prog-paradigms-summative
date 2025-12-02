#ifndef ALLOCATOR_H
#define ALLOCATOR_H

int mm_init(uint8_t *heap, size_t heap_size);
void *mm_malloc(size_t size);
void mm_free(void *ptr);
int mm_read(void *ptr, size_t offset, void *buf, size_t len);
int mm_write(void *ptr, size_t offset, const void *src, size_t
len);

#endif