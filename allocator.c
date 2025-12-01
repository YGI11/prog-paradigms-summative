#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "allocator.h"

#define ALIGNMENT 40

uint8_t *global_heap_pointer;
size_t global_heap_size; 
uint8_t global_pattern[5];

struct block{  //struct to segment the heap into blocks allowing us to track what space is available and what space is and isn't free.
    size_t block_size;  //size of block
    bool is_free;   // values in c are 1 for true and 0 for false
    int checksum;   //check for corruption
    int canary;     //additional check for corruption
    uint8_t padding[16];
};

// Function to align size to the nearest multiple of ALIGNMENT
static size_t align_size(size_t size);
static void fill_pattern(void *ptr, size_t len);


int mm_init(uint8_t *heap, size_t heap_size) {  //parameters are pointer to heap and size of the heap.
   
   if (heap == NULL) {     //if allocation didn't work return -1
       return -1;
   }
   for (size_t i = 0; i<5; i++) {
         global_pattern[i] = heap[i];
   }
     //if allocation worked save heap pointer and heap size as global variables so it can be accessed by mm_malloc
   size_t offset = (40 - ((size_t)heap % 40)) % 40;
   uint8_t *aligned_heap = heap + offset;
   global_heap_pointer = aligned_heap;
   global_heap_size = heap_size - offset;
   global_heap_size = (global_heap_size / 40) * 40;
   if (global_heap_size < sizeof(struct block) + 40) {
            return -1;
   }

   struct block *header = (struct block *)global_heap_pointer; //make a header pointer for the first block of the heap
   header->is_free = 1; //set header as free to true
   header->block_size = global_heap_size - sizeof(struct block); //the size of the header is the current heap_size - size of the block
        
   return 0;
    
   
}


void *mm_malloc(size_t size) {
    if (global_heap_pointer == NULL) {
    return NULL; 
    }
    if (size == 0) {
        return NULL;
    }
    size_t aligned_size = align_size(size);
    struct block *header = (struct block*)global_heap_pointer;
    uint8_t *heap_end = global_heap_pointer + global_heap_size;
    while ((uint8_t*)header + sizeof(struct block) <= heap_end)  {
      if (header->block_size >= aligned_size && header->is_free) {
       if (header->block_size > aligned_size + sizeof(struct block)) {
        size_t old_block_size = header->block_size;
        header->block_size = aligned_size;
        uint8_t *temp2 = (uint8_t*)header;
        temp2 += sizeof(struct block) + aligned_size;
        struct block *new_header = (struct block*) temp2;
        new_header->block_size = old_block_size - aligned_size - sizeof(struct block);
        new_header->is_free = 1;
       }
       header->is_free = 0;
       return (void *)(header + 1);
     
      }      
      uint8_t *temp1 = (uint8_t *) header;
      temp1 += sizeof(struct block) + header->block_size;
      header = (struct block *) temp1;       
    }
    return NULL;
}


void mm_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    
    if (global_heap_pointer == NULL) {
    return; 
    }
    
    if (ptr < (void *)global_heap_pointer || ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return; 
    }
   

    else {
        struct block *header = (struct block*)ptr - 1;
        if (header->is_free == 1) {
            return;
        }
        else {
            struct block *curr_header = (struct block*)global_heap_pointer;
            uint8_t *heap_end = global_heap_pointer + global_heap_size;
            struct block *prev_header = NULL;
            struct block *nxt_header = NULL;
            while ((uint8_t *)curr_header + sizeof(struct block) <= heap_end) {
             if (curr_header == header) {
               header->is_free = 1;
               
               uint8_t *temp1 = (uint8_t *)header;
               temp1 += header->block_size + sizeof(struct block);
               nxt_header = (struct block*) temp1;
               while ((uint8_t *)nxt_header + sizeof(struct block) <= heap_end && nxt_header->is_free == 1) {
                header->block_size +=  nxt_header->block_size + sizeof(struct block);
                uint8_t *temp3 = (uint8_t *)header;
                temp3 += header->block_size + sizeof(struct block);
                nxt_header = (struct block*)temp3;
               }
               if (prev_header != NULL && prev_header->is_free == 1) {
                prev_header->block_size += header->block_size + sizeof(struct block);
                fill_pattern((void *)(prev_header + 1), prev_header->block_size);
                return;
               
               }
               fill_pattern(ptr, header->block_size);
               return;
                
             }  
             else {
               prev_header = curr_header;
               uint8_t *temp2 = (uint8_t *)curr_header;
               temp2 += curr_header->block_size + sizeof(struct block);
               curr_header = (struct block*)temp2;
             }
            }
            return;         
            
            
            
            
        }
    }

}

int mm_write(void *ptr, size_t offset, const void *src, size_t
len) {
    if (ptr == NULL) {
        return -1;
    }
    if (global_heap_pointer == NULL) {
    return -1; 
    }
    
    if (ptr < (void *)global_heap_pointer || ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return -1; 
    }
    
    else {
        struct block *header = (struct block *)ptr - 1;
        if (header->is_free == 0) {
          if (offset + len <= header->block_size) {
            uint8_t *destination = (uint8_t *)ptr + offset;
            for (size_t i=0; i < len; i++) {
                destination[i] = ((uint8_t *)src)[i];
            }
          return len;
          } 
          else {
            return -1;
          }
        }
        else {
            return -1;
        }
    }


}


int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    if (ptr == NULL) {
        return -1;
    }
    
    if (global_heap_pointer == NULL) {
    return -1; 
    }
    if (ptr < (void *)global_heap_pointer || ptr >= (void *)(global_heap_pointer + global_heap_size)) {
    return -1; 
    }
    
    else {
        struct block *header = (struct block *)ptr - 1;
        if (header->is_free == 0) {
          if (offset + len <= header->block_size) {
            uint8_t *source = (uint8_t *)ptr + offset;
            for (size_t i=0; i<len; i++) {
                ((uint8_t *)buf)[i] = source[i];
            }
            return len;
          }
          else {
            return -1;
          }
        }
        else {
            return -1;
        }

    }
        
}

static size_t align_size(size_t size) {
    return size % ALIGNMENT ? size + (ALIGNMENT - (size % ALIGNMENT)) : size;  
}

static void fill_pattern(void *ptr, size_t len) {
    uint8_t *p = (uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = global_pattern[i % 5];
    }
}