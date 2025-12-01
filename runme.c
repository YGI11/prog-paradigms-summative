#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "allocator.h"
#include <string.h>


int main(int argc, char *argv[]) {
    size_t heap_size = 8192; //default heap size in case user doesn't specify 
    
    
    for (int i = 1; i < argc; i++) {     //allows user to enter deisgnated size via '--size' in command line
        if (strcmp(argv[i], "--size") == 0) {
            heap_size = atoi(argv[i + 1]);
        }
    }
    
    //setup
    uint8_t *heap= malloc(heap_size); 
    mm_init(heap, heap_size);
    if (mm_init(heap, heap_size) != 0) {
    printf("mm_init failed\n");
    return 1;
    }
    
    

    void *ptr1 = mm_malloc(1);
    void *ptr2 = mm_malloc(41);
    void *ptr3 = mm_malloc(100);
    
    printf("ptr1: %p - mod 40 = %zu\n", ptr1, (size_t)ptr1 % 40);
    printf("ptr2: %p - mod 40 = %zu\n", ptr2, (size_t)ptr2 % 40);
    printf("ptr3: %p - mod 40 = %zu\n", ptr3, (size_t)ptr3 % 40);

   

    return 0;
}   