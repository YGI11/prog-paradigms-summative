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
    
    

    void *ptr1 = mm_malloc(100);
    printf("ptr1: %p - aligned: %d\n", ptr1, ((size_t)ptr1 % 40) == 0);

   

    return 0;
}   