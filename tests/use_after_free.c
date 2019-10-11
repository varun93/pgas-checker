#include <stdio.h>
#include <stdlib.h>
#include "open_shmem.h"

// fails if we try to pass an unsymetric variable to the destination

int main(int argc, char *argv[])
{
    void *dest = shmem_malloc(10);
    void *source = shmem_malloc(10);
    int pe = 2;    

    shmem_put(dest, source, 1, pe);	
    
    // free list
    shem_free(dest);
    
    // Oops! Use after free complain
    shmem_get(dest, source, 1, pe);
    
    return 0;
}
