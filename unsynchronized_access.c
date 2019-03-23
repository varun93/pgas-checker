#include <stdio.h>
#include <stdlib.h>
#include "open_shmem.h"

// shmem_barrier removed
// catches unsynchrized access  to symmetric variables

int main(int argc, char *argv[])
{
    void *dest = shmem_malloc(10);
    void *source = malloc(10);
    int pe = 2;    

    shmem_put(dest,source,1,pe);	
    
    // notice the barrier has been removed from all_is_well.c
    // boom! access to unsynchronized dest
    shmem_get(dest,source,1,pe);
    
    free(dest);
    free(source);
    return 0;
}


