#include <stdio.h>
#include <stdlib.h>
#include "open_shmem.h"

int main(int argc, char *argv[])
{
    void *dest = shmem_malloc(10);
    void *source = malloc(10);
    int pe = 2;    

    shmem_put(dest,source,1,pe);	
    
    shmem_barrier_all(); 	   
    
    shmem_get(dest,source,1,pe);
    
    free(dest);
    free(source);
    return 0;
}


