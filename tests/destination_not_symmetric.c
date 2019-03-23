#include <stdio.h>
#include <stdlib.h>
#include "open_shmem.h"

// fails if we try to pass an unsymetric variable to the destination

int main(int argc, char *argv[])
{
    void *dest = malloc(10);
    void *source = malloc(10);
    int pe = 2;    

    // boom! the dest is not symmteric our checker catches the error!
    shmem_put(dest,source,1,pe);	
    
    free(dest);
    free(source);
    return 0;
}


