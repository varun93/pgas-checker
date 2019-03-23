// dummy declarations
void shmem_put(void *dest, void *source, int nelems, int pe);
void shmem_get(void *dest, void *source, int nelems, int pe);
void *shmem_malloc(int size);
void *shmem_barrier_all();

