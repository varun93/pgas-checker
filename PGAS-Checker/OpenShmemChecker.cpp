#include "PGASChecker.h"
#include "OpenShmemChecker.h"

routineHandlers handlers;


const std::string OpenShmemConstants::SHMEM_MALLOC = "shmem_malloc";
const std::string OpenShmemConstants::SHMEM_GET = "shmem_get";
const std::string OpenShmemConstants::SHMEM_PUT = "shmem_put";
const std::string OpenShmemConstants::SHMEM_FREE = "shmem_free";
const std::string OpenShmemConstants::SHMEM_BARRIER = "shmem_barrier_all";


const std::string OpenShmemErrorMessages::VARIABLE_NOT_SYMMETRIC = "Not a symmetric variable";
const std::string OpenShmemErrorMessages::UNSYNCHRONIZED_ACCESS = "Unsynchronized access to variable";
const std::string OpenShmemErrorMessages::ACCESS_FREED_VARIABLE = "Trying to access a freed variable";
const std::string OpenShmemErrorMessages::ACCESS_UNINTIALIZED_VARIABLE = "Trying to access a unitialized variable";



void OpenShmemChecker::addHandlers() {
    handlers.emplace(OpenShmemConstants::SHMEM_MALLOC, std::make_pair(MEMORY_ALLOC, (Handler)NULL));
    handlers.emplace(OpenShmemConstants::SHMEM_FREE, std::make_pair(MEMORY_DEALLOC, (Handler)NULL));
    handlers.emplace(OpenShmemConstants::SHMEM_BARRIER, std::make_pair(SYNCHRONIZATION, (Handler)NULL));
    handlers.emplace(OpenShmemConstants::SHMEM_PUT, std::make_pair(NON_BLOCKING_WRITE, (Handler)NULL));
    handlers.emplace(OpenShmemConstants::SHMEM_GET, std::make_pair(READ_FROM_MEMORY, (Handler)NULL));
}


