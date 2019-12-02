#include "OpenShmemChecker.h"

void OpenShmemChecker::addHandlers() {
	handlers.emplace(OpenShmemConstants::SHMEM_MALLOC, std::make_pair(MEMORY_ALLOC, (Handler)NULL));
	handlers.emplace(OpenShmemConstants::SHMEM_FREE, std::make_pair(MEMORY_DEALLOC, (Handler)NULL));
	handlers.emplace(OpenShmemConstants::SHMEM_BARRIER, std::make_pair(SYNCHRONIZATION, (Handler)NULL));
	handlers.emplace(OpenShmemConstants::SHMEM_PUT, std::make_pair(NON_BLOCKING_WRITE, (Handler)NULL));
	handlers.emplace(OpenShmemConstants::SHMEM_GET, std::make_pair(READ_FROM_MEMORY, (Handler)NULL));
}

void ento::registerOpenShmemChecker(CheckerManager &mgr) {
  mgr.registerChecker<PGASChecker, void (*)()>(OpenShmemChecker::addHandlers);
}


