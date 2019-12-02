#ifndef __OPENSHMEM_CHECK
#define __OPENSHMEM_CHECK

#include "PGASChecker.h"

namespace OpenShmemConstants {
  const std::string SHMEM_MALLOC = "shmem_malloc";
  const std::string SHMEM_GET = "shmem_get";
  const std::string SHMEM_PUT = "shmem_put";
  const std::string SHMEM_FREE = "shmem_free";
  const std::string SHMEM_BARRIER = "shmem_barrier_all";
}

#endif