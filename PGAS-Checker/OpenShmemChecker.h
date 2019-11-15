  class OpenShmemConstants {
  public:
    static const std::string SHMEM_MALLOC;
    static const std::string SHMEM_GET;
    static const std::string SHMEM_PUT;
    static const std::string SHMEM_FREE;
    static const std::string SHMEM_BARRIER;
  };


 class OpenShmemErrorMessages {
  public:
    static const std::string VARIABLE_NOT_SYMMETRIC;
    static const std::string UNSYNCHRONIZED_ACCESS;
    static const std::string ACCESS_FREED_VARIABLE;
    static const std::string ACCESS_UNINTIALIZED_VARIABLE;
  };


  // constants
  const std::string OpenShmemConstants::SHMEM_MALLOC = "shmem_malloc";
  const std::string OpenShmemConstants::SHMEM_GET = "shmem_get";
  const std::string OpenShmemConstants::SHMEM_PUT = "shmem_put";
  const std::string OpenShmemConstants::SHMEM_FREE = "shmem_free";
  const std::string OpenShmemConstants::SHMEM_BARRIER = "shmem_barrier_all";


  // error messages
  const std::string OpenShmemErrorMessages::VARIABLE_NOT_SYMMETRIC = "Not a symmetric variable";
  const std::string OpenShmemErrorMessages::UNSYNCHRONIZED_ACCESS = "Unsynchronized access to variable";
  const std::string OpenShmemErrorMessages::ACCESS_FREED_VARIABLE = "Trying to access a freed variable";
  const std::string OpenShmemErrorMessages::ACCESS_UNINTIALIZED_VARIABLE = "Trying to access a unitialized variable";
