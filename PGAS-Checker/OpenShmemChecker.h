 extern routineHandlers handlers;
 
 class OpenShmemConstants {
  public:
    static const std::string SHMEM_MALLOC;
    static const std::string SHMEM_GET;
    static const std::string SHMEM_PUT;
    static const std::string SHMEM_FREE;
    static const std::string SHMEM_BARRIER;
  };


 class OpenShmemChecker {
   public:
    static void addHandlers();
 };

 class OpenShmemErrorMessages {
  public:
    static const std::string VARIABLE_NOT_SYMMETRIC;
    static const std::string UNSYNCHRONIZED_ACCESS;
    static const std::string ACCESS_FREED_VARIABLE;
    static const std::string ACCESS_UNINTIALIZED_VARIABLE;
  };

