  // TODO: remove uncessary imports
  
  #include "PGASChecker.h"
  #include "OpenShmemChecker.h"
  
  using namespace clang;
  using namespace ento;

  enum HANDLERS {PRE_CALL = 0, POST_CALL = 1}; 
  typedef std::unordered_map<int, Handler> defaultHandlers;
  defaultHandlers defaults;
  routineHandlers handlers;

  namespace {

    // this is a custom data structure 
    // the user is free to define custom data structures as long as they overload the == operator and override Profile method
    struct RefState {
      private:
        enum Kind { Synchronized, Unsynchronized } K;
        RefState(Kind InK) : K(InK) { }

      public:
        bool isSynchronized() const { return K == Synchronized; }
        bool isUnSynchronized() const { return K == Unsynchronized; }

        static RefState getSynchronized() { return RefState(Synchronized); }
        static RefState getUnsynchronized() { return RefState(Unsynchronized); }

        // overloading of == comparison operator 
        bool operator==(const RefState &X) const {
          return K == X.K;
        }
        void Profile(llvm::FoldingSetNodeID &ID) const {
          ID.AddInteger(K);
        }
    };

  class PGASChecker : public Checker <check::PostCall, check::PreCall> {
    mutable std::unique_ptr<BugType> BT;
    
    private:
      void eventHandler(int handler, std::string &routineName, 
                      const CallEvent &Call, CheckerContext &C) const;
      void addDefaultHandlers();
      Handler getDefaultHandler(Routine routineType) const;

    // define the event listeners; in our case pre and post call
    public:
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

      void construct() { 
        OpenShmemChecker::addHandlers();
        // add default handlers here
        addDefaultHandlers();
      } 

    };
  }
  

  // map to hold the state of the variable; synchronized or unsynchronized
  REGISTER_MAP_WITH_PROGRAMSTATE(CheckerState, SymbolRef, RefState)
  // set of unitilized variables
  REGISTER_SET_WITH_PROGRAMSTATE(UnintializedVariables, SymbolRef)
  // set of freed variables
  REGISTER_SET_WITH_PROGRAMSTATE(FreedVariables, SymbolRef)

  // int* source = (int*) shmem_malloc(npes*sizeof(int));
  // shmem_put(TYPE *dest, const TYPE *source, size_t nelems, int pe);
  // shmem_get(TYPE *dest, const TYPE *source, size_t nelems, int pe);

  // TODO
  bool checkIfSymmetric(SymbolRef variable, ProgramStateRef State) {
    return false;
  }

  // TODO
  bool checkIfFreed(SymbolRef variable, ProgramStateRef State) {
    return false;
  }

  void PGASChecker::addDefaultHandlers() {
    defaults.emplace(MEMORY_ALLOC, handleMemoryAllocations);
    defaults.emplace(MEMORY_DEALLOC, handleMemoryDeallocations);
    defaults.emplace(SYNCHRONIZATION, handleBarriers);
    defaults.emplace(NON_BLOCKING_WRITE, handleNonBlockingWrites);
    defaults.emplace(READ_FROM_MEMORY, handleReads);
}
  
  Handler PGASChecker::getDefaultHandler(Routine routineType) const {

      defaultHandlers::const_iterator iterator = defaults.find(routineType);

      if(iterator != defaults.end()) {
          return iterator->second; 
      }

      return (Handler)NULL;
  }

  void PGASChecker::eventHandler(int handler, std::string &routineName, 
                      const CallEvent &Call, CheckerContext &C) const {

      Handler routineHandler = NULL;
      routineHandlers::const_iterator iterator = handlers.find(routineName);
      
      if(iterator != handlers.end()) {

        Pair value = iterator->second;
        Routine routineType = value.first;
        
        // if the event handler exists invoke it; else call the default implementation
        if(value.second) {
          routineHandler = value.second ;
        }
        else {
          routineHandler = getDefaultHandler(routineType);
        }

        if(routineHandler != NULL) {
            routineHandler(handler, Call, C);
        }
        else{
            std::cout << "No implementation found for this routine!\n";
        }

      }
  
  }
 
  void PGASChecker::checkPostCall(const CallEvent &Call,
                                          CheckerContext &C) const {
    const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

    if (!FD)
      return;

    // get the invoked routine name
    std::string routineName = FD->getNameInfo().getAsString();

    eventHandler(POST_CALL, routineName, Call, C);
    
  }

  void PGASChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {

    const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

    if (!FD)
      return;

    // TODO: Temp fix! place these checks into seperate functions
    if(Call.getNumArgs() < 1)
      return;

    // TODO: remove the harcoding of variable index; 
    SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
    
    if(!symmetricVariable)
      return;

    // TODO: extract this out of the function
    ProgramStateRef State = C.getState();

    const RefState *SS = State->get<CheckerState>(symmetricVariable);

    if (!SS) {
      // TODOS: replace couts with bug reports
      std::cout << OpenShmemErrorMessages::VARIABLE_NOT_SYMMETRIC;
      return;
    }

    // complain if an access it made to the freed variables 
    if(State->contains<FreedVariables>(symmetricVariable)){
      // TODOS: replace couts with bug reports 
      std::cout << OpenShmemErrorMessages::ACCESS_FREED_VARIABLE;
      return;
    }
  
    // get the name of the invoked routine
    std::string routineName = FD->getNameInfo().getAsString();

    eventHandler(PRE_CALL, routineName, Call, C);
   
  }

  void ento::registerPGASChecker(CheckerManager &mgr) {
    mgr.registerChecker<PGASChecker>();
  }


