  // many unnecessary imports to be removed later
  #include "ClangSACheckers.h"
  #include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
  #include "clang/StaticAnalyzer/Core/Checker.h"
  #include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
  #include <clang/StaticAnalyzer/Core/CheckerRegistry.h>
  #include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
  #include "clang/StaticAnalyzer/Core/CheckerManager.h"
  #include <iostream>
  #include <utility>

  using namespace clang;
  using namespace ento;


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

  // malloc null checks
  // unitialized get 
  // defining an anynomous namespace
  namespace {


  struct RefState {
    private:
      enum Kind { Synchronized, Unsynchronized } K;
      RefState(Kind InK) : K(InK) { }

    public:
      bool isSynchronized() const { return K == Synchronized; }
      bool isUnSynchronized() const { return K == Unsynchronized; }

      static RefState getSynchronized() { return RefState(Synchronized); }
      static RefState getUnsynchronized() { return RefState(Unsynchronized); }

      bool operator==(const RefState &X) const {
        return K == X.K;
      }
      void Profile(llvm::FoldingSetNodeID &ID) const {
        ID.AddInteger(K);
      }
  };

  class MainCallChecker : public Checker <check::PostCall, check::PreCall> {
    mutable std::unique_ptr<BugType> BT;
   
    public:
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
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


  /*
    - Memory Allocation Routines = {"shmem_malloc", "...."}
    - Synchronization Routines  = {"...."}
  */
  void MainCallChecker::checkPostCall(const CallEvent &Call,
                                          CheckerContext &C) const {
    if (!Call.isGlobalCFunction())
      return;

    // check for only certain routines:
    // TODO: make this generic
    if (!(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_MALLOC) || 
          Call.isGlobalCFunction(OpenShmemConstants::SHMEM_BARRIER) ||
          Call.isGlobalCFunction(OpenShmemConstants::SHMEM_PUT) || 
          Call.isGlobalCFunction(OpenShmemConstants::SHMEM_FREE)
         )){
        return;
    }
      

    ProgramStateRef State = C.getState();
  	
    // check if a shmem memory allocation routine
    // {"shem_malloc", "shmem_alloc", ...etc}
    // if(Call is a memory allocation routine) { record it as a symmetric variable }
    if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_MALLOC)){
    	// Get the symbolic value corresponding to the file handle.
    	SymbolRef symmetricVariable = Call.getReturnValue().getAsSymbol();
    	
    	if (!symmetricVariable)
      	return;
      
      // add unitilized variables to unitilized list
      State = State->add<UnintializedVariables>(symmetricVariable);
      // mark is synchronized by default
      State = State->set<CheckerState>(symmetricVariable, RefState::getSynchronized());
      C.addTransition(State); 	
    }

    // if it  is
    else if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_BARRIER)){ 

        // iterate through all the track variables so far variables
        // set each of the values to sy/nchronized
        ProgramStateRef State = C.getState();
        CheckerStateTy trackedVariables = State->get<CheckerState>();
        for (CheckerStateTy::iterator I = trackedVariables.begin(),
                                E = trackedVariables.end(); I != E; ++I) {
          SymbolRef symmetricVariable = I->first;
          const RefState *SS = State->get<CheckerState>(symmetricVariable);
          // mark all symmetric variables as synchronized
          if (SS && SS->isUnSynchronized()) {
      	    State = State->set<CheckerState>(symmetricVariable, RefState::getSynchronized());
            C.addTransition(State);
  	     }
      }
    }
    // mark the variable as unsynchronized only on a put call
    else if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_PUT)){
        SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();
        const RefState *SS = State->get<CheckerState>(destVariable);
        if (SS && SS->isSynchronized()) {
            State = State->set<CheckerState>(destVariable, RefState::getUnsynchronized());
            C.addTransition(State);
         }
    }
    // add freed variables to a free list
    else if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_FREE)) {
       SymbolRef freedVariable = Call.getArgSVal(0).getAsSymbol();
       State = State->add<FreedVariables>(freedVariable);
       C.addTransition(State);
    }

  }

  //static int a = 0;
  //              |
  //shmem_get(a,......); void * 
  void MainCallChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {
    if (!Call.isGlobalCFunction())
      return;

    if (!(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_GET) || Call.isGlobalCFunction(OpenShmemConstants::SHMEM_PUT)))
      return;

    // remove the harcoding 
    SymbolRef symetricVariable = Call.getArgSVal(0).getAsSymbol();
    
    if(!symetricVariable)
      return;
    
    ProgramStateRef State = C.getState();
    const RefState *SS = State->get<CheckerState>(symetricVariable);

    if (!SS) {
      std::cout << OpenShmemErrorMessages::VARIABLE_NOT_SYMMETRIC;
      return;
   }

   if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_GET)){
       if (SS && SS->isUnSynchronized()) {
      	std::cout << OpenShmemErrorMessages::UNSYNCHRONIZED_ACCESS;
          // generate a sink node
        return;
       }
    }
   
  }


  void ento::registerMainCallChecker(CheckerManager &mgr) {
    mgr.registerChecker<MainCallChecker>();
  }


