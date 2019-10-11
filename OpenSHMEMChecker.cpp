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


  // defining checker specific constants; in future maybe move it to a different file
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

  // malloc null checks
  // unitialized get 
  // defining an anynomous namespace
  namespace {


  // this is a custom data structure 
  // the user is free to define custom data structures as long as they overload the == operator and override Profile method
  // Don't ask me why so!! 
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

  // I know this is a bad name; as you might have guessed ripped from an example checker and too lazy to change it later!
  class MainCallChecker : public Checker <check::PostCall, check::PreCall> {
    mutable std::unique_ptr<BugType> BT;
    
    // define the event listeners; in our case pre and post call
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

    // this is very ugly, try to make this generic, one possibility is to have some find of a filter functionality
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

      // remove the variable from the freed list if allocated again
      if(State->contains<FreedVariables>(symmetricVariable)){
        State = State->remove<FreedVariables>(symmetricVariable);
      } 

      C.addTransition(State);
    }

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

        // remove the unintialized variables
        if(State->contains<UnintializedVariables>(destVariable)){
          State = State->remove<UnintializedVariables>(destVariable);
        }   

        // now mark the variable as unsynchronized on a *_put operation
        if (SS && SS->isSynchronized()) {
            State = State->set<CheckerState>(destVariable, RefState::getUnsynchronized());
         }

         C.addTransition(State);
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

    if (!(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_GET) ||
         Call.isGlobalCFunction(OpenShmemConstants::SHMEM_PUT)))
      return;

    // remove the harcoding of variable index
    SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
    
    if(!symmetricVariable)
      return;

    ProgramStateRef State = C.getState();

    // complain if an access it made to the freed variables 
    if(State->contains<FreedVariables>(symmetricVariable)){
      // TODOS: replace couts with bug reports 
      std::cout << OpenShmemErrorMessages::ACCESS_FREED_VARIABLE;
      return;
    }
    
    const RefState *SS = State->get<CheckerState>(symmetricVariable);

    if (!SS) {
      // TODOS: replace couts with bug reports
      std::cout << OpenShmemErrorMessages::VARIABLE_NOT_SYMMETRIC;
      return;
   }

   if(Call.isGlobalCFunction(OpenShmemConstants::SHMEM_GET)){

       if(State->contains<UnintializedVariables>(symmetricVariable)){
        // TODOS: replace couts with bug reports 
        std::cout << OpenShmemErrorMessages::ACCESS_UNINTIALIZED_VARIABLE;
        return;
       }  

       // if the user is trying to access an unintialized bit of memory
       if (SS && SS->isUnSynchronized()) {
      	std::cout << OpenShmemErrorMessages::UNSYNCHRONIZED_ACCESS;
        return;
       }
    }
   
  }


  void ento::registerMainCallChecker(CheckerManager &mgr) {
    mgr.registerChecker<MainCallChecker>();
  }
