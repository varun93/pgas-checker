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

// defining an anynomous namespace
namespace {

typedef SmallVector<SymbolRef, 2> SymbolVector;

// data structure to hold the program state
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

class OpenSHMEMChecker : public Checker < check::PostCall, check::PreCall > {
  mutable std::unique_ptr<BugType> BT;
 
  public:
    // checks for shmem_malloc and shmem_barrier 
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    // checks for shmem_get and shmem_put
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  };
}
// end of anonymous namespace 

// registring our program state
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, RefState)

// int* source = (int*) shmem_malloc(npes*sizeof(int));
// shmem_put(TYPE *dest, const TYPE *source, size_t nelems, int pe);
// shmem_get(TYPE *dest, const TYPE *source, size_t nelems, int pe);

/* 
  program point called after a function invocation
  we use this to tap into shmem_malloc for tracking the symmetric variables; intially 
  all variables are marked as unsynchronized
  and shmem_barrier for marking all the tracked symmetric variables as synchrnonized
*/ 
void OpenSHMEMChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;
  
  // return if its not  shmem_malloc or shmem_barrier_all
  if (!(Call.isGlobalCFunction("shmem_malloc") || Call.isGlobalCFunction("shmem_barrier_all")))
    return;

  // get hold of the state
  ProgramStateRef State = C.getState();
	
  if(Call.isGlobalCFunction("shmem_malloc")){
  	// Get the symbolic value corresponding to symmetric variable
  	SymbolRef symetricVariable = Call.getReturnValue().getAsSymbol();
  	
  	if (!symetricVariable)
    	return;
  
    // mark it as unsynchronized
    State = State->set<StreamMap>(symetricVariable, RefState::getUnsynchronized());
    // the the new state to the transition graph
    C.addTransition(State); 	
  }

  else if(Call.isGlobalCFunction("shmem_barrier_all")){ 

      // iterate through all the track variables so far variables
      // set each of the variables to synchronized
      ProgramStateRef State = C.getState();
      StreamMapTy trackedVariables = State->get<StreamMap>();
      for (StreamMapTy::iterator I = trackedVariables.begin(),
                              E = trackedVariables.end(); I != E; ++I) {
        SymbolRef Sym = I->first;
        const RefState *SS = State->get<StreamMap>(Sym);
        // mark only unsynchronized as synchronized
        if (SS && SS->isUnSynchronized()) {
    	    State = State->set<StreamMap>(Sym, RefState::getSynchronized());
            // the the new state to the transition graph
            C.addTransition(State);
	}
      }
  }
}

/*
  program point called before a function invocation
  used for tapping into shmem_put; to check if the destination is indeed a symmetric variable 
  and for shmem_get if the programmer is trying to access an unsychronized variable  
*/
void OpenSHMEMChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  // return if it is not shmem_get or shmem_put
  if (!(Call.isGlobalCFunction("shmem_get") || Call.isGlobalCFunction("shmem_put")))
    return;

  // get hold of the first argument which is the destination in our case
  // shmem_(put|get)(TYPE *dest, ...params)
  SymbolRef symetricVariable = Call.getArgSVal(0).getAsSymbol();

  if(!symetricVariable)
    return;
  
  ProgramStateRef State = C.getState();
  const RefState *SS = State->get<StreamMap>(symetricVariable);

  // check if the destination variable is indeed a symmetric variable
  if (!SS) {
    // create a sink node and report bug
    std::cout << "Destination is not a symmetric variable\n";
    return;
  }
  
  // check if we are trying to get unsynchronized access to a variable
  if(Call.isGlobalCFunction("shmem_get")){
     if (SS && SS->isUnSynchronized()) {
    	std::cout << "unsynchronized access to variable\n";
        // generate a sink node
        return;
     }
  }
 
}

// finally register your checker!
void ento::registerOpenSHMEMChecker(CheckerManager &mgr) {
  mgr.registerChecker<OpenSHMEMChecker>();
}


