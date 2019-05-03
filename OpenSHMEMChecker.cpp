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
    // needed to check if the value bound to a variable has a storage class of static 
    void checkBind(SVal location, SVal val, const Stmt *S, CheckerContext &C) const;
  };
}
// end of anonymous namespace 

// registring our program state
REGISTER_MAP_WITH_PROGRAMSTATE(TrackVar, SymbolRef, RefState)

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
    State = State->set<TrackVar>(symetricVariable, RefState::getUnsynchronized());
    // the the new state to the transition graph
    C.addTransition(State); 	
  }

  else if(Call.isGlobalCFunction("shmem_barrier_all")){ 

      // iterate through all the track variables so far variables
      // set each of the variables to synchronized
      ProgramStateRef State = C.getState();
      TrackVarTy trackedVariables = State->get<TrackVar>();
      for (TrackVarTy::iterator I = trackedVariables.begin(),
                              E = trackedVariables.end(); I != E; ++I) {
        SymbolRef Sym = I->first;
        const RefState *SS = State->get<TrackVar>(Sym);
        // mark only unsynchronized as synchronized
        if (SS && SS->isUnSynchronized()) {
    	    State = State->set<TrackVar>(Sym, RefState::getSynchronized());
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
  
  SymbolRef symetricVariable = Call.getArgSVal(0).getAsSymbol();

  if(!symetricVariable)
    return;
  
  ProgramStateRef State = C.getState();
  const RefState *SS = State->get<TrackVar>(symetricVariable);
  if (SS && SS->isUnSynchronized()) {
    	std::cout << "unsynchronized access to variable\n";
        return;
  }

  /* check if the argument is a static variable; 
        | |-ImplicitCastExpr 0x5564718 <col:15, col:16> 'void *' <BitCast>
        | | `-UnaryOperator 0x55645c8 <col:15, col:16> 'int *' prefix '&' cannot overflow
        | |   `-DeclRefExpr 0x55645a0 <col:16> 'int' lvalue Var 0x55644e0 'dest' 'int'
    */
	if (const clang::ImplicitCastExpr *implicitCastExpr = clang::dyn_cast<const clang::ImplicitCastExpr>(Call.getArgExpr(0))) {
         if(const clang::UnaryOperator *unaryOperator = clang::dyn_cast<clang::UnaryOperator>(implicitCastExpr->getSubExpr())){
          if(const clang::DeclRefExpr *DRE = clang::dyn_cast<clang::DeclRefExpr>(unaryOperator->getSubExpr())){
                if(const clang::VarDecl *VD = clang::dyn_cast<clang::VarDecl>(DRE->getDecl())){
                    if(VD->isStaticLocal()){
                        ///std::cout << "Is a static variable " << VD->getQualifiedNameAsString() << "\n";
                       	// currently doesn't support checking for synchronized access to static variable; so return for the time being
			        return;
			    }
             }
          }
        }
     }
   // check if the destination variable is indeed a symmetric variable
   if (!SS) {
    // create a sink node and report bug
    std::cout << "Destination is not a symmetric variable\n";
    return;
  }

}

void OpenSHMEMChecker::checkBind(SVal location, SVal val,
                                           const Stmt *StoreE,
                                           CheckerContext &C) const {
 if (const DeclStmt *DS = dyn_cast<DeclStmt>(StoreE)) {
      const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if(VD->isStaticLocal()){
	VD->dump();
	const Expr *e = VD->getInit(); 
	const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(e);
	//SValBuilder &svalBuilder = C.getSValBuilder();
	//SVal V = svalBuilder.makeIntVal(IL);
	//SymbolRef symetricVariable  = V.getAsSymbol();
	//QualType ty = VD->getType();
        //SVal V = svalBuilder.makeIntVal(0, ty);	
        //SymbolRef symetricVariable  = V.getAsSymbol();

	 ProgramStateRef State = C.getState();
         SymbolRef symetricVariable = State->getSValAsScalarOrLoc(e, C.getLocationContext()).getAsLocSymbol();

	if(!symetricVariable)
	 return;
 
	std::cout << IL->getValue().signedRoundToDouble() << "\n"; 
	std::cout << "A is static variable\n";
        State = State->set<TrackVar>(symetricVariable, RefState::getUnsynchronized());
    	C.addTransition(State);
       }
   }

}

// finally register your checker!
void ento::registerOpenSHMEMChecker(CheckerManager &mgr) {
  mgr.registerChecker<OpenSHMEMChecker>();
}

