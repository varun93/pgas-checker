#ifndef __PGAS_CHECK
#define __PGAS_CHECK	

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <clang/StaticAnalyzer/Core/CheckerRegistry.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include <iostream>
#include <utility>
#include <unordered_map>

using namespace clang;
using namespace ento;


// arguments for the handlers; 
// the members would be replaced by actual checker arguments 
typedef void (*Handler)(int handler, const CallEvent &Call, CheckerContext &C); 
typedef enum routines {
	MEMORY_ALLOC,
	MEMORY_DEALLOC,
	SYNCHRONIZATION,
	BLOCKING_WRITE,
	NON_BLOCKING_WRITE,
	READ_FROM_MEMORY
} Routine;
typedef std::pair<Routine, Handler> Pair;
// the key of the map is the routine name
typedef std::unordered_map<std::string, Pair> routineHandlers;


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


// // map to hold the state of the variable; synchronized or unsynchronized
REGISTER_MAP_WITH_PROGRAMSTATE(CheckerState, SymbolRef, RefState)
// // set of unitilized variables
REGISTER_SET_WITH_PROGRAMSTATE(UnintializedVariables, SymbolRef)
// // set of freed variables
REGISTER_SET_WITH_PROGRAMSTATE(FreedVariables, SymbolRef)

enum HANDLERS {PRE_CALL = 0, POST_CALL = 1}; 

namespace ErrorMessages {
  const std::string VARIABLE_NOT_SYMMETRIC = "Not a symmetric variable";
  const std::string UNSYNCHRONIZED_ACCESS = "Unsynchronized access to variable";
  const std::string ACCESS_FREED_VARIABLE = "Trying to access a freed variable";
  const std::string ACCESS_UNINTIALIZED_VARIABLE = "Trying to access a unitialized variable";
}

namespace DefaultHandlers {
   	void handleMemoryAllocations(int handler, const CallEvent &Call, CheckerContext &C);
	void handleBarriers(int handler, const CallEvent &Call, CheckerContext &C);
	void handleNonBlockingWrites(int hanndler, const CallEvent &Call, CheckerContext &C);
	void handleBlockingWrites(int handler, const CallEvent &Call, CheckerContext &C);
	void handleReads(int handler, const CallEvent &Call, CheckerContext &C);
	void handleMemoryDeallocations(int handler, const CallEvent &Call, CheckerContext &C);
}


class PGASChecker : public Checker <check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

  private:
    void eventHandler(int handler, std::string &routineName, 
                    const CallEvent &Call, CheckerContext &C) const;
    void addDefaultHandlers();
    Handler getDefaultHandler(Routine routineType) const;

  // event listeners; in our case pre and post call
  public:
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
    PGASChecker(routineHandlers (*addHandlers)());

};


#endif