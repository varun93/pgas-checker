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



class DefaultHandlers {
   public:
   	static void handleMemoryAllocations(int handler, const CallEvent &Call, CheckerContext &C);
	static void handleBarriers(int handler, const CallEvent &Call, CheckerContext &C);
	static void handleNonBlockingWrites(int hanndler, const CallEvent &Call, CheckerContext &C);
	static void handleBlockingWrites(int handler, const CallEvent &Call, CheckerContext &C);
	static void handleReads(int handler, const CallEvent &Call, CheckerContext &C);
	static void handleMemoryDeallocations(int handler, const CallEvent &Call, CheckerContext &C);
};
