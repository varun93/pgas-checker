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


// arguments for the handlers; 
// the members would be replaced by actual checker arguments 
typedef struct handlerArgs {
	int handler;
	std::string checkerContext;
	std::string state;
} handlerArgs;

typedef void (*Handler)(handlerArgs); 
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