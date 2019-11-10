#include <iostream>
#include <utility>
#include <unordered_map>


// todo change the signature
typedef void (*Handler)(void); 
typedef enum routines {
	MEMORY_ALLOC,
	MEMORY_DEALLOC,
	SYNCHRONIZATION,
	WRITE_TO_MEMORY,
	READ_FROM_MEMORY
} Routine;
typedef std::pair<Routine, Handler> Pair;

// the key of the map represents
typedef std::unordered_map<std::string, Pair> routineHandlers;
