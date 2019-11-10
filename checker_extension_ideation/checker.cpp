#include "checker.h"

// memory allocation routine
void myAlloc() {
	std::cout << "In my alloc";
} 

// memory deallocation routine
void myDealloc() {
	std::cout << "In my dealloc";
} 

// synchronization routine
void mySynchronization() {
	std::cout << "In my synchronization";
} 

// my write routine
void myWrite() {
	std::cout << "In my write";
} 

// my allocation handler
void myRead() {
	std::cout << "In my read";
} 


int main() {

	routineHandlers handlers;
	// the function on w
    handlers.emplace("my_alloc", std::make_pair(MEMORY_ALLOC, myAlloc));
    handlers.emplace("my_free", std::make_pair(MEMORY_DEALLOC, (Handler)NULL));
    handlers.emplace("my_barrier", std::make_pair(SYNCHRONIZATION, mySynchronization));
    handlers.emplace("my_write", std::make_pair(WRITE_TO_MEMORY, myWrite));
    handlers.emplace("my_read", std::make_pair(READ_FROM_MEMORY, myRead));


    // usage; this is how it would be used in the main checker
    routineHandlers::const_iterator iterator = handlers.find("my_alloc");

    if(iterator != handlers.end()) {
    	std::string routineName = iterator->first;
    	Pair value = iterator->second;
    	Routine routineType = value.first;
    	Handler routineHandler = value.second;
    	if(routineHandler != NULL) {
    		routineHandler();
    	}
    }

    return 0;
}
