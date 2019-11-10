#include "checker.h"
#include "my_checker.h"

routineHandlers handlers;

// memory allocation routine
void myAlloc() {
	std::cout << "In my alloc\n";
} 

// memory deallocation routine
void myDealloc() {
	std::cout << "In my dealloc\n";
} 

// synchronization routine
void mySynchronization() {
	std::cout << "In my synchronization\n";
} 

// my write routine
void myWrite() {
	std::cout << "In my write\n";
} 

// my allocation handler
void myRead() {
	std::cout << "In my read\n";
} 


void addHandlers() {
    handlers.emplace("my_alloc", std::make_pair(MEMORY_ALLOC, myAlloc));
    handlers.emplace("my_free", std::make_pair(MEMORY_DEALLOC, (Handler)NULL));
    handlers.emplace("my_barrier", std::make_pair(SYNCHRONIZATION, mySynchronization));
    handlers.emplace("my_write", std::make_pair(WRITE_TO_MEMORY, myWrite));
    handlers.emplace("my_read", std::make_pair(READ_FROM_MEMORY, myRead));
}
