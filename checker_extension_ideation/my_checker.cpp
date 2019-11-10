#include "checker.h"
#include "my_checker.h"

routineHandlers handlers;

// memory allocation routine
void myAlloc(handlerArgs args) {
	std::cout << "In my alloc\n";
} 

// memory deallocation routine
void myDealloc(handlerArgs args) {
	std::cout << "In my dealloc\n";
} 

// synchronization routine
void mySynchronization(handlerArgs args) {
	std::cout << "In my synchronization\n";
} 

// my write routines
void myBlockingWrite(handlerArgs args) {
	std::cout << "In blocking write\n";
} 

void myNonBlockingWrite(handlerArgs args) {
	std::cout << "In non blocking write write\n";
} 

// my allocation handler
void myRead(handlerArgs args) {
	std::cout << "In my read\n";
} 

void addHandlers() {
    handlers.emplace("my_alloc", std::make_pair(MEMORY_ALLOC, myAlloc));
    handlers.emplace("my_free", std::make_pair(MEMORY_DEALLOC, (Handler)NULL));
    handlers.emplace("my_barrier", std::make_pair(SYNCHRONIZATION, mySynchronization));
    handlers.emplace("my_non_blocking_write", std::make_pair(NON_BLOCKING_WRITE, myNonBlockingWrite));
    handlers.emplace("my_blocking_write", std::make_pair(BLOCKING_WRITE, myBlockingWrite));
    handlers.emplace("my_read", std::make_pair(READ_FROM_MEMORY, myRead));
}
