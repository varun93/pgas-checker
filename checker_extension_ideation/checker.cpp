#include "checker.h"
// include your checker declartion
#include "my_checker.h"

// doesn't work in c++11 standard
// Please refer to the following post
// https://stackoverflow.com/questions/18837857/cant-use-enum-class-as-unordered-map-key 

typedef std::unordered_map<Routine, Handler> defaultHandlers;
defaultHandlers defaults;

// memory allocation routine
void defaultAlloc(handlerArgs args) {
	std::cout << "Default Alloc\n";
} 

// memory deallocation routine
void defaultDealloc(handlerArgs args) {
	std::cout << "Default Dealloc\n";
} 

// synchronization routine
void defaultSynchronization(handlerArgs args) {
	std::cout << "Default Synchronization\n";
} 

// write routines
void defaultBlockingWrite(handlerArgs args) {
	std::cout << "Default Blocking Writes\n";
} 

void defaultNonBlockingWrite(handlerArgs args) {
	std::cout << "Default NonBlocking Writes\n";
} 

// my allocation handler
void defaultRead(handlerArgs args) {
	std::cout << "Default Read\n";
} 

// get the default handler
Handler getDefaultHandler(Routine routineType) {

    defaultHandlers::const_iterator iterator = defaults.find(routineType);

    if(iterator != defaults.end()) {
        return iterator->second; 
    }

    return (Handler)NULL;
}

void event_handler(std::string routineName, handlerArgs args) {

    // usage; this is how it would be used in the main checker
    routineHandlers::const_iterator iterator = handlers.find(routineName);
    Handler routineHandler = NULL;

    if(iterator != handlers.end()) {
    	std::string routineName = iterator->first;
    	Pair value = iterator->second;
    	Routine routineType = value.first;
        // if the event handler exists invoke it; else call the default implementation
        if(value.second) {
            routineHandler = value.second;
        }
        else {
            routineHandler = getDefaultHandler(routineType);
        }
    }

    if(routineHandler != NULL) {
        routineHandler(args);
    }
    else{
        std::cout << "No implementation found for this routine!\n";
    }
        
}

void addDefaultHandlers() {
    defaults.emplace(MEMORY_ALLOC, defaultAlloc);
    defaults.emplace(MEMORY_DEALLOC, defaultDealloc);
    defaults.emplace(SYNCHRONIZATION, defaultSynchronization);
    defaults.emplace(BLOCKING_WRITE, defaultBlockingWrite);
    defaults.emplace(NON_BLOCKING_WRITE, defaultNonBlockingWrite);
    defaults.emplace(READ_FROM_MEMORY, defaultRead);
}

int main() {

    handlerArgs args;

    // add default handlers
    addDefaultHandlers();
    // add 
    addHandlers();
    // since the library doesn't specify any specific actions it invokes the default implementation 
    event_handler("my_free", args);
    // invokes the specified handler
    event_handler("my_alloc", args);

    return 0;
}