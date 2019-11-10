#include "checker.h"
// include your checker declartion
#include "my_checker.h"

// doesn't work in c++11 standard
// Please refer to the following post
// https://stackoverflow.com/questions/18837857/cant-use-enum-class-as-unordered-map-key 

typedef std::unordered_map<Routine, Handler> defaultHandlers;
defaultHandlers defaults;

// memory allocation routine
void defaultAlloc() {
	std::cout << "Default Alloc\n";
} 

// memory deallocation routine
void defaultDealloc() {
	std::cout << "Default Dealloc\n";
} 

// synchronization routine
void defaultSynchronization() {
	std::cout << "Default Synchronization\n";
} 

// my write routine
void defaultWrite() {
	std::cout << "Default Write\n";
} 

// my allocation handler
void defaultRead() {
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

void event_handler(std::string routineName) {

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
        routineHandler();
    }
    else{
        std::cout << "No implementation found for this routine!\n";
    }
        
}

void addDefaultHandlers() {
    defaults.emplace(MEMORY_ALLOC, defaultAlloc);
    defaults.emplace(MEMORY_DEALLOC, defaultDealloc);
    defaults.emplace(SYNCHRONIZATION, defaultSynchronization);
    defaults.emplace(WRITE_TO_MEMORY, defaultWrite);
    defaults.emplace(READ_FROM_MEMORY, defaultRead);
}

int main() {

    // add default handlers
    addDefaultHandlers();
    // add 
    addHandlers();
    // since the library doesn't specify any specific actions it invokes the default implementation 
    event_handler("my_free");
    // invokes the specified handler
    event_handler("my_alloc");

    return 0;
}