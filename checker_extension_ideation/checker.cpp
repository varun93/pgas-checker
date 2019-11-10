#include "checker.h"
// include your checker declartion
#include "my_checker.h"


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


void event_handler(std::string routineName) {

    // usage; this is how it would be used in the main checker
    routineHandlers::const_iterator iterator = handlers.find(routineName);

    if(iterator != handlers.end()) {
    	std::string routineName = iterator->first;
    	Pair value = iterator->second;
    	Routine routineType = value.first;
    	Handler routineHandler = value.second;
    	// if the event handler exists invoke it; else call the default implementations
    	if(routineHandler != NULL) {
    		routineHandler();
    	}
    	else{
    		switch(routineType) {
    			case MEMORY_ALLOC: 
	    			defaultAlloc();
	    			break;
	    		case MEMORY_DEALLOC: 
		    		defaultDealloc();
		    		break;
		    	case SYNCHRONIZATION:
		    		defaultSynchronization();
		    		break;
		    	case WRITE_TO_MEMORY:
			    	defaultWrite();
			    	break;
			    case READ_FROM_MEMORY:
			    	defaultRead();
			    	break;
    		}
    	}
    }
}

int main() {
    addHandlers();
    // since the library doesn't specify any specific actions it invokes the default implementation 
    event_handler("my_free");
    // invokes the specified handler
    event_handler("my_alloc");

    return 0;
}