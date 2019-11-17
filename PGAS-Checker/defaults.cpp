 #include "PGASChecker.h"


// remove from the untialized list
void removeFromUnitializedList(ProgramStateRef State, SymbolRef variable) {

  if(State->contains<UnintializedVariables>(variable)){
      State = State->remove<UnintializedVariables>(variable);
  }   
}

// mark as unsynchronized
void markAsUnsynchronized(ProgramStateRef State, SymbolRef variable) {

	const RefState *SS = State->get<CheckerState>(variable);

	// now mark the variable as unsynchronized on a *_put operation
	if (SS && SS->isSynchronized()) {
	    State = State->set<CheckerState>(variable, RefState::getUnsynchronized());
	 }
}


void handleMemoryAllocations(int handler, const CallEvent &Call, CheckerContext &C) {

	int handler = args.handler;
	CheckerContext C = args.C;
	ProgramStateRef State = C.getState();
	SymbolRef allocatedVariable = symmetricVariable = Call.getReturnValue().getAsSymbol();
	// Get the symbolic value corresponding to the allocated memory
	if (!allocatedVariable)
	  return;
	   
	switch(handler) {

	  case PRE_CALL :
	  break;

	  case POST_CALL : 
	    
	    // add unitilized variables to unitilized list
	    State = State->add<UnintializedVariables>(allocatedVariable);
	    // mark is synchronized by default
	    State = State->set<CheckerState>(allocatedVariable, RefState::getSynchronized());

	    // remove the variable from the freed list if allocated again
	    if(State->contains<FreedVariables>(allocatedVariable)){
	      State = State->remove<FreedVariables>(allocatedVariable);
	    } 

	    break;

	}

	C.addTransition(State);

}


void handleBarriers(int handler, const CallEvent &Call, CheckerContext &C) {

  ProgramStateRef State = C.getState();
  CheckerStateTy trackedVariables = State->get<CheckerState>();

  	switch(handler) {
      case PRE_CALL : break;
      case POST_CALL : 
          // iterate through all the track variables so far variables
          // set each of the values to sy/nchronized
          for (CheckerStateTy::iterator I = trackedVariables.begin(),
                                  E = trackedVariables.end(); I != E; ++I) {
            SymbolRef symmetricVariable = I->first;
            const RefState *SS = State->get<CheckerState>(symmetricVariable);
            // mark all symmetric variables as synchronized
            if (SS && SS->isUnSynchronized()) {
              State = State->set<CheckerState>(symmetricVariable, RefState::getSynchronized());
              C.addTransition(State);
           }
          }
        break;
  }
}

void handleNonBlockingWrites(int hanndler, const CallEvent &Call, CheckerContext &C) {

	ProgramStateRef State = C.getState();
	SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();


	switch(handler) {

	  case PRE_CALL : break;

	  case POST_CALL : 
	    // remove the unintialized variables
	    removeFromUnitializedList(State, destVariable);
	    break;
	}

	C.addTransition(State);

}

void handleBlockingWrites(int handler, const CallEvent &Call, CheckerContext &C) {

	ProgramStateRef State = C.getState();
	SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();

	switch(handler) {

	  case PRE_CALL : break;

	  case POST_CALL : 
	     
	    removeFromUnitializedList(State, destVariable);
	    // mark as unsynchronized
	    markAsUnsynchronized(State, destVariable);

	    break;
	}


	C.addTransition(State);

}

void handleReads(int handler, const CallEvent &Call, CheckerContext &C) {

	ProgramStateRef State = C.getState();
	SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
	const RefState *SS = State->get<CheckerState>(symmetricVariable);

	switch(handler) {

	  case PRE_CALL : 

	    if(State->contains<UnintializedVariables>(symmetricVariable)){
	      // TODOS: replace couts with bug reports 
	      std::cout << OpenShmemErrorMessages::ACCESS_UNINTIALIZED_VARIABLE;
	      return;
	   }  

	   // if the user is trying to access an unintialized bit of memory
	   if (SS && SS->isUnSynchronized()) {
	    std::cout << OpenShmemErrorMessages::UNSYNCHRONIZED_ACCESS;
	    return;
	   }

	  break;

	  case POST_CALL :  break;

	}

} 

void handleMemoryDeallocations(int handler, const CallEvent &Call, CheckerContext &C) {

  	ProgramStateRef State = C.getState();
  	SymbolRef freedVariable = Call.getArgSVal(0).getAsSymbol();

  	switch(handler) {
    	case PRE_CALL : 
     		break;
    	case POST_CALL : 
	      // add it to the freed variable set; since it is adding it multiple times should have the same effect
	      State = State->add<FreedVariables>(freedVariable);
	      
	      // stop tracking the variables which have been tracked
	      const RefState *SS = State->get<CheckerState>(freedVariable);
	      if(SS){  
	        // remove from the map
	        State = State->remove<CheckerState>(freedVariable);
	      }
	    break;
   }
 
   C.addTransition(State);
}
