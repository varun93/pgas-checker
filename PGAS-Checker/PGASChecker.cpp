#include "PGASChecker.h"

typedef std::unordered_map<int, Handler> defaultHandlers;
defaultHandlers defaults;
routineHandlers handlers;

// remove from the untialized list
void removeFromUnitializedList(ProgramStateRef State, SymbolRef variable) {
    if (State->contains<UnintializedVariables>(variable)) {
      State = State->remove<UnintializedVariables>(variable);
    }
}

// add to the free list
void addToFreeList(ProgramStateRef State, SymbolRef variable) {
    State = State->add<FreedVariables>(variable);
}


void removeFromState(ProgramStateRef State, SymbolRef variable) {
  const RefState *SS = State->get<CheckerState>(variable);
  
  if(SS){  
    State = State->remove<CheckerState>(variable);
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


void DefaultHandlers::handleMemoryAllocations(int handler, const CallEvent &Call, CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef allocatedVariable = Call.getReturnValue().getAsSymbol();
     
  switch(handler) {

    case PRE_CALL :
    break;

    case POST_CALL: 
      
      // add unitilized variables to unitilized list
      State = State->add<UnintializedVariables>(allocatedVariable);
      // mark is synchronized by default
      State = State->set<CheckerState>(allocatedVariable, RefState::getSynchronized());

      // remove the variable from the freed list if allocated again
      if(State->contains<FreedVariables>(allocatedVariable)){
        State = State->remove<FreedVariables>(allocatedVariable);
      } 

      C.addTransition(State);
      break;

  }

}


void DefaultHandlers::handleBarriers(int handler, const CallEvent &Call, CheckerContext &C) {

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

void DefaultHandlers::handleNonBlockingWrites(int handler, const CallEvent &Call, CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();


  if(!destVariable) {
    return;
  }


  switch(handler) {

    case PRE_CALL : break;

    case POST_CALL : 
      // remove the unintialized variables
      removeFromUnitializedList(State, destVariable);
      // mark as unsynchronized
      markAsUnsynchronized(State, destVariable);
     
      C.addTransition(State);
      break;
  }

}

void DefaultHandlers::handleBlockingWrites(int handler, const CallEvent &Call, CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();

  switch(handler) {

    case PRE_CALL : break;

    case POST_CALL : 
       
      removeFromUnitializedList(State, destVariable);
    
      C.addTransition(State);
      break;
  }

}

void DefaultHandlers::handleReads(int handler, const CallEvent &Call, CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
  const RefState *SS = State->get<CheckerState>(symmetricVariable);
  

  switch(handler) {

    case PRE_CALL : 

      if(State->contains<UnintializedVariables>(symmetricVariable)){
        // TODOS: replace couts with bug reports 
        std::cout << ErrorMessages::ACCESS_UNINTIALIZED_VARIABLE;
        return;
     }  
  
     // if the user is trying to access an unintialized bit of memory
     if (SS && SS->isUnSynchronized()) {
      std::cout << ErrorMessages::UNSYNCHRONIZED_ACCESS;
      return;
     }

    break;

    case POST_CALL :  
    break;

  }

} 

void DefaultHandlers::handleMemoryDeallocations(int handler, const CallEvent &Call, CheckerContext &C) {

    ProgramStateRef State = C.getState();
    SymbolRef freedVariable = Call.getArgSVal(0).getAsSymbol();

    switch(handler) {
      case PRE_CALL : 
        break;
      case POST_CALL : 
        // add it to the freed variable set; since it is adding it multiple times should have the same effect
        addToFreeList(State, freedVariable);
        //stop tracking freed variable
        removeFromState(State, freedVariable);
        C.addTransition(State);
      break;
   }
 
}

PGASChecker::PGASChecker(void (*addHandlers)()) { 
  addHandlers();
  addDefaultHandlers();
} 

// int* source = (int*) shmem_malloc(npes*sizeof(int));
// shmem_put(TYPE *dest, const TYPE *source, size_t nelems, int pe);
// shmem_get(TYPE *dest, const TYPE *source, size_t nelems, int pe);
void PGASChecker::addDefaultHandlers() {
  defaults.emplace(MEMORY_ALLOC, DefaultHandlers::handleMemoryAllocations);
  defaults.emplace(MEMORY_DEALLOC, DefaultHandlers::handleMemoryDeallocations);
  defaults.emplace(SYNCHRONIZATION, DefaultHandlers::handleBarriers);
  defaults.emplace(NON_BLOCKING_WRITE, DefaultHandlers::handleNonBlockingWrites);
  defaults.emplace(READ_FROM_MEMORY, DefaultHandlers::handleReads);
}

 
Handler PGASChecker::getDefaultHandler(Routine routineType) const {

    defaultHandlers::const_iterator iterator = defaults.find(routineType);

    if(iterator != defaults.end()) {
        return iterator->second; 
    }

    return (Handler)NULL;
}

void PGASChecker::eventHandler(int handler, std::string &routineName, 
                    const CallEvent &Call, CheckerContext &C) const {

    Handler routineHandler = NULL;
    routineHandlers::const_iterator iterator = handlers.find(routineName);
    
    if(iterator != handlers.end()) {

      Pair value = iterator->second;
      Routine routineType = value.first;
      
      // if the event handler exists invoke it; else call the default implementation
      if(value.second) {
        routineHandler = value.second ;
      }
      else {
        routineHandler = getDefaultHandler(routineType);
      }

      if(routineHandler != NULL) {
          routineHandler(handler, Call, C);
      }
      else{
          std::cout << "No implementation found for this routine!\n";
      }

    }

}
 
void PGASChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

  if (!FD)
    return;

  // get the invoked routine name
  std::string routineName = FD->getNameInfo().getAsString();

  eventHandler(POST_CALL, routineName, Call, C);
  
}

void PGASChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

  if (!FD)
    return;

  // TODO: Temp fix! place these checks into seperate functions
  if(Call.getNumArgs() < 1)
    return;

  // TODO: remove the harcoding of variable index; 
  SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
  
  if(!symmetricVariable)
    return;

  // TODO: extract this out of the function
  ProgramStateRef State = C.getState();

  const RefState *SS = State->get<CheckerState>(symmetricVariable);

  if (!SS) {
    // TODOS: replace couts with bug reports
    std::cout << ErrorMessages::VARIABLE_NOT_SYMMETRIC;
    return;
  }

  // complain if an access it made to the freed variables 
  if(State->contains<FreedVariables>(symmetricVariable)){
    // TODOS: replace couts with bug reports 
    std::cout << ErrorMessages::ACCESS_FREED_VARIABLE;
    return;
  }

  // get the name of the invoked routine
  std::string routineName = FD->getNameInfo().getAsString();

  eventHandler(PRE_CALL, routineName, Call, C);
 
}