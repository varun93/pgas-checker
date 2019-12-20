#include "PGASChecker.h"

typedef std::unordered_map<int, Handler> defaultHandlers;
defaultHandlers defaults;
routineHandlers handlers;
std::unique_ptr<BuiltinBug> BT;

// Sample Bug Report
// void reportUnsynchronizedAccess(
//   const CallEvent &Call, CheckerContext &C) {

//   ExplodedNode *errorNode = C.generateNonFatalErrorNode();
//   if (!errorNode)
//     return;

//   if (!BT)
//     BT.reset(new BuiltinBug(NULL, "Unsynchronized Access",
//     ErrorMessages::UNSYNCHRONIZED_ACCESS));

//   auto R = llvm::make_unique<BugReport>(*BT, BT->getDescription(),
//   errorNode); R->addRange(Call.getSourceRange()); C.emitReport(std::move(R));
// }

/**
 * @brief Invoked on allocation of symmetric variable
 *
 * @param handler
 * @param Call
 * @param C
 */
void DefaultHandlers::handleMemoryAllocations(int handler,
                                              const CallEvent &Call,
                                              CheckerContext &C) {
  ProgramStateRef State = C.getState();
  // get the reference to the allocated variable
  SymbolRef allocatedVariable = Call.getReturnValue().getAsSymbol();

  switch (handler) {

  case PRE_CALL:
    break;

  case POST_CALL:
    // add unitilized variables to unitilized list
    State = Properties::addToUnintializedList(State, allocatedVariable);
    // mark is synchronized by default
    State = Properties::markAsSynchronized(State, allocatedVariable);
    // remove the variable from the freed list if allocated again
    State = Properties::removeFromFreeList(State, allocatedVariable);
    // update the program state graph;
    // every time we make a change to the program state we need to invoke the
    // transform state
    Properties::transformState(C, State);
    break;
  }
}

/**
 * @brief invoked on synchronization barriers; this is specifically for
 * barrier_all
 *
 * @param handler
 * @param Call
 * @param C
 */
void DefaultHandlers::handleBarriers(int handler, const CallEvent &Call,
                                     CheckerContext &C) {

  ProgramStateRef State = C.getState();
  auto trackedVariables = State->get<CheckerState>();

  switch (handler) {
  case PRE_CALL:
    break;
  case POST_CALL:
    // iterate through all the track variables so far variables
    // set each of the values to synchronized
    for (PGASMapImpl::iterator I = trackedVariables.begin(),
                               E = trackedVariables.end();
         I != E; ++I) {
      SymbolRef symmetricVariable = I->first;
      // mark all symmetric variables as synchronized
      State = Properties::markAsSynchronized(State, symmetricVariable);
      // important to invoke this each time/each variable
      Properties::transformState(C, State);
    }
    break;
  }
}

/**
 * @brief Handler for non blocking writes
 *
 * @param handler
 * @param Call
 * @param C
 */
void DefaultHandlers::handleNonBlockingWrites(int handler,
                                              const CallEvent &Call,
                                              CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();

  if (!destVariable) {
    return;
  }

  switch (handler) {
  case PRE_CALL:
    /*
    to retrieve all all arguments of the invoked it you could something like
    int argCount =  Call.getNumArgs();
    for(int argIndex=0; argIndex < argCount; argIndex++) {
      SVal argument = Call.getArgSVal(argIndex);
      SymbolRef ref = argument.getAsSymbol();
      //do something useful with this
    }
    */
    const RefState *SS = State->get<CheckerState>(destVariable);

    if (!SS) {
      // TODOS: replace couts with bug reports
      std::cout << ErrorMessages::VARIABLE_NOT_SYMMETRIC;
      return;
    }
    break;
  case POST_CALL:
    // remove the unintialized variables
    State = Properties::removeFromUnitializedList(State, destVariable);
    // mark as unsynchronized
    State = Properties::markAsUnsynchronized(State, destVariable);
    Properties::transformState(C, State);
    break;
  }
}

/**
 * @brief Handler for blocking writes; same as non blocking writes
 *
 * @param handler
 * @param Call
 * @param C
 */
void DefaultHandlers::handleBlockingWrites(int handler, const CallEvent &Call,
                                           CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SymbolRef destVariable = Call.getArgSVal(0).getAsSymbol();

  switch (handler) {
  case PRE_CALL:
    break;
  case POST_CALL:
    // remove from uninitilized list
    State = Properties::removeFromUnitializedList(State, destVariable);
    Properties::transformState(C, State);
    break;
  }
}

// invoked on read routines such as shmem_get
void DefaultHandlers::handleReads(int handler, const CallEvent &Call,
                                  CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef symmetricVariable = Call.getArgSVal(0).getAsSymbol();
  const RefState *SS = State->get<CheckerState>(symmetricVariable);

  switch (handler) {

  case PRE_CALL:

    // if the user is trying to access an unintialized bit of memory
    if (State->contains<UnintializedVariables>(symmetricVariable)) {
      // TODOS: replace couts with bug reports
      std::cout << ErrorMessages::ACCESS_UNINTIALIZED_VARIABLE;
      return;
    }

    // check if the symmetric memory is in an unsynchronized state
    if (SS && SS->isUnSynchronized()) {
      // reportUnsynchronizedAccess(Call, C);
      std::cout << ErrorMessages::UNSYNCHRONIZED_ACCESS;
      return;
    }

    break;

  case POST_CALL:
    break;
  }
}

/**
 * @brief invoked on memory deallocation routines as shmem_free
 *
 * @param handler
 * @param Call
 * @param C
 */
void DefaultHandlers::handleMemoryDeallocations(int handler,
                                                const CallEvent &Call,
                                                CheckerContext &C) {

  ProgramStateRef State = C.getState();
  SymbolRef freedVariable = Call.getArgSVal(0).getAsSymbol();

  switch (handler) {
  case PRE_CALL:
    break;
  case POST_CALL:
    // add it to the freed variable set; since it is adding it multiple times
    // should have the same effect
    State = Properties::addToFreeList(State, freedVariable);
    // stop tracking freed variable
    State = Properties::removeFromState(State, freedVariable);
    Properties::transformState(C, State);
    break;
  }
}

/**
 * @brief Construct a new PGASChecker::PGASChecker object
 * Does two things:
 * Get the library specific handlers, populate default handlers
 *
 * @param addHandlers
 */
PGASChecker::PGASChecker(routineHandlers (*addHandlers)()) {
  handlers = addHandlers();
  addDefaultHandlers();
}

/**
 * @brief Populate the default handlers for each routine type
 *
 */
void PGASChecker::addDefaultHandlers() {
  defaults.emplace(MEMORY_ALLOC, DefaultHandlers::handleMemoryAllocations);
  defaults.emplace(MEMORY_DEALLOC, DefaultHandlers::handleMemoryDeallocations);
  defaults.emplace(SYNCHRONIZATION, DefaultHandlers::handleBarriers);
  defaults.emplace(NON_BLOCKING_WRITE,
                   DefaultHandlers::handleNonBlockingWrites);
  defaults.emplace(READ_FROM_MEMORY, DefaultHandlers::handleReads);
}

/**
 * @brief retrieve the  default routine handler for a routine type
 *
 * @param routineType
 * @return Handler
 */
Handler PGASChecker::getDefaultHandler(Routine routineType) const {

  defaultHandlers::const_iterator iterator = defaults.find(routineType);

  if (iterator != defaults.end()) {
    return iterator->second;
  }

  return (Handler)NULL;
}

/**
 * @brief Event handler takes in the routine name,
 * and maps the routine name to routine
 * type and the corresponding routine handler of the specific routine
 * invoked handler can be default one or the programming model specific one
 *
 * @param handler
 * @param routineName
 * @param Call
 * @param C
 */
void PGASChecker::eventHandler(int handler, std::string &routineName,
                               const CallEvent &Call, CheckerContext &C) const {

  Handler routineHandler = NULL;
  // get the corresponding iterator to the key
  routineHandlers::const_iterator iterator = handlers.find(routineName);

  if (iterator != handlers.end()) {

    // corresponding <routineType, routineHandler> pair
    Pair value = iterator->second;
    // value.first is the routineType and value.second is the routineHandler
    Routine routineType = value.first;

    // if the event handler exists invoke it; else call the default
    // implementation
    if (value.second) {
      routineHandler = value.second;
    } else {
      routineHandler = getDefaultHandler(routineType);
    }

    // finally invoke the routine handler
    if (routineHandler != NULL) {
      routineHandler(handler, Call, C);
    } else {
      std::cout << "No implementation found for this routine\n";
    }
  }
}
/**
 * @brief Gets called as a post callback on invocation of a routine
 *
 * @param Call
 * @param C
 */
void PGASChecker::checkPostCall(const CallEvent &Call,
                                CheckerContext &C) const {
  // get the declaration of the invoked routine
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

  if (!FD)
    return;

  // get the invoked routine name
  std::string routineName = FD->getNameInfo().getAsString();

  // invoke the event handler to figure out the right implementation
  eventHandler(POST_CALL, routineName, Call, C);
}
// pre call callback
void PGASChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

  if (!FD)
    return;

  // get the name of the invoked routine
  std::string routineName = FD->getNameInfo().getAsString();

  eventHandler(PRE_CALL, routineName, Call, C);
}