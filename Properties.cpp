#include "PGASChecker.h"

// every time we make a change to the program state we need to invoke the
// transform state
void Properties::transformState(CheckerContext &C, ProgramStateRef State) {
  C.addTransition(State);
}

// remember program state is an immutable data structure, so it is neccessary to
// return the new state with effect to the caller
// the caller eventually invokes the transformState to add the new state to the
// program state graph
// remove from the uninitialized list
ProgramStateRef Properties::removeFromUnitializedList(ProgramStateRef State,
                                                      SymbolRef variable) {
  if (State->contains<UnintializedVariables>(variable)) {
    State = State->remove<UnintializedVariables>(variable);
  }
  return State;
}

ProgramStateRef Properties::removeFromFreeList(ProgramStateRef State,
                                               SymbolRef variable) {
  if (State->contains<FreedVariables>(variable)) {
    State = State->remove<FreedVariables>(variable);
  }
  return State;
}

// add to the free list
ProgramStateRef Properties::addToFreeList(ProgramStateRef State,
                                          SymbolRef variable) {
  State = State->add<FreedVariables>(variable);
  return State;
}

ProgramStateRef Properties::addToUnintializedList(ProgramStateRef State,
                                                  SymbolRef variable) {
  State = State->add<UnintializedVariables>(variable);
  return State;
}

// remove the variable program state
ProgramStateRef Properties::removeFromState(ProgramStateRef State,
                                            SymbolRef variable) {
  const RefState *SS = State->get<CheckerState>(variable);
  if (SS) {
    State = State->remove<CheckerState>(variable);
  }
  return State;
}

// mark as unsynchronized
ProgramStateRef Properties::markAsUnsynchronized(ProgramStateRef State,
                                                 SymbolRef variable) {
  State = State->set<CheckerState>(variable, RefState::getUnsynchronized());
  return State;
}

ProgramStateRef Properties::markAsSynchronized(ProgramStateRef State,
                                               SymbolRef variable) {
  State = State->set<CheckerState>(variable, RefState::getSynchronized());
  return State;
}