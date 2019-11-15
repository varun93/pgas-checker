## OpenSHMEM Checker

![alt text](./checker.png)

**This is currently experimental**

Although this is checker is meant for static analysis of an OpenShmem source, the ultimate goal of the project is to extend it to any library following one-sided(Fire and Forget) communication semantics. 

**Extending for libraries following One Sided Communication(Yet to be incorporated into the Main Checker)**

- Please check the folder ```checker_extension_ideation``` to get a sense of how to extend the checker for other libraries.
- The basis of providing the extension is that libraries following this paradigm of communication have routines which fall under these  broad categories.
    - Memory Allocation
    - Memory Dellocation
    - Write to Shared Memory(Can be blocking or Non Blocking)
    - Read from Shared Memory
    - Synchronization Barriers
- Most routines would be categorized into one the above categories. The developer would add an entry to the map with the routine name as the
key of the map and the value being a pair of <RoutineType, FunctionPointer>. The function pointer may be left null if the developer wishes to use the default implementation.  

- The library developers need to implement their handler for  

- The checker identifies if a variable is a symmetric variable.
- Checks is the destination variable is a symmetric variable.
- Catches unsynchronized access to variables via shmem_get.

## How to include your checker?
- Navigate to `clang/lib/StaticAnalyzer/Checkers` directory.
- Add your checker file.Include the checker file in the `CMakeLists.txt` file.
- Enter the following lines in `include/clang/StaticAnalyzer/Checkers/Checkers.td`
    ```def PGASChecker : Checker<"PGASChecker">,
       HelpText<"Checks correctness of a PGAS program">,
       DescFile<"PGASChecker.cpp">;
    ```
- Build clang - Navigate to the build directory, do `make clang -j CORES_NUM`

## Tests

- all_is_well.c : Correct Open Shmem Program
- destination_not_symmetric.c : Destination is not a symmetric variable
- unsynchronized_access.c : Unsynchronized access of shmem_get
- use_after_free.c : Catch use after free bugs
- unintialized_access.c - Check if a shmem_get operation is on an unintialized variable. 

```
cd tests
clang -Xanalyzer -analyzer-checker=core.OpenSHMEMChecker --analyze PROGRAM_TO_TEST open_shmem.c
```

## TODO

- Add proper bug report.
- Yet to add support for catching other synchronization mechanisms like quiet etc. 
- Synchronization mechanisms for symmetric variables allocated via static and global variables. 
