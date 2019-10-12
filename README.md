## OpenSHMEM Checker

![alt text](./checker.png)

**This is currently experimental**

Although this is checker is meant for static analysis of an OpenShmem source, the ultimate goal of the project is to extend it to any library following one-sided communication semantics. 

**Coming Soon**  
A concrete detailed roadmap for the project.

- The checker identifies if a variable is a symmetric variable.
- Checks is the destination variable is a symmetric variable.
- Catches unsynchronized access to variables via shmem_get.

## How to include the checker?
- Include your checker file in the `CMakeLists.txt` file
- Navigate to the build folder and `make clang -j CORES_NUM`

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
