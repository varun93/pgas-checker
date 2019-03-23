## OpenSHMEM Checker

**This is currently only experimental**

- The checker identifies if a variable is a symmetric variable.
- Checks is the destination variable is a symmetric variable.
- Catches unsynchronized access to variables via shmem_get.

## Tests

- all_is_well.c : Correct Open Shmem Program
- destination_not_symmetric.c : Destination is not a symmetric variable
- unsynchronized_access.c :Unsynchronized access of shmem_get

```
cd tests
clang -Xanalyzer -analyzer-checker=core.MainCallChecker --analyze PROGRAM_TO_TEST open_shmem.c
```

## TODO

- Currently only symmetric variables on the heap is identified. Will soon add support for identifying all symmetric variables.
- Yet to add support for catching other synchronization mechanisms like quiet etc.
- Check if the pe is a power of two.
