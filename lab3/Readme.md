# lab3
## Lab Instructions
1. The implementation of the chals somehow calls incorrect coding functions. The objective of your solver is to ensure that the chals calls to the correct functions. For example, the first coding function called in chals is code_498, but all function calls to code_498 should be code_44. To find the correct mappings of coding functions, please refer to the ndat array defined in shuffle.h. It is obvious that the index value of 498 in the ndat array is 44.
## Hints
1. Hijack GOT 
2. dlopen, dlsym