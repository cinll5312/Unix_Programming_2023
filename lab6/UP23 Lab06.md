UP23 Lab06
==========
Date: 2023-05-01

# Assembly Sort Challenge

This lab aims to practice writing assembly codes. Your mission is to implement a sort algorithm in assembly language that sorts a given array containing $n$ `long` integers in an ascending order. To have more fun, we implement a live scoreboard to show solution ranks based on the *correctness*, *running time*, and *code size*. Please try your best to implement efficient assembly codes.

## The Challenge Server

The challenge server can be accessed using the `nc` command:

```
nc up23.zoolab.org 10950
```

Upon connecting to the challenge server, you must first solve the Proof-of-Work challenge . Then you can follow the instructions to submit (1) the shellcode to run on the server and (2) optionally submit your token for the live scoreboard, and (3) the assembled machine codes used to sort the array.



## Lab Hints

Here are some hints for you. You can solve the challenge locally and then verify your solution on the challenge server.

1. We will invoke your uploaded machine code from offset zero. It is called from the server with two arguments, the pointer to the array and the number of `long` integers in the array. The prototype of the function is

   ```
   typedef void (*sort_funcptr_t)(long *numbers, int n);
   ```

   We do not have another array for placing sorted numbers. You can reorder the elements in the array `numbers` directly.

1. Your code cannot invoke any system call in your implementation. If you need to allocate memory spaces, allocate them on the stack.

1. We have runtime constraints for your uploaded machine code. 
   - Your code size cannot exceed 512 bytes.
   - The maximum running time is 120 seconds.
    
1. To simplify the code submission process, you can use our provided `pwntools` python script to solve the pow and submit your shellcode. You have to place the `pow.py` file in the same directory and invoke the script by passing the path of your compiled solver executable as the first parameter to the submission script. The usage of the submission script is as follows.

   ```
   ./submit.py filename.s [scoreboard-token]
   ```
 
   The above command assumes you implement your assembly codes in `filename.s`. If you plan to submit your score to the live scoreboard, please pass your *scoreboard-token* as the third parameter to the submission script.

1. The challenge server only accepts machine codes generated for Intel x86_64 CPU.


   

