# lab5
## Specification
1. The module has to automatically create 8 devices in /dev filesystem (from kshram0 to kshram7). Each device corresponds to a kernel memory space of 4KB (default) allocated in the kernel using the kzalloc function. You may use an array of customized data structures to store your required information.
2. The size of each shared memory file can be listed from /proc/kshram. A sample output is shown below.

```bash
00: 4096
01: 4096
02: 4096
03: 4096
04: 4096
05: 4096
06: 4096
07: 4096
```

3. The module has to support the following ioctl commands, defined in kshram.h
*  KSHRAM_GETSLOTS returns the number of slots available in the module. It should be 8. This command does not have an additional argument.
* KSHRAM_GETSIZE returns the size of the shared memory corresponding to the opened device. You should manage the size of each allocated memory internally by yourself. This command does not have an additional argument.
* KSHRAM_SETSIZE resizes the size of the shared memory file based on the third parameter passed to the ioctl function. Given an allocated memory pointer, you may resize it by using the krealloc function in the kernel. This command uses an additional argument to pass the size to be set.
4. Your module must support mmap file operation. In the mmap file operation, you have to map to memory allocated in the kernel to user-space addresses so that the user-space program can access it directly.