# HW1
## Secured API Call
The homework aims to practice library injection, API hijacking, and GOT rewriting. You have to implement a sandbox.so
## Specification
### Program Launcher
We use a launcher program to execute a command and load your sandbox.so using LD_PRELOAD. The launcher executes the command and passes the required environment variables to an invoked process. The environment variables include:
* SANDBOX_CONFIG: The path of the configuration file for sandbox.so.
* LOGGER_FD: the file descriptor (fd) for logging messages.
'''bash
./launcher sandbox.so config.txt command arg1 arg2 ...
'''
### Sandbox
Implement a __libc_start_main to hijack the process’s entry point.

Your sandbox.so cannot have a function with the same function name listed in the API function list. To hijack an API function, you must perform GOT hijacking in the __libc_start_main of sandbox.so.
#### API Function List
1. open
Allow a user to set the file access blacklist so that files listed in the blacklist cannot be opened. If a file is in the blacklist, return -1 and set errno to EACCES. Note that for handling symbolic linked files, your implementation has to follow the links before performing the checks.
2. read
Your implementation must log all content into a file. The log file should be named in the format {pid}-{fd}-read.log and be created at read function on this fd be called first time. (If an fd is used more than one time in a process, keep logging the content into the same log file.)
3. write
Your implementation must log all content into a file. The log file should be named in the format {pid}-{fd}-write.log and be created at write function on this fd be called first time. (If an fd is used more than one time in a process, keep logging the content into the same log file.)
4. connect
Allow a user to block connection setup to specific IP addresses and PORT numbers. If the IP and PORT is blocked, return -1 and set errno to ECONNREFUSED.
5. getaddrinfo
Allow a user to block specific host name resolution requests. If a host is blocked, return EAI_NONAME.
6. system
Commands invoked by system function should also be hijacked and monitored by your sandbox. Note that you cannot invoke the launcher again in your implementation. The correct and incorrect relationship for the invoked process should look like the example below.
### Configuration File Format
The configuration file is a text file containing blocked content for each API function. For each API. A sample configuration is given below.
```bash
BEGIN open-blacklist
/etc/passwd
/etc/shadow
END open-blacklist

BEGIN read-blacklist
-----BEGIN CERTIFICATE-----
END read-blacklist

BEGIN connect-blacklist
www.nycu.edu.tw:4433
google.com:80
END connect-blacklist

BEGIN getaddrinfo-blacklist
www.ym.edu.tw
www.nctu.edu.tw
END getaddrinfo-blacklist
```