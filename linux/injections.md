# Detailing our Abstraction for Process Injections
An injection is defined as having three particularly mutable aspects:

1. Identification - The method by which the target process is chosen.
   
   a. For procjet, there are currently three possible values for this aspect:
   
     i. By name: the program is passed a process executable name which it should attempt to match with a process running on the system.
   
     ii. By PID: the programm is passed a program identifier which it should use to open a handle to the corresponding process.
   
     iii. Via privilege algorithm: the program attempts to ascertain a process with higher privileges than its own, which is nevertheless writeable by the program.
   
   b. There is no default for the method of identification in the jet_inject family of functions; one must select either jet_inject_pid, jet_inject_name, or jet_inject_priv.
   
3. Delivery - The method by which the target process is modified.
   
   a. For procjet, there are currently two possible values for this aspect:
   
     i. ptrace: the program should perform process injection and modification using the ptrace() system call API, writing to and reading from memory using PTRACE_PEEKTEXT and PTRACE_POKETEXT, and writing to and reading from registers using PTRACE_GETREGS and PTRACE_SETREGS, among other things.
     ii. /proc: the program should perform process injection and modification using the /proc virtual filesystem, leveraging files like /proc/PID/maps, /proc/PID/mem, and /proc/PID/syscall to enumerate and write to memory and registers.
   
   b. The process_vm_writev() syscall API *may* be supported as a possible value for this aspect in the future, but there are currently no guarantees.
   
   c. The default for the method of delivery is /proc, as it has been selected as the most generally applicable and effective of the possible methods of process modification. To use the ptrace aspect, jet_inject_*identification*_trace ought be used.
   
6. Execution - The method by which the injected shellcode is executed.
   
  a. For procjet, there are currently three possible values for this aspect, with isp having different behavior based on the chosen Delivery.
    /
    i. isp (under ptrace): execution will be modified by setting the target process's instruction pointer to the shellcode address.
    /
    i. isp (under /proc): execution will be modified by writing a shellcode stub to the address specified in the program's instruction pointer, which, when executed, jumps program execution to the shellcode address.
    /
    ii. offset: execution will be modified by overwriting relevant entries in libc's Global Offset Table to the shellcode address.
    /
    iii. smash: execution will be modified by overwriting the most recent call address on the stack to the shellcode address.
    
  b. The default for the method of execution is isp.
  
