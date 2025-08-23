#ifndef __PROCJET_H__
#define __PROCJET_H__

#include <sys/types.h>
#include "std/ptools.h"

#define _MEM_C_

/**
 * @brief Reads from process memory via the /proc virtual filesystem.
 *
 * @param buffer the data buffer which will store the read process memory
 * @param length the length of the data buffer
 * @param pid the process id of the target process
 * @param offset the offset into the process memory at which the data is to be read
 * @return the number of bytes read from process memory
 */
extern size_t mem_read(byte *buffer, size_t length, pid_t pid, qword offset);

/**
 * @brief Overwrites process memory via the /proc virtual filesystem.
 *
 * @param data the binary data to be written to process memory
 * @param length the length of the data to be written
 * @param pid the process id of the target process
 * @param offset the offset into the process memory at which the data is to be written
 * @return the number of bytes written to process memory
 */
extern size_t mem_write(byte *data, size_t length, pid_t pid, qword offset);

#endif

#define _JET_C_

/**
 * @brief Injects and executes shellcode within a more privileged process.
 *
 * Digs through system processes to find one more privileged than its own. Once such a
 * process is found, the shellcode is injected and executed as normal.
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @return a boolean value confirming the success or failure of the function
 */
extern bool jet_inject_priv(byte *data, size_t length);

/**
 * @brief Injects and executes shellcode within a process, chosen by its PID.
 *
 * Injects and executes shellcode from within the memory space of a remote process. Said process is
 * selected via its Process ID (PID).
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @param pid the Process ID of the desired process
 * @return a boolean value confirming the success or failure of the function
 */
extern bool jet_inject_pid(byte *data, size_t length, pid_t pid);

/**
 * @brief Injects and executes shellcode within a process, chosen by its command-line name.
 *
 * Injects and executes shellcode from within the memory space of a remote process. Said process is
 * selected via its command-line name, which can be queried from the 'cmdline' file in a process's procfs directory.
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @param procname the command-line name of the desired process
 * @return a boolean value confirming the success or failure of the function
 */
extern bool jet_inject_name(byte *data, size_t length, char *procname);

#endif

#endif //__PROCJET_H__
