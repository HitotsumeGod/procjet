#ifndef __PROCJET_H__
#define __PROCJET_H__

#include "ptools.h"
#include <sys/types.h>

#define _MEM_C_

/**
 * @brief Reads from process memory via the /proc virtual filesystem.
 *
 * @param buffer the data buffer which will store the read process memory
 * @param length the length of the data buffer
 * @param pid the process id of the target process
 * @param offset the offset into the process memory at which the data is to be read
 * @return a pointer to an errep linked list for debugging
 */
extern struct errep *jet_mem_read(byte *buffer, size_t length, pid_t pid, qword offset);

/**
 * @brief Overwrites process memory via the /proc virtual filesystem.
 *
 * @param data the binary data to be written to process memory
 * @param length the length of the data to be written
 * @param pid the process id of the target process
 * @param offset the offset into the process memory at which the data is to be written
 * @return a pointer to an errep linked list for debugging
 */
extern struct errep *jet_mem_write(byte *data, size_t length, pid_t pid, qword offset);

#define _JET_C_

/**
 * @brief Injects and executes shellcode within a more privileged process.
 *
 * Digs through system processes to find one more privileged than its own. Once such a
 * process is found, the shellcode is injected and executed as normal.
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @return a pointer to an errep linked list for debugging
 */
extern struct errep *jet_inject_priv(byte *data, size_t length);

/**
 * @brief Injects and executes shellcode within a process, chosen by its PID.
 *
 * Injects and executes shellcode from within the memory space of a remote process. Said process is
 * selected via its Process ID (PID).
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @param pid the Process ID of the desired process
 * @return a pointer to an errep linked list for debugging
 */
extern struct errep *jet_inject_pid(byte *data, size_t length, pid_t pid);

/**
 * @brief Injects and executes shellcode within a process, chosen by its command-line name.
 *
 * Injects and executes shellcode from within the memory space of a remote process. Said process is
 * selected via its command-line name, which can be queried from the 'cmdline' file in a process's procfs directory.
 * @param data the binary data (typically shellcode) to be executed from remote process memory
 * @param length the length of the executable data
 * @param procname the command-line name of the desired process
 * @return a pointer to an errep linked list for debugging
 */
extern struct errep *jet_inject_name(byte *data, size_t length, char *procname);

/**
 * Alternate version of jet_inject_priv() that utilizes the ptrace API
 */
extern struct errep *jet_inject_priv_trace(byte *data, size_t length);

/**
 * Alternate version of jet_inject_pid() that utilizes the ptrace API
 */
extern struct errep *jet_inject_pid_trace(byte *data, size_t length, pid_t pid);

/**
 * Alternate version of jet_inject_name() that utilizes the ptrace API
 */
extern struct errep *jet_inject_name_trace(byte *data, size_t length, pid_t pid);

extern byte stub[];

extern size_t get_stub_len(void);

extern void set_stub_dst(qword address);

#endif //__PROCJET_H__
