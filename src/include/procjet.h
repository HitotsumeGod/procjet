#ifndef __PROCJET_H__
#define __PROCJET_H__

#include <sys/types.h>
#include "std/ptools.h"

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

#endif //__PROCJET_H__
