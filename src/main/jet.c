#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "procjet.h"

bool inject_jet_pid(byte *data, size_t dlen, pid_t p)
{
	FILE *maps, *syscall;
	char mapname[20], syscallname[20], segment[220], straddr[20], strrip[20];
	qword addr, rip;
	byte saved[dlen];
	int count;

	if (!data || dlen < 1 || p < 1) {
		errno = BAD_ARGS_ERR;
		PRINT_CERR("inject_jet_pid()");
		return false;
	}
	if (kill(p, SIGSTOP) != 0) {
		perror("kill() error");
		return false;
	}
	straddr[0] = '0', straddr[1] = 'x';
	sprintf(mapname, "/proc/%d/maps", p);
	if ((maps = fopen(mapname, "rb")) == NULL) {
		perror("fopen() error");
		return false;
	}
	//find an executable memory segment
	do {
		if (fgets(segment, sizeof(segment), maps) == NULL) {
			perror("fgets() error");
			return false;
		}
	} while (strchr(segment, 'x') == NULL);
	fclose(maps);
	//format and copy segment offset to qword
	for (int i = 0, ii = 2; ii; i++, ii++) {
		if (segment[i] == '-')
			break;
		straddr[ii] = segment[i];
	}
	addr = strtol(addr, NULL, 16);
	//perform injection proper
	if (mem_read(saved, sizeof(saved), p, addr) <= 0)
		return false;
	if (mem_write(data, dlen, p, addr) <= 0)
		return false;
	sprintf(syscallname, "/proc/%d/syscall", p);
	if ((syscall = fopen(syscallname, "wb+")) == NULL) {
		perror("fopen() error");
		return NULL;
	}
	//set the file pointer at the start of the instruction pointer
	count = 0;
	while (count != 8)
		if (fgetc(syscall) == ' ')
			count++;
	}
	if (fgets(strrip, sizeof(strrip), syscall) == NULL) {
		perror("fgets() error");
		return false;
	}
	rip = strtol(strrip, NULL, 16);
	SET_STUB_PAYLOAD(addr);
	if (mem_write(STUB, GET_STUB_SIZE, p, rip) <= 0)
		return false;
	if (kill(p, SIGCONT) != 0) {
		perror("kill() error");
		return false;
	}
	return true;
}
