#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include "procjet.h"

/**
 * Killback stub
 * calls getpid and then kill to SIGSTOP itself
 */
byte kstub[] =  { 	
			0xB8, 0x27, 0x00, 0x00, 0x00,
			0x0F, 0x05,
			0x48, 0x89, 0xC7,
			0xB8, 0x3E, 0x00, 0x00, 0x00,
			0xBE, 0x13, 0x00, 0x00, 0x00,
			0x0F, 0x05
		};

bool jet_inject_pid(byte *data, size_t dlen, pid_t p)
{
	struct user_regs_struct regs;
	FILE *maps;
	char mapname[20], segment[220], straddr[20];
	qword addr, rip;
	byte saved[dlen];
	int wstatus;

	if (!data || dlen < 1 || p < 1) {
		errno = BAD_ARGS_ERR;
		PRINT_CERR("inject_jet_pid()");
		return false;
	}
	if (ptrace(PTRACE_ATTACH, p, NULL, NULL) == -1) {
		perror("ptrace() error");
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
	addr = strtol(straddr, NULL, 16);
	//perform injection proper
	if (mem_read(saved, sizeof(saved), p, addr) <= 0)
		return false;
	if (mem_write(data, dlen, p, addr) <= 0)
		return false;
	if (ptrace(PTRACE_GETREGS, p, NULL, &regs) == -1) {
		perror("ptrace() error");
		return false;
	}
	rip = regs.rip;
	regs.rip = addr;
	if (ptrace(PTRACE_SETREGS, p, NULL, &regs) == -1) {
		perror("ptrace() error");
		return false;
	}
	if (ptrace(PTRACE_CONT, p, NULL, NULL) == -1) {
		perror("ptrace() error");
		return false;
	}
	//wait for tracee to finish executing shellcode
	while (wait(&wstatus))
		if (WIFSTOPPED(wstatus))
			break;
		else
			if (ptrace(PTRACE_CONT, p, NULL, NULL) == -1) {
				perror("ptrace() error");
				return false;
			}
	//restore tracee's original state and restart its execution
	if (mem_write(saved, sizeof(saved), p, addr) <= 0)
		return false;
	regs.rip = rip;
	if (ptrace(PTRACE_SETREGS, p, NULL, &regs) == -1) {
		perror("ptrace() error");
		return false;
	}
	if (ptrace(PTRACE_DETACH, p, NULL, &regs) == -1) {
		perror("ptrace() error");
		return false;
	}
	return true;
}

bool jet_inject_pid_noptrace(byte *data, size_t dlen, pid_t p)
{
	struct timespec t;
	FILE *maps, *syscall, *stat;
	char strname[20], segment[220], straddr[20], strrip[20], stats[220], *tokens;
	qword addr, rip;
	byte saved[dlen + (sizeof(kstub) / sizeof(byte))], savedrip[get_stub_len() + 100];
	int count;

	if (!data || dlen < 1 || p < 1) {
		errno = BAD_ARGS_ERR;
		PRINT_CERR("inject_jet_pid_noptrace()");
		return false;
	}
	if (kill(p, SIGSTOP) != 0) {
		perror("kill() error");
		return false;
	}
	straddr[0] = '0', straddr[1] = 'x';
	sprintf(strname, "/proc/%d/maps", p);
	if ((maps = fopen(strname, "rb")) == NULL) {
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
	addr = strtol(straddr, NULL, 16);
	//write our payload to memory
	if (mem_read(saved, sizeof(saved), p, addr) <= 0)
		return false;
	//if (mem_write(data, dlen, p, addr) <= 0)
	//	return false;
	if (mem_write(kstub, sizeof(kstub) / sizeof(byte), p, addr + dlen) <= 0)
		return false;
	//get the rip address
	sprintf(strname, "/proc/%d/syscall", p);
	if ((syscall = fopen(strname, "r")) == NULL) {
		perror("fopen() error");
		return NULL;
	}
	count = 0;
	while (count != 8)
		if (fgetc(syscall) == ' ')
			count++;
	if (fgets(strrip, sizeof(strrip), syscall) == NULL) {
		perror("fgets() error");
		return false;
	}
	rip = strtol(strrip, NULL, 16);
	set_stub_dst(addr);
	//write to the rip address and send SIGCONT to execute our shellcode
	if (mem_read(savedrip, get_stub_len(), p, rip) <= 0)
		return false;
	if (mem_write(stub, get_stub_len(), p, rip) <= 0)
		return false;
	if (kill(p, SIGCONT) != 0) {
		perror("kill() error");
		return false;
	}
	//wait for the process to stop
	sprintf(strname, "/proc/%d/stat", p);
	if ((stat = fopen(strname, "r")) == NULL) {
		perror("fopen() error");
		return false;
	}
	t.tv_sec = 0;
	t.tv_nsec = 100000000;
	while (1) {
		fgets(stats, sizeof(stats), stat);
		tokens = strtok(stats, " ");
		for (int i = 0; i < 2; i++)
			tokens = strtok(NULL, " ");
		if (strcmp(tokens, "T") == 0)
			break;
		nanosleep(&t, NULL);
	}
	fclose(stat);
	//now that our execution is complete, restore the process to its original state
	if (mem_write(saved, sizeof(saved), p, addr) <= 0) {
		fprintf(stderr, "mem_write() error\n");
		return false;
	}
	if (mem_write(savedrip, sizeof(savedrip), p, rip) <= 0) {
		fprintf(stderr, "mem_write() error\n");
		return false;
	}
	if (kill(p, SIGCONT) != 0) {
		perror("kill() error");
		return false;
	}
	return true;
}
