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

struct errep *jet_inject_pid(byte *data, size_t dlen, pid_t p)
{
        struct errep *err;
        char *fnname = "jet_inject_pid()";
        struct user_regs_struct regs;
        FILE *maps;
        char mapname[20], segment[220], straddr[20];
        qword addr, rip;
        byte saved[dlen];
        int wstatus;

        if (!data || dlen < 1 || p < 1) {
                ERREP(err, fnname, "this function was passed bad arguments");
                return err;
        }
        if (ptrace(PTRACE_ATTACH, p, NULL, NULL) == -1) {
                ERREP(err, fnname, "error attaching trace to process");
                return err;
        }
        straddr[0] = '0', straddr[1] = 'x';
        sprintf(mapname, "/proc/%d/maps", p);
        if ((maps = fopen(mapname, "rb")) == NULL) {
                ERREP(err, fnname, "error opening process memory file for reading");
                return err;
        }
        //find an executable memory segment
        do {
                if (fgets(segment, sizeof(segment), maps) == NULL) {
                        ERREP(err, fnname, "error reading from process memory file");
                        return err;
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
        if ((err = mem_read(saved, sizeof(saved), p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error saving process overwriteable memory");
                return err;
        }
        if ((err = mem_write(data, dlen, p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error writing payload to process memory");
                return err;
        }
        if (ptrace(PTRACE_GETREGS, p, NULL, &regs) == -1) {
                ERREP(err, fnname, "error getting registers from traced process");
                return err;
        }
        rip = regs.rip;
        regs.rip = addr;
        if (ptrace(PTRACE_SETREGS, p, NULL, &regs) == -1) {
                ERREP(err, fnname, "error setting traced process registers");
                return err;
        }
        if (ptrace(PTRACE_CONT, p, NULL, NULL) == -1) {
                ERREP(err, fnname, "error restarting traced process");
                return err;
        }
        //wait for tracee to finish executing shellcode
        while (wait(&wstatus))
                if (WIFSTOPPED(wstatus))
                        break;
                else
                        if (ptrace(PTRACE_CONT, p, NULL, NULL) == -1) {
                                ERREP(err, fnname, "error restarting traced process");
                                return err;
                        }
        //restore tracee's original state and restart its execution
        if ((err = mem_write(saved, sizeof(saved), p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error restoring process original memory contents");
                return err;
        }
        regs.rip = rip;
        if (ptrace(PTRACE_SETREGS, p, NULL, &regs) == -1) {
                ERREP(err, fnname, "error restoring traced process registers");
                return err;
        }
        if (ptrace(PTRACE_DETACH, p, NULL, &regs) == -1) {
                ERREP(err, fnname, "error detaching trace from process");
                return err;
        }
        ERREP(err, fnname, NULL);
        return err;
}

struct errep *jet_inject_pid_noptrace(byte *data, size_t dlen, pid_t p)
{
        struct errep *err;
        char *fnname = "jet_inject_pid_noptrace()";
        struct timespec t;
        FILE *maps, *syscall, *stat;
        char strname[20], segment[220], straddr[20], strrip[20], stats[220], *tokens;
        qword addr, rip;
        byte saved[dlen + (sizeof(kstub) / sizeof(byte))], savedrip[get_stub_len() + 100];
        int count;

        if (!data || dlen < 1 || p < 1) {
                ERREP(err, fnname, "this function was passed bad arguments");
                return err;
        }
        if (kill(p, SIGSTOP) != 0) {
                ERREP(err, fnname, "error sending SIGSTOP to target process");
                return err;
        }
        straddr[0] = '0', straddr[1] = 'x';
        sprintf(strname, "/proc/%d/maps", p);
        if ((maps = fopen(strname, "rb")) == NULL) {
                ERREP(err, fnname, "error opening process memory file for reading");
                return err;
        }
        //find an executable memory segment
        do {
                if (fgets(segment, sizeof(segment), maps) == NULL) {
                        ERREP(err, fnname, "error reading from process memory file");
                        return err;
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
        if ((err = mem_read(saved, sizeof(saved), p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error saving overwriteable process memory");
                return err;
        }
        if ((err = mem_write(data, dlen, p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error writing payload to process memory");
                return err;
        }
        if ((err = mem_write(kstub, sizeof(kstub) / sizeof(byte), p, addr + dlen)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error writing killstub to process memory");
                return err;
        }
        //get the rip address
        sprintf(strname, "/proc/%d/syscall", p);
        if ((syscall = fopen(strname, "r")) == NULL) {
                ERREP(err, fnname, "error opening process syscall file for reading");
                return err;
        }
        count = 0;
        while (count != 8)
                if (fgetc(syscall) == ' ')
                        count++;
        if (fgets(strrip, sizeof(strrip), syscall) == NULL) {
                ERREP(err, fnname, "error reading from process syscall file");
                return err;
        }
        rip = strtol(strrip, NULL, 16);
        set_stub_dst(addr);
        //write to the rip address and send SIGCONT to execute our shellcode
        if ((err = mem_read(savedrip, get_stub_len(), p, rip)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error saving contents of process RIP");
                return err;
        }
        if ((err = mem_write(stub, get_stub_len(), p, rip)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error writing relocation stub to process RIP");
                return err;
        }
        if (kill(p, SIGCONT) != 0) {
                ERREP(err, fnname, "error sending SIGCONT to target process");
                return err;
        }
        //wait for the process to stop
        sprintf(strname, "/proc/%d/stat", p);
        if ((stat = fopen(strname, "r")) == NULL) {
                ERREP(err, fnname, "error opening process stat file for reading");
                return err;
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
        if ((err = mem_write(saved, sizeof(saved), p, addr)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error restoring process memory contents");
                return err;
        }
        if ((err = mem_write(savedrip, sizeof(savedrip), p, rip)) -> msg != NULL) {
                ERREP(err -> next, fnname, "error restoring process RIP address");
                return err;
        }
        if (kill(p, SIGCONT) != 0) {
                ERREP(err, fnname, "error restarting target process");
                return err;
        }
        ERREP(err, fnname, NULL);
        return err;
}
