#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "procjet.h"

struct errep *jet_mem_read(byte *buf, size_t blen, pid_t p, qword off)
{
        struct errep *err;
        char *fnname = "jet_mem_read()";
        FILE *mem;
        char fname[30];

        if (!buf || blen < 1 || p < 1 || off < 1) {
                ERREP(err, fnname, "this function was provided bad arguments");
                return err;
        }
        sprintf(fname, "/proc/%d/mem", p);
        if ((mem = fopen(fname, "rb")) == NULL) {
                ERREP(err, fnname, "error opening the process memory file for reading");
                return err;
        }
        fseek(mem, off, SEEK_SET);
        if (fread(buf, sizeof(byte), blen, mem) != sizeof(byte) * blen && ferror(mem) != 0) {
                ERREP(err, fnname, "error reading from the process memory file");
                return err;
        }
        fclose(mem);
        ERREP(err, fnname, NULL);
        return err;
}

struct errep *jet_mem_write(byte *data, size_t dlen, pid_t p, qword off)
{         
        struct errep *err;
        char *fnname = "jet_mem_write()";
        FILE *mem;
        char fname[30];

        if (!data || dlen < 1 || p < 1 || off < 1) {
                ERREP(err, fnname, "this function was provided bad arguments");
                return err;
        }
        sprintf(fname, "/proc/%d/mem", p);
        if ((mem = fopen(fname, "wb")) == NULL) {
                ERREP(err, fnname, "error opening the process memory file for writing");
                return err;
        }
        fseek(mem, off, SEEK_SET);
        if (fwrite(data, sizeof(byte), dlen, mem) != sizeof(byte) * dlen) {
                ERREP(err, fnname, "error writing to the process memory file");
        }
        fclose(mem);
        ERREP(err, fnname, NULL);
        return err;
}
