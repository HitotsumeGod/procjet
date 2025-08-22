#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "procjet.h"

size_t mem_read(byte *buf, size_t blen, pid_t p, qword off)
{
	FILE *mem;
	char fname[30];
	size_t amou;

	if (!buf || blen < 1 || p < 1 || off < 1) {
		errno = BAD_ARGS_ERR;
		PRINT_CERR("mem_overwrite()");
		return 0;
	}
	sprintf(fname, "/proc/%d/mem", p);
	if ((mem = fopen(fname, "rb")) == NULL) {
		perror("fopen() err");
		return 0;
	}
	fseek(mem, off, SEEK_SET);
	if ((amou = fread(buf, sizeof(byte), blen, mem)) != sizeof(byte) * blen && ferror(mem) != 0) {
		perror("fwrite() error");
		return 0;
	}
	fclose(mem);
	return amou;

}
size_t mem_write(byte *data, size_t dlen, pid_t p, qword off)
{
	FILE *mem;
	char fname[30];
	size_t amou;

	if (!data || dlen < 1 || p < 1 || off < 1) {
		errno = BAD_ARGS_ERR;
		PRINT_CERR("mem_overwrite()");
		return 0;
	}
	sprintf(fname, "/proc/%d/mem", p);
	if ((mem = fopen(fname, "wb")) == NULL) {
		perror("fopen() err");
		return 0;
	}
	fseek(mem, off, SEEK_SET);
	if ((amou = fwrite(data, sizeof(byte), dlen, mem)) != sizeof(byte) * dlen) {
		perror("fwrite() error");
		return 0;
	}
	fclose(mem);
	return amou;
}
