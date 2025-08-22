#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "procjet.h"

int main(int argc, char *argv[])
{
	byte buffer[10], corebuf[10], daten[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
	pid_t pid;
	qword offset;

	pid = atoi(argv[1]);
	offset = strtol(argv[2], NULL, 16);
	if (mem_read(buffer, sizeof(buffer), pid, offset) <= 0)
		return -1;
	printf("%s", "Original read ----> ");
	for (int i = 0; i < sizeof(buffer); i++)
		printf("%02X ", buffer[i]);
	printf("\n");
	if (mem_write(daten, sizeof(daten), pid, offset) <= 0)
		return -1;
	memcpy(corebuf, buffer, sizeof(corebuf));
	if (mem_read(buffer, sizeof(buffer), pid, offset) <= 0)
		return -1;
	printf("%s", "Read after write ----> ");
	for (int i = 0; i < sizeof(buffer); i++)
		printf("%02X ", buffer[i]);
	printf("\n");
	if (mem_write(corebuf, sizeof(corebuf), pid, offset) <= 0)
		return -1;
	if (mem_read(buffer, sizeof(buffer), pid, offset) <= 0)
		return -1;
	printf("%s", "Read after replace ----> ");
	for (int i = 0; i < sizeof(buffer); i++)
		printf("%02X ", buffer[i]);
	printf("\n");
	return 0;
}
