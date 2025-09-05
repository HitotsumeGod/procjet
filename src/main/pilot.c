#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "procjet.h"

int main(int argc, char *argv[])
{
	byte daten[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (!jet_inject_pid_noptrace(daten, sizeof(daten), atoi(argv[1])))
		return false;
	return 0;
}
