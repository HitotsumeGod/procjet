#include "procjet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

byte daten[] = {
        0xB8, 0x3C, 0x00, 0x00,
        0x00, 0xBF, 0x48, 0x00,
        0x00, 0x00, 0x0F, 0x05
};

int main(int argc, char *argv[])
{
        struct errep *err;

        if ((err = jet_inject_pid(daten, sizeof(daten), atoi(argv[1]))) -> msg != NULL) {
                fprintf(stderr, "%s", ptools_format_errors(err));
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
