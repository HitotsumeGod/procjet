#include "winjet.h"
#include <stdio.h>
#include <stdlib.h>

#define MAXPROCS        512

HANDLE winjet_select_process(void)
{
        DWORD processes[MAXPROCS], res;
        HANDLE current;
        char cmdl[120];

        EnumProcesses(&processes, sizeof(processes), &res);
        //walk through discovered processes
        for (int i = 0; i < res / sizeof(DWORD); i++) {
                if (!(current = OpenProcess(PROCESS_QUERY_INFORMATION, false, processes[i]))
                        continue;
                QueryFullProcessImage(
                        current,
                        0,
                        cmdl,
                        sizeof(cmdl)
                );
                printf("%s\n", cmdl);
                CloseHandle(current);
        }
}