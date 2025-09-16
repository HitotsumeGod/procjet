#include "winjet.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#define MAXPROCS        512

HANDLE winjet_select_process(void)
{
        DWORD processes[MAXPROCS], res;
        HANDLE current;
        char cmdl[120];
        DWORD cmdlen = sizeof(cmdl);

        EnumProcesses(processes, sizeof(processes), &res);
        //walk through discovered processes
        for (int i = 0; i < res / sizeof(DWORD); i++) {
                if (!(current = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processes[i])))
                        continue;
                QueryFullProcessImageName(
                        current,
                        0,
                        cmdl,
                        &cmdlen
                );
                printf("%s\n", cmdl);
                CloseHandle(current);
        }
}

void winjet_enum_processes(FILE *out)
{
        HANDLE snapshot;
        PROCESSENTRY32 current;

        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        memset(&current, 0, sizeof(current));
        current.dwSize = sizeof(PROCESSENTRY32);
        Process32First(snapshot, &current);
        fprintf(out, "Process %s\n", current.szExeFile);
        fprintf(out, "ID : %d\n", current.th32ProcessID);
        fprintf(out, "Parent ID: %d\n", current.th32ParentProcessID);
        fprintf(out, "Number of Threads : %d\n", current.cntThreads);
        while (Process32Next(snapshot, &current)) {
                fprintf(out, "Process %s\n", current.szExeFile);
                fprintf(out, "ID : %d\n", current.th32ProcessID);
                fprintf(out, "Parent ID: %d\n", current.th32ParentProcessID);
                fprintf(out, "Number of Threads : %d\n", current.cntThreads);
                memset(&current, 0, sizeof(current));
                current.dwSize = sizeof(PROCESSENTRY32);
        }
        CloseHandle(snapshot);
}