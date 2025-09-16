#ifndef __WINJET_H__
#define __WINJET_H__

#include <windows.h>
#include <stdio.h>

extern HANDLE winjet_select_process(void);
extern void winjet_enum_processes(FILE *outfile);

#endif //__WINJET_H__
