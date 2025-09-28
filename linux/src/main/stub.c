#include "procjet.h"

/*
 * mov 		rax, 0xFFFFFFFF
 * jmp              rax
 */
byte stub[] = { 0x48, 0xB8, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xE0 };

size_t get_stub_len(void)
{
	int i = 0;
	while (stub[i++] != 0xE0);
	return i;
}

void set_stub_dst(qword addr)
{
        asm ("mov %1, 2(%0)"
                :  
                : "r" (stub), "r" (addr));


