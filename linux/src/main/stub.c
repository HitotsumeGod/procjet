#include "procjet.h"

/*
 * mov 		rdi, 0xFFFFFFFF
 * call		rdi
 */
byte stub[] = {
			0xBF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xD7
		};

size_t get_stub_len(void)
{
	int i = 0;
	while (stub[i++] != 0xD7);
	return i;
}

void set_stub_dst(qword addr)
{
	stub[1] = (byte) ((addr & 0xF000) << 24);
	stub[2] = (byte) ((addr & 0x0F00) << 16);
	stub[3] = (byte) ((addr & 0x00F0) << 8);
	stub[4] = (byte) (addr & 0x000F);
}
