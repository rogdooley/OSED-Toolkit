#include "lab_io.h"

#include <stdint.h>
#include <stdio.h>

__declspec(noinline) static void vulnerable_print(const char *format)
{
    printf(format,
        0x13572468u, 0xA1A2A3A4u, 0x51525354u, 0x41414141u,
        0x62626262u, 0x73737373u, 0x84848484u, 0x95959595u);
    putchar('\n');
}

int main(int argc, char **argv)
{
    char format[256];

    puts("FMT-01: stack argument survey");
    if (!read_format_string(argc, argv, format, sizeof(format))) {
        return 1;
    }
    vulnerable_print(format);
    return 0;
}
