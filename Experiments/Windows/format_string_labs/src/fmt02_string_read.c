#include "lab_io.h"

#include <stdio.h>

static char decoy[] = "DECOY: this is not the protected record";
static char protected_record[] = "LAB_SECRET=argument_consumption_is_state";

__declspec(noinline) static void vulnerable_print(const char *format)
{
    printf(format,
        0x11111111u, 0x22222222u, decoy, 0x44444444u,
        0x55555555u, protected_record, 0x77777777u, 0x88888888u);
    putchar('\n');
}

int main(int argc, char **argv)
{
    char format[256];

    puts("FMT-02: pointer-directed string disclosure");
    if (!read_format_string(argc, argv, format, sizeof(format))) {
        return 1;
    }
    vulnerable_print(format);
    return 0;
}
