#include "lab_io.h"

#include <stdio.h>
#include <string.h>

int read_format_string(int argc, char **argv, char *buffer, size_t capacity)
{
    FILE *input;
    size_t length;

    if (capacity < 2) {
        return 0;
    }

    if (argc == 2) {
        if (fopen_s(&input, argv[1], "rb") != 0) {
            fprintf(stderr, "[-] Could not open input file: %s\n", argv[1]);
            return 0;
        }
        length = fread(buffer, 1, capacity - 1, input);
        fclose(input);
        buffer[length] = '\0';
    } else {
        printf("format> ");
        if (fgets(buffer, (int)capacity, stdin) == NULL) {
            return 0;
        }
    }

    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] == '\0') {
        fprintf(stderr, "[-] Empty format string.\n");
        return 0;
    }
    return 1;
}
