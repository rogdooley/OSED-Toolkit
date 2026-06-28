#include "mini_proto_vuln.h"

#include <stdio.h>

const char *opcode_name(uint16_t opcode)
{
    switch (opcode) {
    case OPCODE_PING:
        return "PING";
    case OPCODE_ECHO:
        return "ECHO";
    case OPCODE_COPY_PAYLOAD:
        return "COPY_PAYLOAD";
    default:
        return "UNKNOWN";
    }
}

const char *record_name(uint16_t type)
{
    switch (type) {
    case RECORD_METADATA:
        return "METADATA";
    case RECORD_COMMAND:
        return "COMMAND";
    case RECORD_PAYLOAD:
        return "PAYLOAD";
    default:
        return "UNKNOWN";
    }
}

void hexdump(const unsigned char *data, size_t length, size_t limit)
{
    size_t i;
    size_t count;

    count = length < limit ? length : limit;
    for (i = 0; i < count; ++i) {
        if ((i % 16U) == 0U) {
            printf("  %04lu:", (unsigned long)i);
        }

        printf(" %02x", data[i]);

        if ((i % 16U) == 15U || i + 1U == count) {
            size_t j;

            for (j = (i % 16U); j < 15U && i + 1U == count; ++j) {
                printf("   ");
            }

            printf("  ");
            {
                size_t line_start;
                size_t line_end;
                size_t k;

                line_start = i - (i % 16U);
                line_end = i + 1U;
                for (k = line_start; k < line_end; ++k) {
                    unsigned char ch = data[k];
                    putchar((ch >= 32U && ch <= 126U) ? (int)ch : '.');
                }
            }
            putchar('\n');
        }
    }

    if (count == 0U) {
        puts("  <empty>");
    } else if (length > count) {
        printf("  ... %lu bytes omitted ...\n", (unsigned long)(length - count));
    }
}
