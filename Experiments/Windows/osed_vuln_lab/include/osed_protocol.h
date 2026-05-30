#pragma once

#include <stdint.h>

#define OSED_MAGIC 0x4F534544u /* 'OSED' */

typedef enum OSED_OPCODE {
    OP_STACK = 0x1001,
    OP_SEH = 0x1002,
    OP_SMALLBUF = 0x1003,
    OP_LEAK = 0x1004,
    OP_ROP = 0x1005
} OSED_OPCODE;

#pragma pack(push, 1)
typedef struct OSED_PACKET_HEADER {
    uint32_t magic;
    uint16_t opcode;
    uint16_t reserved;
    uint32_t length;
} OSED_PACKET_HEADER;
#pragma pack(pop)
