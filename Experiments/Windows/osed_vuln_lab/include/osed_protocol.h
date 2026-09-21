#pragma once

#include <stdint.h>

#define OSED_MAGIC 0x4F534544u /* 'OSED' */

#define OSED_CONTROL_V1 0x0000u
#define OSED_CONTROL_STRUCTURED 0x0001u
#define OSED_CONTROL_V2 0x0200u
#define OSED_CONTROL_V2_RECORD (OSED_CONTROL_V2 | OSED_CONTROL_STRUCTURED)

#define OSED_RECORD_QUERY 0x0001u
#define OSED_RECORD_DATA 0x0002u

typedef enum OSED_OPCODE {
    OP_PING = 0x1000,
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
    uint16_t control;
    uint32_t length;
} OSED_PACKET_HEADER;

typedef struct OSED_SEH_RECORD {
    uint16_t type;
    uint16_t name_length;
    uint32_t data_length;
} OSED_SEH_RECORD;

typedef struct OSED_V2_RECORD {
    uint16_t kind;
    uint16_t options;
    uint32_t data_offset;
    uint32_t data_length;
} OSED_V2_RECORD;

typedef struct OSED_V2_RESULT {
    uint16_t status;
    uint16_t kind;
    uint32_t value;
} OSED_V2_RESULT;
#pragma pack(pop)
