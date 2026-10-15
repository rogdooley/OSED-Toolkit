#include <stdint.h>
#include <string.h>

#include "io_helpers.h"
#include "stage_trace.h"

static int file03_valid_record(const uint8_t *record, size_t record_length) {
    size_t payload_length;
    if (record_length < 9 || memcmp(record, "BCF3", 4) != 0 || record[4] != 1 || record[5] != 1) {
        return 0;
    }
    payload_length = (size_t)record[6] | ((size_t)record[7] << 8);
    return payload_length == record_length - 8;
}

int main(int argc, char **argv) {
    uint8_t *record = NULL;
    uint8_t *decoded = NULL;
    size_t record_length = 0;
    size_t payload_length;
    size_t input_index = 0;
    size_t output_length = 0;
    wchar_t path[MAX_PATH];
    uint8_t stack_stage[256];
    int result = 1;

    if (argc != 2 || !MultiByteToWideChar(CP_ACP, 0, argv[1], -1, path, MAX_PATH) ||
        common_read_file_all(path, &record, &record_length, 4096) != COMMON_OK ||
        !file03_valid_record(record, record_length)) {
        goto cleanup;
    }
    payload_length = record_length - 8;
    decoded = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, payload_length);
    if (decoded == NULL) {
        goto cleanup;
    }
    stage_trace_capture(STAGE_INITIAL_INPUT, record + 8, payload_length);
    stage_trace_capture(STAGE_PRE_TRANSFORM, record + 8, payload_length);
    while (input_index < payload_length) {
        uint8_t kind, count;
        size_t item;
        int escaped = 0;
        if (payload_length - input_index < 2) goto cleanup;
        kind = record[8 + input_index++]; count = record[8 + input_index++];
        if (count > payload_length - input_index) goto cleanup;
        for (item = 0; item < count; ++item) {
            uint8_t value = record[8 + input_index++];
            if ((kind & 1) && escaped) { decoded[output_length++] = value ^ 0x20; escaped = 0; }
            else if ((kind & 1) && value == '\\') escaped = 1;
            else decoded[output_length++] = value;
        }
        if (escaped) decoded[output_length++] = '\\';
    }
    stage_trace_capture(STAGE_POST_TRANSFORM, decoded, output_length);
    if (output_length > sizeof(stack_stage)) {
        output_length = sizeof(stack_stage);
    }
    memcpy(stack_stage, decoded, output_length);
    stage_trace_capture(STAGE_FINAL_DESTINATION, stack_stage, output_length);
    result = 0;

cleanup:
    if (decoded != NULL) {
        HeapFree(GetProcessHeap(), 0, decoded);
    }
    common_free_file_buffer(record);
    return result;
}
