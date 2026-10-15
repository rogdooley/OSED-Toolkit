#include <stdint.h>
#include <string.h>

#include "io_helpers.h"
#include "stage_trace.h"

static int file02_valid_record(const uint8_t *record, size_t record_length) {
    size_t payload_length;
    if (record_length < 9 || memcmp(record, "BCF2", 4) != 0 || record[4] != 1 || record[5] != 1) {
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
    size_t index;
    wchar_t path[MAX_PATH];
    int result = 1;

    if (argc != 2 || !MultiByteToWideChar(CP_ACP, 0, argv[1], -1, path, MAX_PATH) ||
        common_read_file_all(path, &record, &record_length, 4096) != COMMON_OK ||
        !file02_valid_record(record, record_length)) {
        goto cleanup;
    }
    payload_length = record_length - 8;
    decoded = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, payload_length);
    if (decoded == NULL) {
        goto cleanup;
    }
    stage_trace_capture(STAGE_INITIAL_INPUT, record + 8, payload_length);
    for (index = 0; index < payload_length; ++index) {
        decoded[index] = record[8 + index] ^ 0x23;
    }
    stage_trace_capture(STAGE_POST_TRANSFORM, decoded, payload_length);
    stage_trace_capture(STAGE_FINAL_DESTINATION, decoded, payload_length);
    result = 0;

cleanup:
    if (decoded != NULL) {
        HeapFree(GetProcessHeap(), 0, decoded);
    }
    common_free_file_buffer(record);
    return result;
}
