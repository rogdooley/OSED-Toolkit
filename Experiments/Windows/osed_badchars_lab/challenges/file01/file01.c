#include <stdint.h>
#include <string.h>

#include "io_helpers.h"
#include "stage_trace.h"

static uint8_t file01_received[4097];

static int file01_valid_record(const uint8_t *record, size_t record_length) {
    size_t payload_length;
    if (record_length < 9 || memcmp(record, "BCF1", 4) != 0 || record[4] != 1 || record[5] != 1) {
        return 0;
    }
    payload_length = (size_t)record[6] | ((size_t)record[7] << 8);
    return payload_length == record_length - 8;
}

int main(int argc, char **argv) {
    uint8_t *record = NULL;
    size_t record_length = 0;
    size_t payload_length;
    wchar_t path[MAX_PATH];
    char vulnerable_destination[128];
    int result = 1;

    if (argc != 2 || !MultiByteToWideChar(CP_ACP, 0, argv[1], -1, path, MAX_PATH) ||
        common_read_file_all(path, &record, &record_length, 4096) != COMMON_OK ||
        !file01_valid_record(record, record_length)) {
        goto cleanup;
    }
    payload_length = record_length - 8;
    memcpy(file01_received, record + 8, payload_length);
    file01_received[payload_length] = '\0';
    stage_trace_capture(STAGE_INITIAL_INPUT, file01_received, payload_length);
    stage_trace_capture(STAGE_PRE_TRANSFORM, file01_received, payload_length);
    /* Intentional lab operation: embedded NUL terminates this vulnerable copy. */
    strcpy(vulnerable_destination, (const char *)file01_received);
    stage_trace_capture(STAGE_FINAL_DESTINATION, (const uint8_t *)vulnerable_destination,
                        strlen(vulnerable_destination));
    result = 0;

cleanup:
    common_free_file_buffer(record);
    return result;
}
