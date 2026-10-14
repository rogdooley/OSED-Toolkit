#include "stage_trace.h"

#ifdef BADCHARS_INSTRUCTOR_TRACE
#include <windows.h>

void stage_trace_capture(enum stage_id stage, const uint8_t *bytes, size_t length) {
    char message[96];
    unsigned int first = length == 0 ? 0U : bytes[0];
    wsprintfA(message, "badchars stage=%u length=%zu first=%02X\n", (unsigned int)stage,
              length, first);
    OutputDebugStringA(message);
}
#else
void stage_trace_capture(enum stage_id stage, const uint8_t *bytes, size_t length) {
    (void)stage;
    (void)bytes;
    (void)length;
}
#endif
