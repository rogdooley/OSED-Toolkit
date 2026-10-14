#pragma once

#include <stddef.h>
#include <stdint.h>

enum stage_id {
    STAGE_INITIAL_INPUT = 1,
    STAGE_PRE_TRANSFORM = 2,
    STAGE_POST_TRANSFORM = 3,
    STAGE_FINAL_DESTINATION = 4,
};

void stage_trace_capture(enum stage_id stage, const uint8_t *bytes, size_t length);
