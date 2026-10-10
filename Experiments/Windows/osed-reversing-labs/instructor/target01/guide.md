# Target 01 Instructor Guide

## Architecture

The executable is a loopback TCP service. Its receive helper obtains a fixed frame and then a body. The call path is `main -> handle_client -> receive_all/unmask -> relay`. The frame contains a marker, operation value, transformation key, received-body length, and a second length used after transformation.

## Analysis notes

The receive boundary constrains only the received-body length. After the byte-wise transformation, `relay` trusts the other length when copying into a smaller automatic buffer. Normal requests remain within that buffer. This is a stack overwrite primitive; DEP is enabled and ASLR is deliberately disabled. The build disables stack cookies to keep the frame visible. Exact compiler output and offsets must be established from the transferred build.

## Suggested hints

1. Start from Winsock imports and find the loop that consumes exactly N bytes.
2. Compare every header field used before and after the byte-wise loop.
3. Locate the `memcpy` destination and compare its stack allocation with the source of its count.

## Validation notes

Use valid requests first. Trigger reachability belongs to the instructor-only validation process; do not distribute a trigger or exploit with the student package.
