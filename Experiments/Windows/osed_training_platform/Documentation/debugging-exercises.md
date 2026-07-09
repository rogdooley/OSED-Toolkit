# Debugging Exercises

These exercises are for the safe design phase.

## Exercise 1: find the hot path

- Break on `ws2_32!recv`.
- Step to the first application function.
- Write down the exact packet fields that are validated before dispatch.

Success criterion:

- you can explain which bytes matter and which bytes are just envelope data

## Exercise 2: prove a path is safe

- Follow one suspicious string copy in the auth or config path.
- Confirm the destination buffer size.
- Confirm the explicit length guard.

Success criterion:

- you can justify why the copy is not the bug

## Exercise 3: map the modules

- Record the base addresses of the service, helper DLL, and gadget DLL.
- Note which modules are fixed-base and which are ASLR-enabled.

Success criterion:

- you can explain which module would be a stable gadget source in each build
  profile

## Exercise 4: prepare the offset workflow

- Build a cyclic pattern generator in the client/tooling layer.
- Send only benign packets.
- Record how you would detect an overwrite once the bug exists.

Success criterion:

- the workflow is ready before the vulnerability is added
