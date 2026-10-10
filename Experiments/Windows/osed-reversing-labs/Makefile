CC := i686-w64-mingw32-gcc
PYTHON ?= python3
DIST := dist
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O0 -fno-omit-frame-pointer -fno-stack-protector -s
LDFLAGS := -Wl,--nxcompat -Wl,--no-insert-timestamp
TARGETS := $(DIST)/target01.exe $(DIST)/target02.exe $(DIST)/target03.exe

.PHONY: all clean validate student-package toolchain-check
all: toolchain-check $(TARGETS)
toolchain-check:
	@$(CC) -dumpmachine | grep -Eq '^i[3-6]86-w64-mingw32' || (echo "error: install an i686-w64-mingw32 GCC toolchain; refusing a non-x86 build" && exit 1)
$(DIST):
	mkdir -p $@
$(DIST)/target01.exe: src/target01/main.c | $(DIST)
	$(CC) $(CFLAGS) -o $@ $< -lws2_32 $(LDFLAGS) -Wl,--disable-dynamicbase
$(DIST)/target02.exe: src/target02/main.c | $(DIST)
	$(CC) $(CFLAGS) -o $@ $< -lws2_32 $(LDFLAGS) -Wl,--dynamicbase
$(DIST)/target03.exe: src/target03/main.c | $(DIST)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -Wl,--disable-dynamicbase
validate: all
	$(PYTHON) tests/validate.py --dist $(DIST)
student-package: all
	rm -rf student/package
	mkdir -p student/package
	cp $(TARGETS) student/package/
	cp student/target01/README.md student/target02/README.md student/target03/README.md student/package/
	$(PYTHON) tests/make_sample.py student/package/sample.rvf
clean:
	rm -rf $(DIST) student/package
