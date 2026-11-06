# GenPE - UEFI CA 2023 Secure Boot updater
# Cross-compile:  make            (needs x86_64-w64-mingw32-gcc + python3)
# 32-bit:         make x86        (needs i686-w64-mingw32-gcc)

X64CC   ?= x86_64-w64-mingw32-gcc
X86CC   ?= i686-w64-mingw32-gcc
CFLAGS   = -Os -Wall -Wextra -Wno-unused-parameter -Isrc
LDFLAGS  = -municode -static -s -Wl,--gc-sections
LIBS     = -ladvapi32

GEN      = src/generated/payloads.h src/generated/payloads.S

all: build/GenPE.exe

x86: build/GenPE32.exe

$(GEN): tools/embed.py payloads/kek_map.json
	python3 tools/embed.py

build/payloads64.o: src/generated/payloads.S | build
	$(X64CC) -c $< -o $@

build/payloads32.o: src/generated/payloads.S | build
	$(X86CC) -c $< -o $@

build/GenPE.exe: src/genpe.c src/sha1.h src/generated/payloads.h build/payloads64.o | build
	$(X64CC) $(CFLAGS) -o $@ src/genpe.c build/payloads64.o $(LDFLAGS) $(LIBS)

build/GenPE32.exe: src/genpe.c src/sha1.h src/generated/payloads.h build/payloads32.o | build
	$(X86CC) $(CFLAGS) -o $@ src/genpe.c build/payloads32.o $(LDFLAGS) $(LIBS)

build:
	mkdir -p build

# native (Linux) build of the parsing unit test against real payloads
test: build/test_parse
	./build/test_parse

build/payloads_test.o: src/generated/payloads.S | build
	gcc -c $< -o $@

build/test_parse: tests/test_parse.c src/sigparse.h src/sha1.h src/generated/payloads.h build/payloads_test.o | build
	gcc -O0 -g -Isrc -o $@ tests/test_parse.c build/payloads_test.o

clean:
	rm -rf build src/generated/payloads.h src/generated/payloads.S

.PHONY: all x86 clean test
