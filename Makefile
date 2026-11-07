# GenPE - UEFI CA 2023 Secure Boot updater
# Cross-compile:  make            (needs x86_64-w64-mingw32-gcc + python3)
# 32-bit:         make x86        (needs i686-w64-mingw32-gcc)
# ARM64:          make arm64      (llvm-mingw: aarch64-w64-mingw32-clang;
#                                no distro mingw-w64 aarch64 package exists)

X64CC   ?= x86_64-w64-mingw32-gcc
X86CC   ?= i686-w64-mingw32-gcc
ARM64CC ?= aarch64-w64-mingw32-clang
CFLAGS   = -Os -Wall -Wextra -Wno-unused-parameter -Isrc
LDFLAGS  = -municode -static -s -Wl,--gc-sections
LIBS     = -ladvapi32 -luser32 -lgdi32 -lcomctl32
WINDRES64 ?= x86_64-w64-mingw32-windres
WINDRES32 ?= i686-w64-mingw32-windres
WINDRESARM ?= aarch64-w64-mingw32-windres

GEN      = src/generated/payloads.h src/generated/payloads.S

all: build/GenPE.exe

x86: build/GenPE32.exe

arm64: build/GenPE-arm64.exe

$(GEN): tools/embed.py payloads/kek_map.json
	python3 tools/embed.py

build/payloads64.o: src/generated/payloads.S | build
	$(X64CC) -c $< -o $@

build/payloads32.o: src/generated/payloads.S | build
	$(X86CC) -c $< -o $@

build/payloads-arm64.o: src/generated/payloads.S | build
	$(ARM64CC) -c $< -o $@

build/genpe64.res: src/genpe.rc src/genpe.manifest | build
	$(WINDRES64) -Isrc src/genpe.rc -O coff -o $@

build/genpe32.res: src/genpe.rc src/genpe.manifest | build
	$(WINDRES32) -Isrc src/genpe.rc -O coff -o $@

build/genpe-arm64.res: src/genpe.rc src/genpe.manifest | build
	$(WINDRESARM) -Isrc src/genpe.rc -O coff -o $@

build/GenPE.exe: src/genpe.c src/sha1.h src/generated/payloads.h build/payloads64.o build/genpe64.res | build
	$(X64CC) $(CFLAGS) -o $@ src/genpe.c build/payloads64.o build/genpe64.res $(LDFLAGS) $(LIBS)

build/GenPE32.exe: src/genpe.c src/sha1.h src/generated/payloads.h build/payloads32.o build/genpe32.res | build
	$(X86CC) $(CFLAGS) -o $@ src/genpe.c build/payloads32.o build/genpe32.res $(LDFLAGS) $(LIBS)

build/GenPE-arm64.exe: src/genpe.c src/sha1.h src/generated/payloads.h build/payloads-arm64.o build/genpe-arm64.res | build
	$(ARM64CC) $(CFLAGS) -o $@ src/genpe.c build/payloads-arm64.o build/genpe-arm64.res $(LDFLAGS) $(LIBS)

build:
	mkdir -p build

# native (Linux) build of the parsing + signature unit tests
test: build/test_parse build/test_sigcheck
	./build/test_parse
	./build/test_sigcheck

build/payloads_test.o: src/generated/payloads.S | build
	gcc -c $< -o $@

build/test_parse: tests/test_parse.c src/sigparse.h src/sha1.h src/generated/payloads.h build/payloads_test.o | build
	gcc -O0 -g -Isrc -o $@ tests/test_parse.c build/payloads_test.o

build/test_sigcheck: tests/test_sigcheck.c src/sigcheck.h src/bignum.h src/der.h src/sha1.h src/sha256.h | build
	gcc -O0 -g -Isrc -o $@ tests/test_sigcheck.c

clean:
	rm -rf build src/generated/payloads.h src/generated/payloads.S

.PHONY: all x86 arm64 clean test
