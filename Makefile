# Makefile - build smbftp on Linux (and other POSIX systems)
#
# Windows does not use this file: it builds with build.cmd and TCC only.
#
# Version : 1.1
# Usage   : make                release build -> ./smbftp
#           make DEBUG=1        -g -O0, libdsm's debug trace and asserts left on
#           make asan           AddressSanitizer + UBSan build -> ./smbftp-asan
#           make fetch          only download, verify and patch libdsm into ./libdsm
#           make test           tests/test_applydiff.sh, then a smoke test of ./smbftp
#           make clean          remove build objects and the binaries
#           make distclean      clean, and also ./libdsm and the download cache ./deps
#           CC=clang make       use another compiler (CC=tcc works too)
# Needs   : a C compiler, make, tar, curl or wget, sha256sum or shasum
#
# libdsm is not part of this source tree. The first build downloads the upstream
# commit named in patches/libdsm.cfg, checks its SHA-256, unpacks it into ./libdsm
# and applies patches/*.diff with tools/applydiff.c (the same tool build.cmd uses on
# Windows, so both builds patch identically). The libdsm sources compiled are listed
# in sources.lst. Changing the config or a patch re-creates ./libdsm automatically.
# An already downloaded deps/libdsm-<commit>.tar.gz is used as it is (offline builds).
#
# History : 1.1  2026-10-23  also builds smb_engine.c (the code that talks to libdsm,
#                shared with WinSMBFTP.exe, which is Windows-only and built by
#                build.cmd gui, not by this Makefile). "make test" runs
#                tests/test_applydiff.sh through bash, so it works even when a
#                zip has dropped the scripts' executable bit.
#           1.0  first version.

include patches/libdsm.cfg

HASH := \#
OUT    ?= smbftp
BUILD  ?= build
DEPS   := deps
LIBDSM := libdsm
STAMP  := $(LIBDSM)/.stamp
ARCHIVE   := $(DEPS)/libdsm-$(LIBDSM_COMMIT).tar.gz
APPLYDIFF := $(DEPS)/applydiff
PATCHES   := $(addprefix patches/,$(LIBDSM_PATCHES))
SHA256    := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

SRCS_DSM := $(shell tr -d '\r' < sources.lst | grep -v '^$(HASH)')
OBJS_DSM := $(patsubst %.c,$(BUILD)/dsm/%.o,$(SRCS_DSM))

ifdef SAN
  CFLAGS  = -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
  DEFS    = -DNDEBUG
else
ifdef DEBUG
  CFLAGS  = -g -O0
  DEFS    =
else
  CFLAGS  ?= -O2
  DEFS    = -DNDEBUG
endif
endif
LDLIBS ?= -lm

# -Ilinux first: it holds the config.h that libdsm includes (HAVE_CONFIG_H)
INCS    := -Ilinux -I. -I$(LIBDSM) -I$(LIBDSM)/include -I$(LIBDSM)/contrib -I$(LIBDSM)/compat
CPPALL   = -DHAVE_CONFIG_H=1 $(DEFS) $(INCS) $(CPPFLAGS)

.PHONY: all asan fetch test clean distclean
.DELETE_ON_ERROR:

all: $(OUT)

$(OUT): $(BUILD)/smbftp.o $(BUILD)/smb_engine.o $(OBJS_DSM)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/smbftp.o: smbftp.c smbftp.h smb_engine.h linux/config.h $(STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPALL) -c -o $@ smbftp.c

$(BUILD)/smb_engine.o: smb_engine.c smb_engine.h smbftp.h linux/config.h $(STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPALL) -c -o $@ smb_engine.c

# libdsm objects: ./libdsm only changes when $(STAMP) is rewritten, so that is the dependency.
# (libdsm's own warnings are not ours to fix: -w)
$(BUILD)/dsm/%.o: $(STAMP) linux/config.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPALL) -w -c -o $@ $(LIBDSM)/$*.c

asan:
	$(MAKE) SAN=1 BUILD=build-asan OUT=smbftp-asan

fetch: $(STAMP)

$(APPLYDIFF): tools/applydiff.c
	@mkdir -p $(DEPS)
	$(CC) -O2 -o $@ tools/applydiff.c

# Download (if not cached), verify, unpack into a staging folder, patch there, and only
# then move it to ./libdsm, so a failed run never leaves a half-patched ./libdsm behind.
$(STAMP): patches/libdsm.cfg $(PATCHES) $(APPLYDIFF)
	@set -e; \
	if [ -d $(LIBDSM) ] && [ ! -f $(STAMP) ]; then \
	  echo "[fetch] ./$(LIBDSM) exists but was not made by this Makefile (no $(STAMP))." >&2; \
	  echo "[fetch] Move it away (or: make distclean) so it can be downloaded and patched again." >&2; \
	  exit 1; \
	fi; \
	mkdir -p $(DEPS); \
	if [ ! -f $(ARCHIVE) ]; then \
	  echo "[fetch] $(LIBDSM_URL)"; \
	  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o $(ARCHIVE).part '$(LIBDSM_URL)'; \
	  elif command -v wget >/dev/null 2>&1; then wget -q -O $(ARCHIVE).part '$(LIBDSM_URL)'; \
	  else echo "[fetch] need curl or wget, or put the file at $(ARCHIVE)" >&2; exit 1; fi; \
	  mv $(ARCHIVE).part $(ARCHIVE); \
	fi; \
	if ! echo "$(LIBDSM_SHA256)  $(ARCHIVE)" | $(SHA256) -c - >/dev/null 2>&1; then \
	  echo "[fetch] SHA-256 of $(ARCHIVE) does not match patches/libdsm.cfg" >&2; \
	  echo "[fetch]   expected $(LIBDSM_SHA256)" >&2; \
	  echo "[fetch]   got      $$($(SHA256) $(ARCHIVE) | cut -d' ' -f1)" >&2; \
	  rm -f $(ARCHIVE); exit 1; \
	fi; \
	rm -rf $(DEPS)/stage; mkdir -p $(DEPS)/stage; \
	tar -xzf $(ARCHIVE) -C $(DEPS)/stage; \
	for p in $(LIBDSM_PATCHES); do \
	  echo "[patch] $$p"; \
	  $(APPLYDIFF) -p1 -d $(DEPS)/stage/libdsm-$(LIBDSM_COMMIT) patches/$$p >/dev/null || exit 1; \
	done; \
	rm -rf $(LIBDSM); \
	mv $(DEPS)/stage/libdsm-$(LIBDSM_COMMIT) $(LIBDSM); \
	rm -rf $(DEPS)/stage; \
	echo "$(LIBDSM_COMMIT) $(LIBDSM_PATCHES)" > $(STAMP)

test: $(OUT)
	CC="$(CC)" bash tests/test_applydiff.sh
	./$(OUT) -h >/dev/null 2>&1
	./$(OUT) -S 127.0.0.1 >/dev/null 2>&1
	@echo "smoke test passed (the server test matrix is tests/run_all.sh)"

clean:
	rm -rf build build-asan smbftp smbftp-asan

distclean: clean
	rm -rf $(LIBDSM) $(DEPS)
