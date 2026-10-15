#!/bin/sh
# build_linux.sh - test-harness build of smbftp + the bundled libdsm on Linux
#
# Version : 1.2
# Usage   : [EXTRA_DEFS="-DNDEBUG"] build_linux.sh <srcdir> <outbin> [asan|plain|valgrind]
#             srcdir  = project tree holding smbftp.c, sources.lst, linux/ and the fetched libdsm/
#                       (run "make fetch" there first; run_all.sh does it for you)
#             asan    = -fsanitize=address,undefined (UBSan is recoverable: reports, keeps going)
#             plain   = -O2, no sanitizers (shows what a normal build does)
#             valgrind= -O0 -g for valgrind runs
#             EXTRA_DEFS="-DNDEBUG" removes libdsm's debug trace (as build.cmd release does)
# History : 1.2  source list from sources.lst, config.h from linux/ (was tests/linuxcfg);
#                compat/strlcpy.c and compat/strndup.c are built, as in every other build.
#           1.1  UBSan recoverable; EXTRA_DEFS instead of BDSM_DEBUG.
#           1.0  first version.
SRC="$1"; OUT="$2"; MODE="${3:-asan}"
HERE="$(cd "$(dirname "$0")" && pwd)"
case "$MODE" in
  asan)     FL="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined" ;;
  plain)    FL="-g -O2" ;;
  valgrind) FL="-g -O0" ;;
esac
FILES=""
for f in $(grep -v '^#' "$SRC/sources.lst" | tr -d '\r'); do FILES="$FILES $SRC/libdsm/$f"; done
gcc $FL -w -DHAVE_CONFIG_H=1 ${EXTRA_DEFS} \
  -I"$SRC/linux" -I"$SRC" -I"$SRC/libdsm" -I"$SRC/libdsm/include" -I"$SRC/libdsm/contrib" -I"$SRC/libdsm/compat" \
  -o "$OUT" "$SRC/smbftp.c" $FILES -lm 2>&1
