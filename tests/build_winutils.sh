#!/bin/sh
# build_winutils.sh - like build_linux.sh, but smb_utils.c is replaced by the REAL Windows
#                     (MultiByteToWideChar / WideCharToMultiByte) branch running on a Linux shim,
#                     so ASan can check the conversion code that the Windows/TCC build uses.
#
# Version : 1.2
# Usage   : [WIN_FL="-g -O2"] [EXTRA_DEFS=...] build_winutils.sh <srcdir> <outbin> [codepage 0|65001]
#             WIN_FL overrides the default sanitizer flags (use "-g -O2" for a no-ASan build)
# History : 1.2  source list from sources.lst (without smb_utils.c), config.h from $SRC/linux.
#           1.1  WIN_FL override; libdsm/src on the include path.
#           1.0  first version.
SRC="$1"; OUT="$2"; CP="${3:-0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/gen_winutils.sh" "$SRC" "$HERE/winshim/smb_utils_win_$CP.c" "$CP"
FL="${WIN_FL:--g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined}"
FILES=""
for f in $(grep -v '^#' "$SRC/sources.lst" | tr -d '\r' | grep -v '^src/smb_utils\.c$'); do FILES="$FILES $SRC/libdsm/$f"; done
gcc $FL -w -DHAVE_CONFIG_H=1 -DNDEBUG ${EXTRA_DEFS} \
  -I"$SRC/linux" -I"$HERE/winshim" -I"$SRC" -I"$SRC/libdsm" -I"$SRC/libdsm/include" -I"$SRC/libdsm/contrib" -I"$SRC/libdsm/compat" -I"$SRC/libdsm/src" \
  -o "$OUT" "$SRC/smbftp.c" $FILES "$HERE/winshim/smb_utils_win_$CP.c" "$HERE/winshim/winshim.c" -lm 2>&1
