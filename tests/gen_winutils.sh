#!/bin/sh
# gen_winutils.sh - extract the REAL Windows branch of libdsm's smb_utils.c so it can be compiled on Linux
#
# Version : 1.0
# Usage   : gen_winutils.sh <srcdir> <outfile> [codepage]
#             srcdir   = tree holding libdsm/src/smb_utils.c (the "#ifdef _WIN32" ... "#else" part is used)
#             outfile  = generated C file (compile with winshim/winshim.c)
#             codepage = SMB_WIN_CODEPAGE value, 0 (ANSI, default) or 65001 (UTF-8)
# History : 1.0  first version.
SRC="$1"; OUT="$2"; CP="${3:-0}"
{
echo '#include "config.h"'
echo '#include <assert.h>'
echo '#include <stdio.h>'
echo '#include <stdlib.h>'
echo '#include <string.h>'
echo '#include <errno.h>'
echo '#include "winshim.h"'
echo '#include "bdsm_debug.h"'
echo '#include "smb_utils.h"'
echo "#define SMB_WIN_CODEPAGE $CP"
sed -n '/^#ifdef _WIN32$/,/^#else   \/\* !_WIN32: iconv \*\//p' "$SRC/libdsm/src/smb_utils.c" | sed -e '1d' -e '$d'
} > "$OUT"
