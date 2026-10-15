/*
 * config.h - hand-written libdsm configuration for the TCC / Windows build
 *
 * libdsm normally generates this file with meson from config.h.meson. Meson,
 * autotools and the feature probes they run are not used here: the answers for
 * a TCC-on-Windows target are fixed, so they are simply written down. build.cmd
 * puts this folder first on the include path, so every libdsm source that does
 * #include "config.h" gets this file.
 *
 * Deliberately NOT defined (so the compat sources are built instead):
 *   HAVE_STRLCPY, HAVE_STRNDUP      -> compat\strlcpy.c, compat\strndup.c
 * Not defined because the feature is absent or unused on this target:
 *   HAVE_PIPE, HAVE_SYS_TIME_H, HAVE_ARPA_INET_H, HAVE_SYS_SOCKET_H,
 *   HAVE_IFADDRS_H, HAVE_ALLOCA_H, HAVE_NL_LANGINFO, HAVE_SYS_QUEUE_H, HAVE_ICONV
 *   (iconv is replaced by the Win32 code in smb_utils.c)
 */
#ifndef BDSM_WINPORT_CONFIG_H
#define BDSM_WINPORT_CONFIG_H

#define PACKAGE         "libdsm"
#define PACKAGE_NAME    "libdsm"
#define PACKAGE_VERSION "0.4.3"
#define VERSION         "0.4.3"

/*
 * System headers that mention off_t are included here, before
 * include/bdsm/smb_types.h redefines off_t as a 64-bit type (TCC's off_t is a
 * 32-bit long). Once a header has been included its include guard keeps it from
 * being processed again under the new definition.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* compat\strlcpy.c and compat\strndup.c are built; declare them */
size_t strlcpy(char *dst, const char *src, size_t siz);
char  *strndup(const char *str, size_t n);

#endif
