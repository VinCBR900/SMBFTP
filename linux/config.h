/*
 * config.h - libdsm configuration for the Linux build of smbftp (Makefile, tests/)
 *            The Windows build uses winport/config.h instead.
 *
 * Version : 1.1
 * Usage   : put first on the include path (-Ilinux) together with -DHAVE_CONFIG_H=1
 * History : 1.1  moved from tests/linuxcfg to linux/ (used by the Makefile);
 *                HAVE_STRLCPY / HAVE_STRNDUP no longer claimed: glibc before 2.38 has
 *                no strlcpy, so compat/strlcpy.c and compat/strndup.c are always built
 *                (they are in sources.lst), exactly as on Windows.
 *         1.0  first version (iconv, nl_langinfo, pipe abort context, /dev/urandom)
 */
#ifndef SMBFTP_LINUX_CONFIG_H
#define SMBFTP_LINUX_CONFIG_H
#define _GNU_SOURCE 1
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#define PACKAGE "libdsm"
#define PACKAGE_VERSION "0.4.3"
#define VERSION "0.4.3"
#define HAVE_ICONV 1
#define HAVE_NL_LANGINFO 1
#define HAVE_ARPA_INET_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_PIPE 1
#define HAVE_SYS_QUEUE_H 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_CLOCKID_T 1
#define HAVE_DECL_CLOCK_MONOTONIC 1
#define HAVE_STRUCT_TIMESPEC 1
#define URANDOM "/dev/urandom"
#ifndef closesocket
#define closesocket(fd) close(fd)
#endif
#endif
