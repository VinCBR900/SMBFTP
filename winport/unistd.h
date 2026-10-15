/* unistd.h stand-in for TCC builds: libdsm includes it unconditionally but
 * uses its POSIX contents only on non-Windows paths. TCC's own copy is
 * missing in some releases. */
#ifndef SMBFTP_WINPORT_UNISTD_H
#define SMBFTP_WINPORT_UNISTD_H
#include <io.h>
#include <process.h>
#endif
