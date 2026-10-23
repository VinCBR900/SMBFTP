/*
 * smbftp.h - shared definitions for smbftp.c, smb_engine.c and winsmbftp.c
 *
 * Version : 0.8 (kept in step with smbftp.c; SMBFTP_VERSION below is the one
 *           that is printed)
 * Usage   : not run directly; included by smbftp.c, smb_engine.c and
 *           winsmbftp.c. Build: see README.md.
 * History : 0.8  2026-10-23  version bump with smbftp.c 0.8 (graceful exit).
 *           0.7  2026-10-23  version bump with smbftp.c 0.7 (SMBFTP-main
 *                            merge); this file gained its version header,
 *                            taken from SMBFTP-main's smbftp.h.
 *           0.6  2026-10-13  Scan types (LocalAddr, ScanNet, IfInfo) and the
 *                            engine's shared declarations live here. SMBFTP-
 *                            main's 0.6 bumped only the version.
 *           0.5  2026-10-12  scan-mode (-S) types and constants.
 *           0.1-0.4          constants, Ctx and NtText split out of smbftp.c.
 *
 * Holds the includes, platform portability layer, constants and type
 * definitions that used to sit at the top of smbftp.c. Data tables and all
 * functions stay in smbftp.c (every function there is static).
 *
 * Windows with TCC: winport/winmini.h declares the few Win32/Winsock names
 * needed instead of the Windows SDK headers (TCC does not ship a complete set).
 * The same file serves the downloaded and patched libdsm sources (see build.cmd and
 * the Makefile), so these declarations exist in exactly one place.
 */
#ifndef SMBFTP_H
#define SMBFTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

/* Win32 / Winsock names: TCC mini declarations, or the real headers elsewhere */
#ifdef _WIN32
#include "winport/winmini.h"
#else
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* socket portability for scan mode */
#ifdef _WIN32
typedef SOCKET sock_t;
typedef int    sock_len_t;
#define SOCK_BAD        INVALID_SOCKET
#define sock_close(s)   closesocket(s)
#else
typedef int       sock_t;
typedef socklen_t sock_len_t;
#define SOCK_BAD        (-1)
#define sock_close(s)   close(s)
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include <bdsm/smb_session.h>
#include <bdsm/smb_share.h>
#include <bdsm/smb_stat.h>
#include <bdsm/smb_file.h>
#include <bdsm/smb_defs.h>

#define SMBFTP_VERSION  "0.8"

#define PATH_LEN        1024        /* remote and local path buffers          */
#define LINE_LEN        2048        /* command line buffer                    */
#define MAX_ARGS        16          /* tokens per command line                */
#define SHARE_LEN       80          /* share name buffer                      */
#define SERVER_LEN      48          /* server text buffer                     */
#define NBNAME_MAX      15          /* libdsm session name is char[16]        */
#define DEF_CHUNK       32768       /* default transfer chunk                 */
#define MIN_CHUNK       512
#define MAX_CHUNK       60000       /* libdsm caps reads/writes near 64 KiB   */
#define PROGRESS_STEP   (256 * 1024) /* redraw progress every this many bytes */

/* NT status codes not defined by libdsm's smb_defs.h */
#define NT_STATUS_BAD_NETWORK_NAME_X    0xc00000ccU
#define NT_STATUS_ACCOUNT_RESTRICTION_X 0xc000006eU
#define NT_STATUS_ACCOUNT_DISABLED_X    0xc0000072U

typedef struct {
    smb_session *sess;              /* libdsm session                         */
    smb_tid      tid;               /* tree id of the current share           */
    int          have_share;        /* non-zero when tid is valid             */
    char         server[SERVER_LEN];/* server address text, for display       */
    char         share[SHARE_LEN];  /* current share name                     */
    char         cwd[PATH_LEN];     /* remote dir: "" = root, else "\a\b"     */
    unsigned long chunk;            /* transfer chunk size in bytes           */
} Ctx;

typedef struct {
    uint32_t    code;
    const char *text;
} NtText;

/* ------------------------------------------------------------------------ */
/* Network scan (-S) definitions                                            */
/* ------------------------------------------------------------------------ */

#define SCAN_MAX_PAR     64         /* hosts probed at the same time          */
#define SCAN_MAX_LOCAL   32         /* local IPv4 addresses remembered        */
#define SCAN_MAX_NETS    16         /* networks scanned in one run            */
#define SCAN_MAX_HITS    1024       /* hosts reported                         */
#define SCAN_MIN_PREFIX  16         /* widest explicit network (65534 hosts)  */
#define SCAN_AUTO_PREFIX 22         /* auto mode clamps wider subnets to /24  */
#define DEF_WAIT_MS      1000       /* time limit per port probe              */
#define MIN_WAIT_MS      100
#define MAX_WAIT_MS      30000

/* probe stages (Job.state) */
enum { ST_FREE = 0, ST_CONNECT, ST_SESSRESP, ST_NEGRESP, ST_DONE };
/* probe results (Job.res[], Hit.res[]) */
enum { R_NONE = 0, R_OPEN, R_SMB1 };

typedef struct {
    uint32_t ip;                    /* host byte order                        */
    uint32_t mask;
} LocalAddr;

typedef struct {
    uint32_t net, first, last;      /* host byte order; first..last probed    */
    int      prefix;                /* prefix length actually scanned         */
    int      orig_prefix;           /* prefix of the adapter (auto mode)      */
} ScanNet;

typedef struct {
    const ScanNet   *nets;
    int              nn, ni, fresh;
    uint32_t         cur;
    const LocalAddr *la;            /* own addresses, never probed            */
    int              nl;
} TargetIter;

typedef struct {
    int           state;            /* ST_*                                   */
    uint32_t      ip;               /* host byte order                        */
    int           pidx;             /* 0 = tcp/445, 1 = tcp/139               */
    int           res[2];           /* R_* per port                           */
    sock_t        s;
    unsigned long deadline, wait;
    unsigned char rx[64];
    int           got;
} Job;

typedef struct {
    uint32_t ip;
    int      res[2];
} Hit;

#ifdef _WIN32
/* Winsock INTERFACE_INFO (SIO_GET_INTERFACE_LIST): flags, then address,
 * broadcast and netmask as 24-byte sockaddr_gen unions. For AF_INET the
 * address bytes sit at offset 4 (after family and port), network order. */
typedef struct {
    unsigned long flags;
    unsigned char addr[24];
    unsigned char bcast[24];
    unsigned char mask[24];
} IfInfo;

#define SMB_SIO_GET_INTERFACE_LIST  0x4004747FUL
#define SMB_IFF_UP                  0x00000001UL
#endif

#endif /* SMBFTP_H */
