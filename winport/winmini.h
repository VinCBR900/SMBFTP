/*
 * winmini.h - Windows / Winsock declarations for builds with TCC (tcc.exe)
 *
 * Purpose
 *   TCC (at least the released 0.9.27 Windows package) does not ship a usable
 *   winsock2.h chain or a ws2_32 import library. This header declares the few
 *   Win32 / Winsock names that smbftp and the bundled libdsm sources use, so
 *   neither needs the Windows SDK headers. It is the single source of these
 *   declarations: smbftp.h includes it, and winsock2.h / ws2tcpip.h in this
 *   folder (which libdsm's #include <winsock2.h> finds first) forward to it.
 *
 *   With any other Windows compiler (MinGW, MSVC) the real winsock2.h and
 *   windows.h are included instead. Define SMBFTP_MINI_WINAPI yourself to force
 *   the declarations below.
 *
 * Link requirements (see build.cmd)
 *   ws2_32 : winsock functions        -> winport\ws2_32.def (supplied)
 *   kernel32 / msvcrt                 -> shipped with TCC
 */
#ifndef SMBFTP_WINMINI_H
#define SMBFTP_WINMINI_H

#ifndef _WIN32
#error winmini.h is for Windows builds only
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(__TINYC__) && !defined(SMBFTP_MINI_WINAPI)
#define SMBFTP_MINI_WINAPI
#endif

#ifdef SMBFTP_MINI_WINAPI

#define FD_SETSIZE      128         /* scan mode: sockets per select() set    */
#define SMB_STDCALL     __stdcall
typedef uintptr_t       SOCKET;
typedef unsigned int    u_int;
typedef unsigned long   u_long;     /* 32 bits on Win32 and Win64             */
#define INVALID_SOCKET  (~(SOCKET)0)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define SOL_SOCKET      0xFFFF
#define SO_ERROR        0x1007
#define FIONBIO         ((long)0x8004667EUL)
#define WSAEWOULDBLOCK  10035
#define WSAEINPROGRESS  10036
#define MAKEWORD(a, b)  ((unsigned short)(((unsigned char)(a)) | (((unsigned short)((unsigned char)(b))) << 8)))
struct in_addr      { uint32_t s_addr; };
struct sockaddr     { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_in  { short sin_family; unsigned short sin_port; struct in_addr sin_addr; char sin_zero[8]; };
#ifndef _TIMEVAL_DEFINED            /* <time.h> may already define it        */
#define _TIMEVAL_DEFINED
struct timeval      { long tv_sec; long tv_usec; };
#endif
typedef struct      { u_int fd_count; SOCKET fd_array[FD_SETSIZE]; } fd_set;
typedef struct      { char opaque[512]; } WSADATA;      /* real size 400/408 */
#define FD_ZERO(set)        ((set)->fd_count = 0)
#define FD_SET(fd, set)     do { if ((set)->fd_count < FD_SETSIZE) \
                                 (set)->fd_array[(set)->fd_count++] = (SOCKET)(fd); } while (0)
#define FD_ISSET(fd, set)   smb_fd_isset((SOCKET)(fd), (set))
int            SMB_STDCALL WSAStartup(unsigned short, WSADATA *);
int            SMB_STDCALL WSACleanup(void);
int            SMB_STDCALL WSAGetLastError(void);
int            SMB_STDCALL WSAIoctl(SOCKET, unsigned long, void *, unsigned long, void *,
                                    unsigned long, unsigned long *, void *, void *);
SOCKET         SMB_STDCALL socket(int, int, int);
int            SMB_STDCALL connect(SOCKET, const struct sockaddr *, int);
int            SMB_STDCALL send(SOCKET, const void *, int, int);
int            SMB_STDCALL recv(SOCKET, void *, int, int);
int            SMB_STDCALL closesocket(SOCKET);
int            SMB_STDCALL ioctlsocket(SOCKET, long, u_long *);
int            SMB_STDCALL select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
int            SMB_STDCALL getsockopt(SOCKET, int, int, void *, int *);
u_long         SMB_STDCALL htonl(u_long);
u_long         SMB_STDCALL ntohl(u_long);
unsigned short SMB_STDCALL htons(unsigned short);
unsigned short SMB_STDCALL ntohs(unsigned short);
unsigned long  SMB_STDCALL GetTickCount(void);
unsigned long  SMB_STDCALL GetCurrentProcessId(void);
int            SMB_STDCALL SetCurrentDirectoryA(const char *);
unsigned long  SMB_STDCALL GetCurrentDirectoryA(unsigned long, char *);
void *         SMB_STDCALL LoadLibraryA(const char *);
void *         SMB_STDCALL GetProcAddress(void *, const char *);
int            SMB_STDCALL MultiByteToWideChar(unsigned int, unsigned long, const char *, int,
                                               unsigned short *, int);
int            SMB_STDCALL WideCharToMultiByte(unsigned int, unsigned long, const unsigned short *,
                                               int, char *, int, const char *, int *);

/*
 * smb_fd_isset - FD_ISSET without the __WSAFDIsSet import
 * Inputs : s = socket, set = fd_set as returned by select()
 * Outputs: 1 if s is in the set, else 0
 * Clobbers: none
 */
static int smb_fd_isset(SOCKET s, const fd_set *set)
{
    u_int i;

    for (i = 0; i < set->fd_count; i++)
        if (set->fd_array[i] == s)
            return 1;
    return 0;
}

#else   /* real Windows headers (MinGW, MSVC) */

#define WIN32_LEAN_AND_MEAN
#ifndef FD_SETSIZE
#define FD_SETSIZE 128              /* scan mode: sockets per select() set    */
#endif
#include <winsock2.h>
#include <windows.h>

#endif  /* SMBFTP_MINI_WINAPI */

#endif  /* SMBFTP_WINMINI_H */
