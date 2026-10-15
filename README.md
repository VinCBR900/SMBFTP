# smbftp

Lightweight Windows FTP-style command-line client utility for SMB1 file servers, for Windows. 
The SMB1 protocol runs in userspace through the excellent [libdsm](https://github.com/videolabs/libdsm).  
The Windows SMB redirector is not used so Windows does not need SMB1 enabled.
Version, usage and history are in the header of `smbftp.c`.

## Usage

    smbftp [options] <IPv4-address>
    smbftp 192.168.4.20
    smbftp -u fred -p secret -d WORKGROUP -s public 192.168.4.20

Default login is `guest` with an empty password (libdsm cannot send a true null
session). Commands: `shares`, `use <share>`, `ls`, `cd`, `pwd`, `get`, `put`,
`lcd`, `lpwd`, `help`, `quit`. Run `smbftp -h` for all options.

**NOTE:** Command line Passwords are plan text - this is not a security project and was just meant as a quick hack to acces an old NAS on Windows machine without SMB1 enabled.

## Finding servers (scan mode)

    smbftp -S                      scan the subnet(s) of this machine's adapters
    smbftp -S 192.168.4.0/24       scan a network you name (/16 to /32), or one address
    smbftp -S -w 2000              wait up to 2 s per port instead of 1 s

No subnet mask is needed: smbftp reads each adapter's address and mask from the
OS (Winsock `SIO_GET_INTERFACE_LIST`; `getifaddrs` on Linux). Loopback,
169.254.x.x and /31, /32 links are skipped, and a subnet wider than /22 is cut
down to the /24 holding your address (name a bigger one yourself if you mean
it). This machine's own addresses are never probed.

Each host is tried on tcp/445 and tcp/139 with an SMB1 NEGOTIATE, so a host is
listed as an SMB1 server only if it actually answers in SMB1. Hosts with an SMB
port open that do not answer in SMB1 (typically SMB1 switched off) are listed
separately. A server found only on tcp/139 needs `smbftp -t nbt <address>`.
Hosts that drop packets show nothing. A /24 takes a few seconds; probes run 64
hosts at a time.


## Building on Windows (TCC only)

Everything is built by [TinyCC](https://github.com/phoenixthrush/Tiny-C-Compiler) (`tcc.exe`): no
GNU tools, MinGW, WSL, meson, make, libtasn1 or iconv. 
TCC does not come with extensive Windows Header files so `WINPORT` contains bare minimum header files needed to compile.
The libdsm sources in
`libdsm\` and `smbftp.c` are compiled together and linked statically into one
`smbftp.exe`; there is no libdsm DLL.

    build.cmd            release build (default)
    build.cmd debug      libdsm's debug trace on stderr, asserts on, -g
    build.cmd clean      delete smbftp.exe

`build.cmd` finds TCC through the `TCC` environment variable (`set TCC=C:\tools\tcc\tcc.exe`),
then `PATH`, then a `tcc` folder next to the script (and a few usual places). It
builds, then smoke-tests the result (`smbftp -h`, and `smbftp -S 127.0.0.1`,
which sends no packets but proves the Winsock imports resolve). Exit status is 0
only if both succeed.

Layout, all next to `build.cmd`:

    build.cmd  smbftp.c  smbftp.h  ws2_32.def
    winport\   support files for TCC on Windows
        winmini.h    the Win32/Winsock declarations TCC lacks (one copy, used by
                     smbftp.h and by libdsm)
        config.h     libdsm's configuration, written by hand instead of meson
        winsock2.h, ws2tcpip.h, unistd.h   stand-ins that libdsm's #includes find
    libdsm\    libdsm source tree, modified for TCC (below)

`ws2_32.def` is the import definition for the Winsock functions; it is linked
even if your TCC ships its own, so older TCC packages work too.

### What was changed in the bundled libdsm

`libdsm-tcc-port.diff` is the complete diff against the tree this port started from.

* **libtasn1 removed.** libdsm used it only in `smb_spnego.c`, to build and read
  the two SPNEGO tokens of the NTLM login, and its generated `spnego_asn1.c`
  needs libtasn1's `asn1Parser` tool. Those tokens have a fixed shape, so they
  are now written and read directly as DER (about 200 lines, mostly comments). The NTLM challenge
  parser also checks that the target info lies inside the message. The libtasn1
  includes and the `ASN1_TYPE` member are gone from both `smb_types.h` files and
  `smb_session.c`, so even `smbftp.c` no longer needs `libtasn1.h`.
* **iconv replaced** by `MultiByteToWideChar` / `WideCharToMultiByte` in
  `smb_utils.c`, using the ANSI code page (the one `argv` and `fopen` use). Add
  `-DSMB_WIN_CODEPAGE=65001` to `FLAGS` in `build.cmd` for UTF-8 instead.
* **Winsock connect fixed** in `netbios_session.c`. libdsm tested `errno` after a
  non-blocking `connect()`, which Winsock never sets, so every connect failed;
  it now uses `WSAGetLastError()`/`WSAEWOULDBLOCK`. A failed connect is reported
  by `select()` in the exception set on Windows, not the write set, and libdsm
  waited forever with no timeout; the exception set is now watched. Errors print
  the Winsock code (for example `10061 (connection refused)`) instead of
  `Success`.
* **64-bit file offsets.** TCC's `off_t` is 32 bits; `smb_types.h` makes it
  `off64_t` (as it already did for Android).
* **TCC compatibility:** packed-struct macros for TCC (`bdsm_common.h`), a plain
  `volatile int` abort flag instead of `<stdatomic.h>` (not in every TCC),
  `strndup` without `strnlen` (hidden in TCC's `string.h`), and NTLM client
  challenges from `RtlGenRandom` (all 64 bits; `rand_s` gave 32).
* **WriteAndX byte count fix applied** (see below), because `build.cmd` has no
  `patch` tool to apply it.
* **Not built:** `netbios_ns.c` (NetBIOS name lookup, needs pthreads). smbftp
  connects by IPv4 address and never calls it.

`meson.build` and `config.h.meson` are left as they were and are not used (the
meson build would still ask for libtasn1).

### libdsm fixes in 0.6 (`libdsm-v0.6-fixes.diff`, applied on top of the port above)

Found by testing smbftp 0.5 (see "Tests"). They explain the reported symptoms
"crashes after `use` + `ls`", "only some files listed" and "out of memory".

* **One-byte heap overflow on every directory entry (Windows build).** The
  Win32 `smb_from_utf16` returned a buffer of exactly the converted length, and
  `smb_trans2.c` then wrote the terminating NUL one byte past it. Whether that
  corrupts the heap depends on the name length and the allocator, so it looked
  random: a crash or entries missing, and probably a failing `malloc` (printed
  as "out of memory"). `smb_from_utf16`/`smb_to_utf16` now always leave a terminator.
* **TRANS2 replies are validated.** Status, command, word count, offsets and
  counts are checked against the real message length; fragments are placed by
  displacement; entries are bounds-checked. A corrupt reply used to give huge
  allocations, overflows or aborts.
* **A listing is never silently cut short.** An undecodable name no longer ends
  the list (`?` is shown instead); iconv builds use UTF-16LE (emoji names broke
  the list); a failing FIND_NEXT keeps the entries already read; FIND_NEXT sends
  the last file name; impacket's mis-sized FIND_NEXT entries are recovered.
  `ls` prints a warning when a listing may be incomplete, a note when the server
  spacing had to be recovered.
* **Smaller fixes:** open-file list removal compared the wrong id (a handle that was
  not first in the list was never closed on the server);
  `smb_session_get_nt_status` is set from every reply (stale errors); receive
  buffer size was off by 4 and a failed realloc left a NULL buffer; a partial
  `send()` is continued instead of failing; a 60 s I/O timeout
  (`SMB_IO_TIMEOUT_SEC`, override with `-D`) replaces waiting for ever; the share
  list parser is bounds-checked and no longer reads an uninitialised reply after a
  failed receive; `smb_fread` rejects more data than requested and `smb_fwrite` a
  larger acknowledgement than sent; a server name of 16 or more characters is
  refused instead of overflowing a fixed field; `SMB_CAPS_XSEC` no longer
  overflows a signed int; `MD4_Update` no longer calls `memcpy(.., NULL, 0)`.
* **New library call:** `smb_session_get_find_flags()` (`SMB_FIND_INCOMPLETE`,
  `SMB_FIND_RESYNCED`), used by `ls`. Not used by anything else, so other callers
  of `smb_find` are unaffected.
* **Names that cannot be converted** (a character the local code page cannot show)
  are listed as `?`. Such a file cannot be opened by that name; use a UTF-8 build
  (`-DSMB_WIN_CODEPAGE=65001`) if your server has names outside your code page.
* **Not changed:** `smb_fstat` (unused by smbftp, has known offset bugs), and no
  FIND_CLOSE2 is sent when a listing ends early.

## libdsm write patch (needed for strict servers)

libdsm 0.4.3 (current master) sets the SMB1 WriteAndX byte count one byte short
(it counts the data but not the pad byte it also sends). Lenient servers (Samba,
Windows) ignore the field. Strict servers, such as impacket's SMB1 server, drop
the last byte of every write yet still acknowledge it, so a large upload ends up
truncated while looking successful.

`libdsm-write-bytecount.patch` is the one-line fix; **the libdsm in this tree
already has it applied.** Keep the patch file for other libdsm builds. smbftp does
not depend on it, but `put` re-reads the remote size after every upload and reports
an error if it differs from the bytes sent, so a bad upload cannot pass silently.

## Testing without real hardware

impacket's SMB1 server is a convenient local target (and a strict one):

    pip install impacket
    smbserver.py TEST /path/to/share -ip 127.0.0.1        # SMB1 only by default, needs port 445
    smbftp -t tcp 127.0.0.1

Scan mode was tested in an isolated virtual LAN (two network namespaces joined by
a veth pair): a real impacket SMB1 server, an SMB2-only stub, a tcp/139-only
stub, a silent listener, and an SMB1 stub on the scanner's own address, which
must not be reported.
