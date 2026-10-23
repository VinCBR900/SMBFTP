# smbftp

Targeted primarily at Windows, this is a Lightweight FTP-style GUI and command-line client utility for SMB1 file servers. The SMB1 protocol runs in userspace via a modified [libdsm](https://github.com/videolabs/libdsm). The Windows SMB redirector is not used so Windows does not need SMB1 enabled.

There are two front ends over one engine: `smbftp.exe` (command line, `smbftp.c`) and
`WinSMBFTP.exe` (Windows GUI, `winsmbftp.c`: connect, browse, Get/Put with a progress bar,
and a Scan window). Everything that talks to libdsm lives in `smb_engine.c` / `smb_engine.h`,
which both use. Version, usage and history are in the header of each source file.

> **AI Disclosure**: The coding heavy lifting was done by Claude AI (Anthropic).  I architected, reviewed, and shepherded Claude.
> To be frank, without Claude this tool would not have been possible.

## Usage

    smbftp [options] <IPv4-address>
    smbftp 192.168.4.20
    smbftp -u fred -p secret -d WORKGROUP -s public 192.168.4.20

Default login is `guest` with an empty password (libdsm cannot send a true null
session). Commands: `shares`, `use <share>`, `ls`, `cd`, `pwd`, `get`, `put`,
`lcd`, `lpwd`, `help`, `quit`. Run `smbftp -h` for all options. `quit` (and end of input) logs
off from the server and closes the connection.

**NOTE**: Command line Passwords are plan text - this is not a security project and was just meant as a quick hack to acces an old NAS on Windows machines without SMB1 enabled.

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

Windows is the primary target and intended to be Lean and Mean, so uses [TinyCC](https://repo.or.cz/w/tinycc.git) (`tcc.exe`): no
GNU tools, MinGW, WSL, meson, make, libtasn1 or iconv. libdsm, `smb_engine.c` and
`smbftp.c` (or `winsmbftp.c`) are compiled together and linked statically into one exe; there
is no libdsm DLL.

    build.cmd              release build of smbftp.exe (default)
    build.cmd debug        smbftp.exe with libdsm's debug trace on stderr, asserts on, -g
    build.cmd gui          build WinSMBFTP.exe (see "WinSMBFTP, the GUI" below)
    build.cmd gui debug    as gui, plus -g and the winsmbftp-debug.log logging
    build.cmd fetch        only download, verify and patch libdsm
    build.cmd clean        delete smbftp.exe and WinSMBFTP.exe
    build.cmd distclean    clean, and delete libdsm\ and the download cache deps\

`build.cmd` finds TCC through the `TCC` environment variable (`set TCC=C:\tools\tcc\tcc.exe`),
then `PATH`, then a `tcc` folder next to the script (and a few usual places). It
gets libdsm ready (below), builds, then smoke-tests smbftp.exe (`smbftp -h`, and
`smbftp -S 127.0.0.1`, which sends no packets but proves the Winsock imports
resolve; there is no automated test for the GUI exe). Exit status is 0 only if
everything succeeds.

libdsm is downloaded using `curl.exe`, `tar.exe` and `certutil.exe`, which are part of
Windows 10 version 1803 and later and Windows 11 (without `curl.exe` the script
falls back to PowerShell for the download). For an offline build, copy the file
`libdsm-<commit>.tar.gz` into `deps\` first; it is used as it is, after its SHA-256
has been checked.

### How libdsm is obtained

libdsm is not part of this source tree. `patches\libdsm.cfg` names the upstream
commit to use, where to download it, and the SHA-256 the download must have. The
build then:

1. downloads `https://codeload.github.com/videolabs/libdsm/tar.gz/<commit>` into
   `deps\` (skipped if the file is already there) and stops if the SHA-256 differs;
2. unpacks it into `deps\stage`, compiles `tools\applydiff.c` with TCC, and applies
   the patches listed in `libdsm.cfg` (`patches\0001-...diff`, `0002-...diff`) in order;
3. only then moves the result to `libdsm\` and writes `libdsm\.stamp`.

A failed run never leaves a half-patched `libdsm\`. The stamp records the commit and
the SHA-256 of every patch, so changing `libdsm.cfg` or a patch file makes the next
build redo this, and otherwise it is skipped. `libdsm\` is generated: edit the
patches, not the tree. A `libdsm\` folder that has no `.stamp` (for example one
left from an older release of this project) is never overwritten; the build stops and
tells you to move it away or run `build.cmd distclean`.

`tools\applydiff.c` is a small, strict unified-diff applier (Windows has no
`patch`, and this build uses TCC only). Every context line must match exactly, no
fuzz; a hunk may sit at a different line number than the patch says; all files are
checked before any is written; it refuses patches that create, delete or rename
files. `tests\test_applydiff.sh` tests it against `diff -u` output. It is called
`applydiff`, not `patch`: Windows asks for elevation when a 32-bit exe without a
manifest has "patch", "setup", "install" or "update" in its name.

The libdsm source files that are compiled are listed in `sources.lst`, which
`build.cmd`, the `Makefile` and the test scripts all read.

Layout, all next to `build.cmd`:

    build.cmd  Makefile  smbftp.h  ws2_32.def  sources.lst
    smbftp.c           the command-line front end
    smb_engine.c/.h    everything that talks to libdsm (sessions, shares, listings,
                       get/put, scan), shared by both front ends
    winsmbftp.c        the Windows GUI front end (user32.def, comctl32.def,
                       comdlg32.def, WinSMBFTP.exe.manifest belong to it)
    winport\   support files for TCC on Windows
        winmini.h    the Win32/Winsock declarations TCC lacks (one copy, used by
                     smbftp.h and by libdsm)
        wingui.h     the user32/comctl32/comdlg32 declarations winsmbftp.c needs
        config.h     libdsm's configuration, written by hand instead of meson
        winsock2.h, ws2tcpip.h, unistd.h   stand-ins that libdsm's #includes find
    linux\     config.h for libdsm on Linux (used by the Makefile and tests\)
    patches\   libdsm.cfg (commit, URL, SHA-256, patch order) and the patch series
    tools\     applydiff.c, the patch tool
    libdsm\    made by the build: upstream libdsm plus the patches. Not committed.
    deps\      download cache and the compiled patch tool. Not committed.

`ws2_32.def` is the import definition for the Winsock functions; it is linked
even if your TCC ships its own, so older TCC packages work too.

If `build.cmd` stops while unpacking, check the path length: libdsm has paths of up
to about 90 characters, which are added to the path of this folder, and older
Windows limits paths to 260 characters in total.

## WinSMBFTP, the GUI

    build.cmd gui          build WinSMBFTP.exe
    build.cmd gui debug    same, with debug logging (below)

WinSMBFTP has a toolbar (Up, Refresh, Connect, Scan, Get, Put, Cancel), a read-only
address bar, a ListView (Name/Size/Type/Modified) and a status bar. Connect opens a window
for host/user/password/domain/share; Up and double-clicking a directory navigate; Get (or
double-clicking a file) opens a Save dialog and downloads, Put opens an Open dialog and
uploads into the current directory, and Cancel stops a transfer or a scan. Every network
call runs on a worker thread, so the window never blocks. The status bar says so when a
listing may be incomplete or was recovered, as `smbftp`'s `ls` does. Connecting again ends
the old session first (SMB logoff, then close), and so does closing the window: it asks a
running transfer or scan to stop (closing mid-transfer is the same as Cancel), waits up to
3 s for it, logs off and closes the connection. If the worker is stuck in a call that cannot
be interrupted, the session is left for the process exit to close. It is built from
`winsmbftp.c` (plain `CreateWindowExA` calls, no resource compiler); `winport\wingui.h`
declares the Win32 GUI API it uses, the same way `winport\winmini.h` does for Winsock.
`WinSMBFTP.exe.manifest` must stay next to the exe: Windows loads a same-named
`.manifest` file automatically, and it asks for the themed (ComCtl32 v6) look.

**Scan.** The Scan button opens a window with an address box, prefilled with this
machine's network (for example `192.168.4.0/24`; any `a.b.c.d` or `a.b.c.d/n`, n = 16 to
32, is accepted, as in `smbftp -S`). Press Scan: hosts with tcp/445 or tcp/139 open are
found first (64 at a time, so a /24 takes about as long as four timeouts however many
addresses are silent), then each is sent an SMB1 NEGOTIATE with a short time limit and only
a host that answers in SMB1 gets a full session and a guest login. Rows appear as hosts
are checked: one row per share, or a bracketed note for a host that needs a login ("SMB1 -
login required") or has an SMB port open but does not answer in SMB1. Double-click a share,
or select it and press Use selected, to open the Connect window with host and share filled
in. Stop (or closing the window) ends the scan; it is checked between batches and between
hosts. This machine's own addresses are not probed. Only guest login is tried.

**Debug log.** A normal `build.cmd gui` contains no logging code. With `build.cmd gui debug`
(which defines `WINSMB_DEBUG` and adds `-g`), `winsmbftp-debug.log` is written next to the
exe while it runs, and the same lines go to `OutputDebugStringA` for a debugger or
DebugView.

## Building on Linux

    make                   release build -> ./smbftp
    make DEBUG=1           -g -O0, libdsm's debug trace and asserts on
    make asan              AddressSanitizer + UBSan build -> ./smbftp-asan
    make fetch             only download, verify and patch libdsm
    make clean             remove build objects and the binaries
    make distclean         clean, and delete libdsm/ and the download cache deps/

Needs a C compiler, `make`, `tar`, `curl` or `wget`, and `sha256sum` or `shasum`.
`CC=clang make` and `CC=tcc make` work too. The `Makefile` gets libdsm exactly as
`build.cmd` does (same `patches/libdsm.cfg`, same `tools/applydiff.c`, same
`sources.lst`), so both platforms build the same patched libdsm. The patched libdsm
needs no libtasn1, no pthreads and no meson; on Linux it uses the C library's
iconv. Windows is the target platform; the Linux build exists for development and
for the tests, and it builds the command-line `smbftp` only: the GUI is Windows-only.

## What the libdsm patches change

The two patch files are against upstream libdsm commit `0f3edc6` (master of
4 January 2024, just after v0.4.3). `0001-tcc-windows-port.diff` is the port;
`0002-v0.6-fixes.diff` is applied after it.

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
* **WriteAndX byte count fix** (`smb_file.c`), see "libdsm write byte count" below.
* **Not built:** `netbios_ns.c` (NetBIOS name lookup, needs pthreads). smbftp
  connects by IPv4 address and never calls it.

`meson.build` and `config.h.meson` are left as they were and are not used (the
meson build would still ask for libtasn1).

## libdsm write byte count (needed for strict servers)

libdsm 0.4.3 (current master) sets the SMB1 WriteAndX byte count one byte short
(it counts the data but not the pad byte it also sends). Lenient servers (Samba,
Windows) ignore the field. Strict servers, such as impacket's SMB1 server, drop
the last byte of every write yet still acknowledge it, so a large upload ends up
truncated while looking successful.

The one-line fix is part of `0001-tcc-windows-port.diff` (`smb_file.c`); it used to
be a separate `libdsm-write-bytecount.patch`, which is no longer needed. smbftp does
not depend on it, but `put` re-reads the remote size after every upload and reports
an error if it differs from the bytes sent, so a bad upload cannot pass silently.

## Changing libdsm or the patches

* **Add a patch:** run `fetch`, copy `libdsm/` to `before/`, edit `libdsm/`, then
  save the difference with `diff -ruN before libdsm > patches/0003-my-fix.diff` and
  add the file name to `LIBDSM_PATCHES` in `patches/libdsm.cfg`. The next build
  starts again from the download, so what is in the patch is what you get. Patches
  are applied with `-p1` inside the libdsm folder, in the order of `LIBDSM_PATCHES`,
  and must stay LF-only (`.gitattributes` does this). Changing an earlier patch can
  stop a later one from applying; the build then names the file and hunk.
* **Move to a newer libdsm:** change `LIBDSM_COMMIT` and `LIBDSM_URL` in
  `patches/libdsm.cfg`, download the file once, put its SHA-256 in `LIBDSM_SHA256`
  (`certutil -hashfile file SHA256`, or `sha256sum file`), and run `fetch`. Patches
  that no longer apply stop the build with the file and hunk that failed; nothing is
  changed. Always pin a full commit id, not a branch.
* **Licence:** libdsm is LGPL 2.1 or later and is linked statically into `smbftp.exe`.
  The pinned upstream commit plus `patches/` is the complete source of the libdsm that
  is in the exe; keep them (and the build scripts) with any copy of the exe you give away.

## Testing without real hardware

impacket's SMB1 server is a convenient local target (and a strict one):

    pip install impacket
    smbserver.py TEST /path/to/share -ip 127.0.0.1        # SMB1 only by default, needs port 445
    smbftp -t tcp 127.0.0.1

Scan mode was tested in an isolated virtual LAN (two network namespaces joined by
a veth pair): a real impacket SMB1 server, an SMB2-only stub, a tcp/139-only
stub, a silent listener, and an SMB1 stub on the scanner's own address, which
must not be reported.
