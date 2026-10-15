# smbftp

FTP-style command-line client for SMB1 file servers, for Windows. The SMB1
protocol runs in userspace through [libdsm](https://github.com/videolabs/libdsm),
so Windows does not need its SMB1 client feature enabled and the Windows SMB
redirector is not used. Version, usage and history are in the header of `smbftp.c`.

## Usage

    smbftp [options] <IPv4-address>
    smbftp 192.168.4.20
    smbftp -u fred -p secret -d WORKGROUP -s public 192.168.4.20

Default login is `guest` with an empty password (libdsm cannot send a true null
session). Commands: `shares`, `use <share>`, `ls`, `cd`, `pwd`, `get`, `put`,
`lcd`, `lpwd`, `help`, `quit`. Run `smbftp -h` for all options.

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

Everything is built by [TinyCC](https://repo.or.cz/w/tinycc.git) (`tcc.exe`): no
GNU tools, MinGW, WSL, meson, make, libtasn1 or iconv. libdsm and `smbftp.c` are
compiled together and linked statically into one `smbftp.exe`; there is no libdsm DLL.

    build.cmd              release build (default)
    build.cmd debug        libdsm's debug trace on stderr, asserts on, -g
    build.cmd fetch        only download, verify and patch libdsm
    build.cmd clean        delete smbftp.exe
    build.cmd distclean    clean, and delete libdsm\ and the download cache deps\

`build.cmd` finds TCC through the `TCC` environment variable (`set TCC=C:\tools\tcc\tcc.exe`),
then `PATH`, then a `tcc` folder next to the script (and a few usual places). It
gets libdsm ready (below), builds, then smoke-tests the result (`smbftp -h`, and
`smbftp -S 127.0.0.1`, which sends no packets but proves the Winsock imports
resolve). Exit status is 0 only if everything succeeds.

The download needs `curl.exe`, `tar.exe` and `certutil.exe`, which are part of
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

    build.cmd  Makefile  smbftp.c  smbftp.h  ws2_32.def  sources.lst
    winport\   support files for TCC on Windows
        winmini.h    the Win32/Winsock declarations TCC lacks (one copy, used by
                     smbftp.h and by libdsm)
        config.h     libdsm's configuration, written by hand instead of meson
        winsock2.h, ws2tcpip.h, unistd.h   stand-ins that libdsm's #includes find
    linux\     config.h for libdsm on Linux (used by the Makefile and tests\)
    patches\   libdsm.cfg (commit, URL, SHA-256, patch order) and the patch series
    tools\     applydiff.c, the patch tool
    tests\     test tools (below)
    libdsm\    made by the build: upstream libdsm plus the patches. Not committed.
    deps\      download cache and the compiled patch tool. Not committed.

`ws2_32.def` is the import definition for the Winsock functions; it is linked
even if your TCC ships its own, so older TCC packages work too.

If `build.cmd` stops while unpacking, check the path length: libdsm has paths of up
to about 90 characters, which are added to the path of this folder, and older
Windows limits paths to 260 characters in total.

## Building on Linux

    make                   release build -> ./smbftp
    make DEBUG=1           -g -O0, libdsm's debug trace and asserts on
    make asan              AddressSanitizer + UBSan build -> ./smbftp-asan
    make fetch             only download, verify and patch libdsm
    make test              tests\test_applydiff.sh, then a smoke test of ./smbftp
    make clean             remove build objects and the binaries
    make distclean         clean, and delete libdsm/ and the download cache deps/

Needs a C compiler, `make`, `tar`, `curl` or `wget`, and `sha256sum` or `shasum`.
`CC=clang make` and `CC=tcc make` work too. The `Makefile` gets libdsm exactly as
`build.cmd` does (same `patches/libdsm.cfg`, same `tools/applydiff.c`, same
`sources.lst`), so both platforms build the same patched libdsm. The patched libdsm
needs no libtasn1, no pthreads and no meson; on Linux it uses the C library's
iconv. Windows is the target platform; the Linux build exists for development and
for the tests.

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

### libdsm fixes in 0.6 (`0002-v0.6-fixes.diff`, applied on top of the port above)

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

## Tests

The tools are in `tests/` (Linux, Python 3, gcc, Samba, impacket; see the header of
each file). They build smbftp with ASan/UBSan, run it against a Samba server
(SMB1 only) and impacket's strict SMB1 server, and compare every listing with the
files on disk. `tests/run_all.sh <project folder>` runs the whole matrix and runs
`make fetch` first if `libdsm/` is not there yet. `tests/test_applydiff.sh` tests the
patch tool on its own (random `diff -u` pairs, refusals, `\ No newline` cases) and
needs no server; `make test` runs it.

| Test | smbftp 0.5 | smbftp 0.6 |
|------|------------|------------|
| Black-box suite (285 tests: listings of 0..5000 files, long and varied names, Unicode, `cd`/`ls` repeats, transfers 0 B..10 MB), Samba, ASan | 9 failed | 0 failed |
| same, impacket | 39 failed (a listing stops at about 500 entries; wrong counts) | 0 failed |
| same, plain (no ASan) build | not run | 0 failed on both servers |
| Windows branch of `smb_utils.c` on a Linux shim, plain build, `d_varlen` (600 names, 1..200 chars) | aborts: glibc "malloc(): invalid next size" | passes |
| Windows branch, UTF-8 code page, ASan, Samba (all) and impacket (listings) | n/a | 0 failed |
| Reply-mutation fuzz (a proxy corrupts server replies), ASan | 100 seeds: 32 sanitizer reports (heap overflows, huge allocations), 1 abort | 690 seeds (Samba, impacket, Windows branch, 30% and 80% mutation): 0 reports |
| Replies delivered 1..500 bytes at a time, with delay | n/a | listing and download exact |
| Connection dropped at 14 points of a listing | n/a | clean exit, partial listing flagged, no wrong or duplicate names, next run works |
| valgrind with leak check (`use`, `ls` x3, `get`, `shares`) | n/a | no errors, no leaks |

The table above was measured on the libdsm tree that used to be shipped. The
download-and-patch build produces a byte-identical tree (checked against the old
one), and the 285-test black-box suite was run again on a binary built by the
`Makefile` against impacket: 0 failed.

Remaining differences, none a defect in smbftp: the Windows-branch shim used for the
ANSI code page converts to Latin-1, so four Unicode listing checks that expect UTF-8
differ in the shim (counts are right; the UTF-8 shim build passes them). A stalled
server ends a request after 60 s, which the fuzzer's short time limit (5-15 s) reports as "hang".

Not tested: a real Windows machine and a real Windows SMB1 server (no Windows here;
the TCC build was only syntax-checked with TCC on Linux). The reported
"out of memory" message could not be reproduced as such; it is the likeliest
result of the heap overflow above (a failing `malloc` after heap corruption), but
that link is inferred, not observed.

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
