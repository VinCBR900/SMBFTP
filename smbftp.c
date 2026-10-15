/*
 * smbftp - minimal FTP-style command-line client for SMB1 file servers
 *
 * Version : 0.6
 * Author  : VinCBR900
 *
 * Purpose
 *   Deliberate access to SMB1 shares that Windows (or anything modern) no
 *   longer talks to. The SMB1 protocol is implemented in userspace by libdsm
 *   (https://github.com/videolabs/libdsm), so Windows does not need its own
 *   SMB1 client feature enabled and the Windows SMB redirector is not used.
 *
 * Usage
 *   smbftp [options] <IPv4-address>
 *   smbftp -S [-w ms] [network]
 *
 *   Scan mode (-S): looks for SMB1 servers on the local network and prints
 *   them; no subnet mask is needed. With no argument every local adapter's own
 *   address and mask are read from the OS and each subnet is scanned (loopback,
 *   169.254/16 and /31, /32 links are skipped; a subnet wider than /22 is
 *   reduced to the /24 holding the local address). To scan something else give
 *   a network as a.b.c.d/n (n = 16..32) or a single address. This machine's own
 *   addresses are never probed. Each host is probed on tcp/445 and tcp/139
 *   with an SMB1 NEGOTIATE; a host is listed as an SMB1 server only if it
 *   answers it, so a host with SMB1 switched off is not listed as one (it is
 *   shown separately as "SMB port open"). Then connect with: smbftp <address>
 *
 *   Options (each takes a separate value, e.g.  -u fred):
 *     -u user     login name           (default: guest)
 *     -p pass     password             (default: empty)
 *     -d domain   domain / workgroup   (default: WORKGROUP)
 *     -n name     server NetBIOS name, max 15 chars
 *                 (default: the IP text for TCP, *SMBSERVER for NBT)
 *     -t mode     transport: auto | tcp | nbt   (default: auto = tcp, then nbt)
 *     -s share    connect to this share immediately after login
 *     -b bytes    transfer chunk size, 512..60000 (default 32768); reduce it
 *                 if an old server rejects large reads or writes
 *     -S          scan for SMB1 servers instead of connecting (takes no value)
 *     -w ms       scan: time limit per port probe, 100..30000 (default 1000)
 *     -h          show usage
 *
 *   The default login (guest, empty password) is the closest equivalent to
 *   anonymous access that libdsm offers: it always sends an NTLM response, so a
 *   true null session is not possible. Servers that map unknown users to Guest
 *   will accept it; others need -u / -p / -d.
 *
 *   Interactive commands (type "help" for the list):
 *     shares              list shares on the server
 *     use <share>         connect to a share        (alias: open)
 *     ls [dir|pattern]    list directory            (alias: dir)
 *     cd <dir>            change remote directory   (.. and \ or / supported)
 *     pwd                 show remote directory
 *     get <remote> [local]  download a file
 *     put <local> [remote]  upload a file (overwrites an existing file)
 *     lcd [dir]           change / show local directory
 *     lpwd                show local directory
 *     help, quit          (aliases: ?, exit, bye)
 *   Names containing spaces must be enclosed in double quotes.
 *
 * Build (see README.md)
 *   build.cmd                          Windows, TCC only: builds the bundled libdsm
 *                                      and smbftp.c into one smbftp.exe (no GNU
 *                                      tools, no WSL, no meson, no libtasn1)
 *   gcc -O2 -Wall -o smbftp smbftp.c -ldsm     Linux, against the system libdsm
 *   gcc -O2 -Wall -o smbftp.exe smbftp.c -ldsm -lws2_32   MinGW-w64 against a
 *                                      separately built libdsm
 *   smbftp.c needs smbftp.h (and, on Windows, winport/winmini.h) beside it.
 *
 * Exit status: 0 = clean exit, 1 = connect/login/runtime failure, 2 = usage.
 *
 * Known limitations
 *   - IPv4 address only; no name resolution, no share browsing by hostname.
 *   - SMB1 only (that is the point of the tool).
 *   - Files of 2 GiB or more may fail on Windows builds, where libdsm's
 *     off_t can be 32-bit.
 *   - Upload overwrites an existing remote file without asking.
 *   - Unpatched libdsm 0.4.3 sends a WriteAndX byte count one byte short.
 *     Lenient servers (Samba, Windows) ignore it; strict ones (impacket's
 *     SMB1 server) drop the last byte of every write and acknowledge it
 *     anyway. put re-reads the remote size and reports an error on a
 *     mismatch, leaving the truncated file behind. Fix: apply
 *     libdsm-write-bytecount.patch to libdsm (see README.md). The
 *     libdsm copy bundled for build.cmd already has this fix applied.
 *   - 0.6 needs the bundled libdsm (it adds smb_session_get_find_flags and
 *     many reply-validation fixes). Built against a stock system libdsm it
 *     still compiles but lacks the "listing may be incomplete" warning and the
 *     fixes, so large or odd directories can list partially or crash.
 *   - Names that the local code page cannot represent are shown with '?'
 *     (ANSI Windows build) and cannot be fetched by that shown name.
 *   - If a server stops answering for 60 s mid-transfer or mid-listing the
 *     operation is abandoned with an error (libdsm SMB_IO_TIMEOUT_SEC); the
 *     server-side search handle of an abandoned listing is not closed.
 *   - Download overwrites an existing local file without asking, and leaves a
 *     partial file behind if the transfer fails.
 *   - No recursive transfers, wildcards in get/put, delete, rename or mkdir.
 *   - The password is taken from the command line (visible to other users).
 *   - Connection attempts to a dead host block until the OS timeout.
 *   - Scan: IPv4 only; probes tcp/445 and tcp/139 only and shows addresses, not
 *     names. A host that drops packets (firewall) shows nothing. tcp/139 uses
 *     the called name *SMBSERVER; a server that refuses it is listed as "SMB
 *     port open". Only the NT LM 0.12 dialect is offered, so a server that
 *     speaks nothing newer than LANMAN is not recognised. A large explicit
 *     network (/16 = 65534 hosts) can take many minutes. Scanning networks
 *     you do not own may trigger intrusion alerts.
 *   - Remote names are converted using the local locale by libdsm; non-ASCII
 *     names may display or transfer incorrectly. A character the local code
 *     page cannot show is listed as '?' and such a file cannot be fetched by
 *     the name shown.
 *   - A listing is not closed with FIND_CLOSE2 when it ends early (server-side
 *     search handle stays until the session ends); a stalled server ends a
 *     request after 60 s (SMB_IO_TIMEOUT_SEC in libdsm).
 *
 * History
 *   0.6  2026-10-14  Fixes for "crashes after use + ls", "only some files shown"
 *                    and "out of memory", found with an ASan build against Samba
 *                    and impacket SMB1 servers and a reply-mutating proxy (test
 *                    tools: smbftp_test/). Library (libdsm-v0.6-fixes.diff):
 *                    (1) Windows smb_from_utf16/smb_to_utf16 returned a buffer of
 *                    exactly the converted length and smb_trans2.c then wrote the
 *                    terminating NUL one byte past it: a one-byte heap overflow
 *                    per directory entry, corrupting the heap on some name lengths
 *                    (crash, entries missing, and probably a failing malloc
 *                    shown as "out of memory" - that last link is inferred, not
 *                    observed); buffers now carry a terminator. (2) TRANS2 find
 *                    replies are validated (status, word count, offsets, counts)
 *                    and reassembled by displacement; entries are bounds-checked;
 *                    an undecodable name no longer ends the listing; impacket's
 *                    FIND_NEXT entry spacing is recovered; a FIND_NEXT failure keeps
 *                    the entries already read; FIND_NEXT sends the last file name.
 *                    (3) iconv build uses UTF-16LE (emoji names broke the list).
 *                    (4) smb_session_file_remove compared the wrong id; nt_status
 *                    is set from every reply; the receive buffer size was off by 4
 *                    and a failed realloc left a NULL buffer; sends handle partial
 *                    writes; 60 s I/O timeout. (5) share-list reply parsing is
 *                    bounds-checked; smb_fread/smb_fwrite reject a server that
 *                    returns or acknowledges more than was asked; names longer than
 *                    15 characters are refused at connect (fixed-size field). A
 *                    character the local code page cannot show becomes '?'.
 *                    smbftp: ls now says when a listing may be incomplete or was
 *                    recovered. Verified: 285 black-box tests x 2 servers x 3
 *                    builds, 690 mutated-reply sessions, chunked/dropped
 *                    connections, valgrind (see README, "Tests").
 *   0.5  2026-10-12  Added -S scan mode and -w: finds SMB1 servers on the
 *                    local subnet(s) without a mask argument (adapter address
 *                    and mask via Winsock WSAIoctl SIO_GET_INTERFACE_LIST on
 *                    Windows, getifaddrs on Linux), skips all of this
 *                    machine's own addresses, takes an optional a.b.c.d/n
 *                    network. Own non-blocking select() prober, 64 hosts at a
 *                    time, because libdsm's connect blocks until the OS
 *                    timeout. TCC support: under TCC (or -DSMBFTP_MINI_WINAPI)
 *                    the Win32/Winsock names used are declared in main.c
 *                    instead of including winsock2.h/windows.h; only ws2_32
 *                    and kernel32 are linked (tcc/ws2_32.def supplied).
 *   0.4  2026-10-12  put now closes the remote file, re-reads its size and
 *                    fails if it differs from the bytes sent (new
 *                    verify_upload). Found against impacket's SMB1 server:
 *                    uploads came out truncated (10 -> 9 bytes, 1500000 ->
 *                    32767) while libdsm reported success. Cause, confirmed by
 *                    wire capture and by patching libdsm: smb_fwrite sets the
 *                    WriteAndX ByteCount to the data length but also sends a
 *                    pad byte, so ByteCount is one short; impacket cuts the
 *                    last byte, then skips every later write as "past end of
 *                    file". With the one-line libdsm fix uploads are exact.
 *                    Added patches/libdsm-write-bytecount.patch and README.md.
 *   0.3  2026-10-12  cd, ls and put no longer call libdsm's smb_fstat(). In
 *                    libdsm 0.4.3 it sends a TRANS2 byte count 3 bytes short
 *                    (find_first adds the 3-byte pad, fstat does not); strict
 *                    servers such as impacket's SMB1 server drop the connection
 *                    on the first cd. New remote_stat() opens and closes the
 *                    path instead. Confirmed by wire capture and by patching
 *                    libdsm (fstat then works).
 *   0.2  2026-10-11  Interactive shell with shares, use, ls, cd, pwd, get,
 *                    put, lcd, lpwd, help, quit. Corrected libdsm usage in
 *                    the 0.1 draft: libdsm returns 0 on success (draft treated
 *                    <= 0 as failure); smb_share_get_list takes (session,
 *                    &list, &count) and returns int; smb_session_login fails
 *                    when any credential is NULL, so guest credentials are
 *                    now explicit. Added -u -p -d -n -t -s -b options, TCP then
 *                    NBT fallback, NT status text in error messages, and a
 *                    NetBIOS name length check (libdsm stores it in char[16]).
 *   0.1  2026-10-11  Milestone 1 draft: connect to one IPv4 address and list
 *                    shares.
 */

#include "smbftp.h"

static const NtText nt_texts[] = {
    { NT_STATUS_ACCESS_DENIED,          "access denied" },
    { NT_STATUS_LOGON_FAILURE,          "logon failure (bad user, password or domain)" },
    { NT_STATUS_ACCOUNT_RESTRICTION_X,  "account restriction (guest/anonymous login not allowed?)" },
    { NT_STATUS_ACCOUNT_DISABLED_X,     "account disabled" },
    { NT_STATUS_BAD_NETWORK_NAME_X,     "share not found" },
    { NT_STATUS_OBJECT_NAME_NOT_FOUND,  "file or directory not found" },
    { NT_STATUS_OBJECT_PATH_NOT_FOUND,  "path not found" },
    { NT_STATUS_NO_SUCH_FILE,           "no such file" },
    { NT_STATUS_OBJECT_NAME_COLLISION,  "name already exists" },
    { NT_STATUS_FILE_IS_A_DIRECTORY,    "is a directory" },
    { NT_STATUS_MEDIA_WRITE_PROTECTED,  "media is write protected" },
    { NT_STATUS_DELETE_PENDING,         "delete pending" },
    { NT_STATUS_TOO_MANY_OPENED_FILES,  "too many open files on server" },
    { NT_STATUS_INSUFF_SERVER_RESOURCES,"insufficient server resources" },
    { NT_STATUS_NOT_IMPLEMENTED,        "not implemented by server" },
    { 0, NULL }
};

/* ------------------------------------------------------------------------ */
/* Small utilities                                                          */
/* ------------------------------------------------------------------------ */

/*
 * str_copy - bounded string copy that reports truncation
 * Inputs : dst/dsz = destination buffer and its size, src = NUL-terminated
 * Outputs: 0 on success, -1 if src did not fit (dst is then left empty)
 * Clobbers: dst
 */
static int str_copy(char *dst, size_t dsz, const char *src)
{
    size_t n = strlen(src);

    if (n >= dsz) {
        if (dsz > 0)
            dst[0] = '\0';
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

/*
 * ci_cmp - case-insensitive (ASCII) string compare
 * Inputs : a, b = NUL-terminated strings (NULL is treated as "")
 * Outputs: <0, 0, >0 as strcmp
 * Clobbers: none
 */
static int ci_cmp(const char *a, const char *b)
{
    int ca, cb;

    if (a == NULL) a = "";
    if (b == NULL) b = "";
    for (;;) {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb)
            return ca - cb;
        if (ca == 0)
            return 0;
    }
}

/*
 * u64_str - format an unsigned 64-bit value in decimal (avoids printf %llu,
 *           which older Windows C runtimes do not support)
 * Inputs : buf = at least 21 bytes, v = value
 * Outputs: buf (also returned)
 * Clobbers: buf
 */
static char *u64_str(char *buf, uint64_t v)
{
    char tmp[24];
    int n = 0, i = 0;

    do {
        tmp[n++] = (char)('0' + (int)(v % 10));
        v /= 10;
    } while (v != 0);
    while (n > 0)
        buf[i++] = tmp[--n];
    buf[i] = '\0';
    return buf;
}

/*
 * ft_str - format an SMB FILETIME (100 ns ticks since 1601-01-01 UTC) as a
 *          local "YYYY-MM-DD HH:MM" string; blank if zero or out of range
 * Inputs : ft = FILETIME value, buf = at least 17 bytes
 * Outputs: buf (also returned)
 * Clobbers: buf
 */
static char *ft_str(uint64_t ft, char *buf)
{
    uint64_t secs;
    time_t t;
    struct tm *tmv;

    strcpy(buf, "                ");
    if (ft == 0)
        return buf;
    secs = ft / 10000000ULL;
    if (secs < 11644473600ULL)
        return buf;
    secs -= 11644473600ULL;
    t = (time_t)secs;
    tmv = localtime(&t);
    if (tmv == NULL)
        return buf;
    if (strftime(buf, 17, "%Y-%m-%d %H:%M", tmv) == 0)
        strcpy(buf, "                ");
    return buf;
}

/*
 * base_name - last component of a path using / or \ as separators
 * Inputs : path = NUL-terminated string
 * Outputs: pointer into path (empty string if path ends in a separator)
 * Clobbers: none
 */
static const char *base_name(const char *path)
{
    const char *p, *b = path;

    for (p = path; *p; p++)
        if (*p == '\\' || *p == '/')
            b = p + 1;
    return b;
}

/*
 * tokenize - split a command line in place into arguments; double quotes group
 *            words (the quotes are removed); backslash is NOT an escape so
 *            Windows paths can be typed as-is
 * Inputs : line = writable command line, argv = output array, max = its size
 * Outputs: argument count, or -1 if there are more than max arguments
 * Clobbers: line (NUL terminators written), argv
 */
static int tokenize(char *line, char **argv, int max)
{
    char *p = line, *w;
    int argc = 0, inq;

    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;
        if (argc >= max)
            return -1;
        argv[argc++] = w = p;
        inq = 0;
        while (*p && (inq || (*p != ' ' && *p != '\t'))) {
            if (*p == '"') {
                inq = !inq;
                p++;
            } else {
                *w++ = *p++;
            }
        }
        if (*p)
            p++;
        *w = '\0';
    }
    return argc;
}

/*
 * parse_ipv4 - strict dotted-quad parser (no short forms, no hex/octal)
 * Inputs : text = e.g. "192.168.4.20"
 * Outputs: 1 and *ip_net (network byte order) on success, 0 if invalid
 * Clobbers: *ip_net only on success
 */
static int parse_ipv4(const char *text, uint32_t *ip_net)
{
    unsigned long part[4], v;
    const char *p = text;
    int i, digits;

    for (i = 0; i < 4; i++) {
        v = 0;
        digits = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned long)(*p - '0');
            if (++digits > 3 || v > 255)
                return 0;
            p++;
        }
        if (digits == 0)
            return 0;
        part[i] = v;
        if (i < 3) {
            if (*p != '.')
                return 0;
            p++;
        }
    }
    if (*p != '\0')
        return 0;
    *ip_net = htonl((uint32_t)((part[0] << 24) | (part[1] << 16) |
                               (part[2] << 8) | part[3]));
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Error reporting                                                          */
/* ------------------------------------------------------------------------ */

/*
 * nt_text - friendly text for an NT status code
 * Inputs : st = NT status
 * Outputs: static string (generic text if the code is not in the table)
 * Clobbers: none
 */
static const char *nt_text(uint32_t st)
{
    int i;

    for (i = 0; nt_texts[i].text != NULL; i++)
        if (nt_texts[i].code == st)
            return nt_texts[i].text;
    return "server returned an error";
}

/*
 * report_rc - print an error for a libdsm int return code
 * Inputs : what = description of the failed operation, rc = DSM_* code,
 *          s = session (for the NT status)
 * Outputs: message on stderr
 * Clobbers: stderr
 */
static void report_rc(const char *what, int rc, smb_session *s)
{
    uint32_t st;

    switch (rc) {
    case DSM_ERROR_NT:
        st = smb_session_get_nt_status(s);
        fprintf(stderr, "Error: %s: %s (NT status 0x%08lX)\n", what,
                nt_text(st), (unsigned long)st);
        break;
    case DSM_ERROR_NETWORK:
        fprintf(stderr, "Error: %s: network error or unexpected server reply\n", what);
        break;
    case DSM_ERROR_CHARSET:
        fprintf(stderr, "Error: %s: character set conversion failed\n", what);
        break;
    default:
        fprintf(stderr, "Error: %s: failed (code %d)\n", what, rc);
        break;
    }
}

/*
 * report_fail - print an error for a libdsm call that returns NULL or -1 and
 *               gives no code; shows the session's last NT status if set
 * Inputs : what = description, s = session
 * Outputs: message on stderr
 * Clobbers: stderr
 */
static void report_fail(const char *what, smb_session *s)
{
    uint32_t st = smb_session_get_nt_status(s);

    if (st != 0)
        fprintf(stderr, "Error: %s: %s (NT status 0x%08lX)\n", what,
                nt_text(st), (unsigned long)st);
    else
        fprintf(stderr, "Error: %s\n", what);
}

/* ------------------------------------------------------------------------ */
/* Remote path handling                                                     */
/* ------------------------------------------------------------------------ */

/*
 * resolve_path - turn a user-typed path into a canonical share-relative path
 * Inputs : c = context (uses c->cwd), arg = path typed by the user, / or \
 *          separators, relative to cwd unless it starts with a separator;
 *          . and .. are processed (.. at the root stays at the root)
 *          out/outsz = result buffer
 * Outputs: 0 on success, -1 if too long. out is "" for the share root,
 *          otherwise "\dir\name" with a leading backslash, no trailing one
 * Clobbers: out
 */
static int resolve_path(const Ctx *c, const char *arg, char *out, size_t outsz)
{
    char tmp[PATH_LEN];
    char comp[PATH_LEN];
    size_t len = 0, clen;
    const char *p = arg;
    char *slash;

    tmp[0] = '\0';
    if (*p != '\\' && *p != '/') {
        if (str_copy(tmp, sizeof tmp, c->cwd) != 0)
            return -1;
        len = strlen(tmp);
    }
    while (*p) {
        while (*p == '\\' || *p == '/')
            p++;
        if (*p == '\0')
            break;
        clen = 0;
        while (*p && *p != '\\' && *p != '/') {
            if (clen + 1 >= sizeof comp)
                return -1;
            comp[clen++] = *p++;
        }
        comp[clen] = '\0';
        if (strcmp(comp, ".") == 0)
            continue;
        if (strcmp(comp, "..") == 0) {
            slash = strrchr(tmp, '\\');
            if (slash != NULL) {
                *slash = '\0';
                len = (size_t)(slash - tmp);
            }
            continue;
        }
        if (len + 1 + clen + 1 > sizeof tmp)
            return -1;
        tmp[len++] = '\\';
        memcpy(tmp + len, comp, clen + 1);
        len += clen;
    }
    return str_copy(out, outsz, tmp);
}

/*
 * remote_stat - find out whether a remote path exists and whether it is a
 *               directory, by opening it read-only and closing it again.
 *               Used instead of libdsm's smb_fstat(): in libdsm 0.4.3 that
 *               call sends a TRANS2 byte count that is 3 bytes short, which
 *               strict SMB1 servers (e.g. impacket's) answer by dropping the
 *               connection. Open/close uses only calls that are known good.
 * Inputs : c = context (session and tid), path = canonical remote path from
 *          resolve_path ("" = share root, which always counts as a directory)
 *          isdir = result flag, size = result size or NULL if not wanted
 * Outputs: DSM_SUCCESS with *isdir (0/1) and *size filled in, otherwise the
 *          DSM_* code from smb_fopen (e.g. DSM_ERROR_NT, status not found)
 * Clobbers: *isdir, *size; opens and closes one remote handle
 */
static int remote_stat(Ctx *c, const char *path, int *isdir, uint64_t *size)
{
    smb_fd fd = 0;
    smb_stat st;
    int rc;

    *isdir = 1;
    if (size != NULL)
        *size = 0;
    if (path[0] == '\0')
        return DSM_SUCCESS;
    rc = smb_fopen(c->sess, c->tid, path, SMB_MOD_READ, &fd);
    if (rc != DSM_SUCCESS)
        return rc;
    st = smb_stat_fd(c->sess, fd);      /* session-owned record, not copied */
    if (st == NULL) {
        smb_fclose(c->sess, fd);
        return DSM_ERROR_GENERIC;
    }
    *isdir = smb_stat_get(st, SMB_STAT_ISDIR) != 0;
    if (size != NULL)
        *size = smb_stat_get(st, SMB_STAT_SIZE);
    smb_fclose(c->sess, fd);
    return DSM_SUCCESS;
}

/*
 * need_share - check that a share is selected, else print a hint
 * Inputs : c = context
 * Outputs: 1 if a share is selected, 0 otherwise
 * Clobbers: stderr when no share
 */
static int need_share(const Ctx *c)
{
    if (!c->have_share) {
        fprintf(stderr, "No share selected. Use 'shares' to list them, then 'use <share>'.\n");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Commands                                                                 */
/* ------------------------------------------------------------------------ */

/*
 * cmd_help - print the command summary
 * Inputs : none
 * Outputs: text on stdout
 * Clobbers: stdout
 */
static void cmd_help(void)
{
    puts("Commands:");
    puts("  shares                list shares on the server");
    puts("  use <share>           connect to a share (alias: open)");
    puts("  ls [dir|pattern]      list a remote directory (alias: dir)");
    puts("  cd <dir>              change remote directory (.. \\ / allowed)");
    puts("  pwd                   show remote directory");
    puts("  get <remote> [local]  download a file");
    puts("  put <local> [remote]  upload a file (overwrites)");
    puts("  lcd [dir]             change or show local directory");
    puts("  lpwd                  show local directory");
    puts("  help                  this text");
    puts("  quit                  leave (aliases: exit, bye)");
    puts("Put names with spaces in \"double quotes\".");
}

/*
 * cmd_shares - list the shares offered by the server
 * Inputs : c = context with a logged-in session
 * Outputs: 0 on success, -1 on failure; share names on stdout
 * Clobbers: stdout, stderr; opens (and leaves open) an IPC$ tree on the server
 */
static int cmd_shares(Ctx *c)
{
    smb_share_list list = NULL;
    size_t count = 0, i;
    const char *name;
    int rc;

    rc = smb_share_get_list(c->sess, &list, &count);
    if (rc != DSM_SUCCESS || list == NULL) {
        if (rc == DSM_SUCCESS)
            rc = DSM_ERROR_GENERIC;
        report_rc("cannot list shares", rc, c->sess);
        return -1;
    }
    printf("Shares on %s:\n", c->server);
    for (i = 0; i < count; i++) {
        name = smb_share_list_at(list, i);
        if (name != NULL)
            printf("  %s\n", name);
    }
    if (count == 0)
        puts("  (none)");
    smb_share_list_destroy(list);
    return 0;
}

/*
 * cmd_use - connect to a share and make it current (cwd = share root)
 * Inputs : c = context, argc/argv = command arguments (argv[1] = share name)
 * Outputs: 0 on success, -1 on failure. On failure the previous share, if any,
 *          stays current
 * Clobbers: c->tid, c->have_share, c->share, c->cwd. The previous tree
 *          connection is not disconnected (it is released when the session
 *          ends); this keeps the rarely-used disconnect path out of play
 */
static int cmd_use(Ctx *c, int argc, char **argv)
{
    smb_tid tid = 0;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "Usage: use <share>\n");
        return -1;
    }
    if (strlen(argv[1]) >= SHARE_LEN) {
        fprintf(stderr, "Error: share name too long\n");
        return -1;
    }
    rc = smb_tree_connect(c->sess, argv[1], &tid);
    if (rc != DSM_SUCCESS) {
        report_rc("cannot connect to share", rc, c->sess);
        return -1;
    }
    c->tid = tid;
    c->have_share = 1;
    str_copy(c->share, sizeof c->share, argv[1]);
    c->cwd[0] = '\0';
    printf("Connected to \\\\%s\\%s\n", c->server, c->share);
    return 0;
}

/*
 * find_flags - quality flags of the last directory listing (bundled libdsm
 *              only; a stock libdsm has no such call, so 0 is returned)
 * Inputs : c = context
 * Outputs: bit mask of FIND_FLAG_INCOMPLETE / FIND_FLAG_RESYNCED, 0 = clean
 * Clobbers: none
 */
#ifdef SMB_FIND_INCOMPLETE
#define FIND_FLAG_INCOMPLETE SMB_FIND_INCOMPLETE
#define FIND_FLAG_RESYNCED   SMB_FIND_RESYNCED
static unsigned long find_flags(const Ctx *c)
{
    return (unsigned long)smb_session_get_find_flags(c->sess);
}
#else
#define FIND_FLAG_INCOMPLETE 0x01UL
#define FIND_FLAG_RESYNCED   0x02UL
static unsigned long find_flags(const Ctx *c)
{
    (void)c;
    return 0;
}
#endif

/*
 * cmp_entries - qsort comparator: directories first, then name (ASCII,
 *               case-insensitive)
 * Inputs : a, b = pointers to smb_stat elements
 * Outputs: <0, 0, >0
 * Clobbers: none
 */
static int cmp_entries(const void *a, const void *b)
{
    smb_stat x = *(const smb_stat *)a;
    smb_stat y = *(const smb_stat *)b;
    int dx = smb_stat_get(x, SMB_STAT_ISDIR) != 0;
    int dy = smb_stat_get(y, SMB_STAT_ISDIR) != 0;

    if (dx != dy)
        return dy - dx;
    return ci_cmp(smb_stat_name(x), smb_stat_name(y));
}

/*
 * cmd_ls - list a remote directory, a single file, or a wildcard pattern
 * Inputs : c = context, argc/argv = optional argv[1] = directory or pattern
 *          (default: current directory)
 * Outputs: 0 on success, -1 on failure; listing on stdout
 * Clobbers: stdout, stderr
 */
static int cmd_ls(Ctx *c, int argc, char **argv)
{
    char path[PATH_LEN], pat[PATH_LEN];
    char tbuf[24], sbuf[24], sbuf2[24];
    smb_stat_list list;
    smb_stat *arr, e;
    size_t n, i, k, plen;
    unsigned long ndirs = 0, nfiles = 0;
    uint64_t total = 0;
    const char *arg, *name;
    int isdir, rc;

    if (!need_share(c))
        return -1;
    if (argc > 2) {
        fprintf(stderr, "Usage: ls [dir|pattern]\n");
        return -1;
    }
    arg = (argc == 2) ? argv[1] : ".";
    if (resolve_path(c, arg, path, sizeof path) != 0) {
        fprintf(stderr, "Error: path too long\n");
        return -1;
    }

    if (strpbrk(arg, "*?") != NULL) {
        if (str_copy(pat, sizeof pat, path) != 0) {
            fprintf(stderr, "Error: path too long\n");
            return -1;
        }
    } else {
        rc = remote_stat(c, path, &isdir, NULL);
        if (rc != DSM_SUCCESS) {
            report_rc("cannot access remote path", rc, c->sess);
            return -1;
        }
        plen = strlen(path);
        if (isdir) {
            if (plen + 3 > sizeof pat) {
                fprintf(stderr, "Error: path too long\n");
                return -1;
            }
            memcpy(pat, path, plen);
            pat[plen] = '\\';
            pat[plen + 1] = '*';
            pat[plen + 2] = '\0';
        } else if (str_copy(pat, sizeof pat, path) != 0) {
            fprintf(stderr, "Error: path too long\n");
            return -1;
        }
    }

    list = smb_find(c->sess, c->tid, pat);
    if (list == NULL) {
        if (smb_session_get_nt_status(c->sess) != 0)
            report_fail("listing failed", c->sess);
        else if (find_flags(c) & FIND_FLAG_INCOMPLETE)
            fprintf(stderr, "Error: listing failed: malformed or cut-short server reply\n");
        else
            puts("No entries.");
        return 0;
    }

    n = smb_stat_list_count(list);
    arr = (smb_stat *)malloc((n ? n : 1) * sizeof *arr);
    if (arr == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        smb_stat_list_destroy(list);
        return -1;
    }
    k = 0;
    for (e = list; e != NULL && k < n; e = smb_stat_list_next(e)) {
        name = smb_stat_name(e);
        if (name == NULL || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        arr[k++] = e;
    }
    qsort(arr, k, sizeof *arr, cmp_entries);

    for (i = 0; i < k; i++) {
        e = arr[i];
        ft_str(smb_stat_get(e, SMB_STAT_WTIME), tbuf);
        if (smb_stat_get(e, SMB_STAT_ISDIR)) {
            strcpy(sbuf, "<DIR>");
            ndirs++;
        } else {
            u64_str(sbuf, smb_stat_get(e, SMB_STAT_SIZE));
            total += smb_stat_get(e, SMB_STAT_SIZE);
            nfiles++;
        }
        printf("%s  %12s  %s\n", tbuf, sbuf, smb_stat_name(e));
    }
    if (k == 0)
        puts("No entries.");
    else
        printf("%lu file(s), %lu dir(s), %s bytes\n", nfiles, ndirs,
               u64_str(sbuf2, total));
    if (find_flags(c) & FIND_FLAG_INCOMPLETE)
        fprintf(stderr, "Warning: the listing may be incomplete (the server sent a "
                        "malformed or cut-short reply)\n");
    else if (find_flags(c) & FIND_FLAG_RESYNCED)
        fprintf(stderr, "Note: the server mis-sized its directory entries; the "
                        "listing was recovered\n");

    free(arr);
    smb_stat_list_destroy(list);
    return 0;
}

/*
 * cmd_cd - change the remote directory
 * Inputs : c = context, argc/argv = argv[1] = target (with no argument the
 *          current directory is shown instead)
 * Outputs: 0 on success, -1 on failure
 * Clobbers: c->cwd on success
 */
static int cmd_cd(Ctx *c, int argc, char **argv)
{
    char path[PATH_LEN];
    int isdir, rc;

    if (!need_share(c))
        return -1;
    if (argc == 1) {
        printf("\\\\%s\\%s%s\n", c->server, c->share, c->cwd);
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "Usage: cd <dir>\n");
        return -1;
    }
    if (resolve_path(c, argv[1], path, sizeof path) != 0) {
        fprintf(stderr, "Error: path too long\n");
        return -1;
    }
    rc = remote_stat(c, path, &isdir, NULL);
    if (rc != DSM_SUCCESS) {
        report_rc("cannot access remote path", rc, c->sess);
        return -1;
    }
    if (!isdir) {
        fprintf(stderr, "Error: not a directory\n");
        return -1;
    }
    str_copy(c->cwd, sizeof c->cwd, path);
    return 0;
}

/*
 * cmd_pwd - print the current remote location as \\server\share\dir
 * Inputs : c = context
 * Outputs: 0; text on stdout
 * Clobbers: stdout
 */
static int cmd_pwd(const Ctx *c)
{
    if (!c->have_share) {
        printf("\\\\%s (no share selected)\n", c->server);
        return 0;
    }
    printf("\\\\%s\\%s%s\n", c->server, c->share, c->cwd);
    return 0;
}

/*
 * show_progress - draw a one-line transfer progress indicator
 * Inputs : done = bytes so far, total = bytes expected (0 = unknown)
 * Outputs: line on stdout, ended with carriage return
 * Clobbers: stdout
 */
static void show_progress(uint64_t done, uint64_t total)
{
    char a[24], b[24];

    if (total != 0)
        printf("\r  %s / %s bytes (%d%%)   ", u64_str(a, done), u64_str(b, total),
               (int)((done * 100) / total));
    else
        printf("\r  %s bytes   ", u64_str(a, done));
    fflush(stdout);
}

/*
 * print_summary - finish a transfer line with byte count and rate
 * Inputs : verb = "Downloaded"/"Uploaded", done = bytes, t0 = start time
 * Outputs: line on stdout
 * Clobbers: stdout
 */
static void print_summary(const char *verb, uint64_t done, time_t t0)
{
    char a[24];
    double secs = difftime(time(NULL), t0);

    printf("\r%s %s bytes", verb, u64_str(a, done));
    if (secs >= 1.0)
        printf(" in %.0f s (%.0f KB/s)", secs, (double)done / 1024.0 / secs);
    puts("                    ");
}

/*
 * cmd_get - download one remote file
 * Inputs : c = context, argc/argv = argv[1] = remote path, optional argv[2] =
 *          local file name (default: remote base name in the local cwd)
 * Outputs: 0 on success, -1 on failure
 * Clobbers: creates/overwrites the local file (partial file left on failure);
 *          stdout, stderr; allocates and frees a chunk buffer
 */
static int cmd_get(Ctx *c, int argc, char **argv)
{
    char path[PATH_LEN];
    const char *local;
    unsigned char *buf = NULL;
    FILE *out = NULL;
    smb_fd fd = 0;
    smb_stat st;
    uint64_t size, done = 0, shown = 0;
    ssize_t n;
    time_t t0;
    int rc, ret = -1;

    if (!need_share(c))
        return -1;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: get <remote> [local]\n");
        return -1;
    }
    if (resolve_path(c, argv[1], path, sizeof path) != 0 || path[0] == '\0') {
        fprintf(stderr, "Error: invalid remote path\n");
        return -1;
    }
    local = (argc == 3) ? argv[2] : base_name(argv[1]);
    if (*local == '\0') {
        fprintf(stderr, "Error: no local file name\n");
        return -1;
    }

    rc = smb_fopen(c->sess, c->tid, path, SMB_MOD_RO, &fd);
    if (rc != DSM_SUCCESS) {
        report_rc("cannot open remote file", rc, c->sess);
        return -1;
    }
    st = smb_stat_fd(c->sess, fd);
    if (st == NULL) {
        fprintf(stderr, "Error: cannot get remote file information\n");
        goto done;
    }
    if (smb_stat_get(st, SMB_STAT_ISDIR)) {
        fprintf(stderr, "Error: remote path is a directory\n");
        goto done;
    }
    size = smb_stat_get(st, SMB_STAT_SIZE);

    buf = (unsigned char *)malloc(c->chunk);
    if (buf == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto done;
    }
    out = fopen(local, "wb");
    if (out == NULL) {
        fprintf(stderr, "Error: cannot create local file '%s'\n", local);
        goto done;
    }

    t0 = time(NULL);
    while (done < size) {
        n = smb_fread(c->sess, fd, buf, c->chunk);
        if (n < 0) {
            puts("");
            report_fail("read failed (partial local file left)", c->sess);
            goto done;
        }
        if (n == 0)
            break;
        if (fwrite(buf, 1, (size_t)n, out) != (size_t)n) {
            puts("");
            fprintf(stderr, "Error: write to '%s' failed (disk full?)\n", local);
            goto done;
        }
        done += (uint64_t)n;
        if (done - shown >= PROGRESS_STEP) {
            show_progress(done, size);
            shown = done;
        }
    }
    if (fclose(out) != 0) {
        out = NULL;
        puts("");
        fprintf(stderr, "Error: closing '%s' failed\n", local);
        goto done;
    }
    out = NULL;
    if (done != size) {
        puts("");
        fprintf(stderr, "Warning: server ended the file early (%lu of %lu bytes)\n",
                (unsigned long)done, (unsigned long)size);
        goto done;
    }
    print_summary("Downloaded", done, t0);
    ret = 0;

done:
    if (out != NULL)
        fclose(out);
    if (fd != 0)
        smb_fclose(c->sess, fd);
    free(buf);
    return ret;
}

/*
 * verify_upload - read back the size of a just-uploaded remote file and
 *                 compare it with the number of bytes sent. Unpatched libdsm
 *                 0.4.3 declares a WriteAndX byte count one byte short, so a
 *                 strict server can store less than it acknowledged; without
 *                 this check such an upload looks successful.
 * Inputs : c = context, full = canonical remote path of the uploaded file
 *          (the remote handle must already be closed), sent = bytes written
 * Outputs: 0 if the remote size equals sent, or if the size cannot be read
 *          back (a warning is printed); -1 if the sizes differ (error printed)
 * Clobbers: stdout (line break), stderr; opens and closes one remote handle
 */
static int verify_upload(Ctx *c, const char *full, uint64_t sent)
{
    char a[24], b[24];
    uint64_t rsize = 0;
    int isdir = 0;

    if (remote_stat(c, full, &isdir, &rsize) != DSM_SUCCESS) {
        puts("");
        fprintf(stderr, "Warning: upload not verified: cannot read back the remote size\n");
        return 0;
    }
    if (rsize == sent)
        return 0;
    puts("");
    fprintf(stderr, "Error: upload failed verification: sent %s bytes, server holds %s "
                    "(truncated remote file left)\n", u64_str(a, sent), u64_str(b, rsize));
    fprintf(stderr, "       Likely cause: unpatched libdsm write byte count; "
                    "see libdsm-write-bytecount.patch and README.md\n");
    return -1;
}

/*
 * cmd_put - upload one local file (creates or overwrites the remote file)
 * Inputs : c = context, argc/argv = argv[1] = local file, optional argv[2] =
 *          remote path; if that is an existing directory the local base name
 *          is appended (default: local base name in the remote cwd)
 * Outputs: 0 on success, -1 on failure
 * Clobbers: creates/overwrites the remote file (partial file left on failure);
 *          stdout, stderr; allocates and frees a chunk buffer
 */
static int cmd_put(Ctx *c, int argc, char **argv)
{
    char path[PATH_LEN], full[PATH_LEN];
    const char *remote_arg, *lname;
    unsigned char *buf = NULL;
    FILE *in = NULL;
    smb_fd fd = 0;
    uint64_t total = 0, done = 0, shown = 0;
    size_t got, off, plen;
    ssize_t w;
    long flen;
    time_t t0;
    int rc, isdir, ret = -1;

    if (!need_share(c))
        return -1;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: put <local> [remote]\n");
        return -1;
    }
    lname = base_name(argv[1]);
    if (*lname == '\0') {
        fprintf(stderr, "Error: invalid local file name\n");
        return -1;
    }
    remote_arg = (argc == 3) ? argv[2] : lname;
    if (resolve_path(c, remote_arg, path, sizeof path) != 0) {
        fprintf(stderr, "Error: remote path too long\n");
        return -1;
    }

    /* an existing remote directory (or the share root) as target: append name */
    if (remote_stat(c, path, &isdir, NULL) != DSM_SUCCESS)
        isdir = 0;                      /* does not exist yet: plain new file */
    if (isdir) {
        plen = strlen(path);
        if (plen + 1 + strlen(lname) + 1 > sizeof full) {
            fprintf(stderr, "Error: remote path too long\n");
            return -1;
        }
        memcpy(full, path, plen);
        full[plen] = '\\';
        strcpy(full + plen + 1, lname);
    } else if (str_copy(full, sizeof full, path) != 0) {
        fprintf(stderr, "Error: remote path too long\n");
        return -1;
    }

    in = fopen(argv[1], "rb");
    if (in == NULL) {
        fprintf(stderr, "Error: cannot open local file '%s'\n", argv[1]);
        return -1;
    }
    if (fseek(in, 0, SEEK_END) == 0) {
        flen = ftell(in);
        if (flen > 0)
            total = (uint64_t)flen;
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: cannot read local file '%s'\n", argv[1]);
        goto done;
    }
    buf = (unsigned char *)malloc(c->chunk);
    if (buf == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto done;
    }

    rc = smb_fopen(c->sess, c->tid, full, SMB_MOD_RW, &fd);
    if (rc != DSM_SUCCESS) {
        report_rc("cannot create remote file", rc, c->sess);
        goto done;
    }

    t0 = time(NULL);
    for (;;) {
        got = fread(buf, 1, c->chunk, in);
        if (got == 0) {
            if (ferror(in)) {
                puts("");
                fprintf(stderr, "Error: read from '%s' failed\n", argv[1]);
                goto done;
            }
            break;
        }
        off = 0;
        while (off < got) {
            w = smb_fwrite(c->sess, fd, buf + off, got - off);
            if (w <= 0) {
                puts("");
                report_fail("write failed (partial remote file left)", c->sess);
                goto done;
            }
            off += (size_t)w;
        }
        done += (uint64_t)got;
        if (done - shown >= PROGRESS_STEP) {
            show_progress(done, total);
            shown = done;
        }
    }
    smb_fclose(c->sess, fd);            /* close before the read-back check */
    fd = 0;
    if (verify_upload(c, full, done) != 0)
        goto done;
    print_summary("Uploaded", done, t0);
    ret = 0;

done:
    if (fd != 0)
        smb_fclose(c->sess, fd);
    if (in != NULL)
        fclose(in);
    free(buf);
    return ret;
}

/*
 * cmd_lcd - change (or with no argument, show) the local directory
 * Inputs : argc/argv = optional argv[1] = directory
 * Outputs: 0 on success, -1 on failure; current directory on stdout
 * Clobbers: process current directory
 */
static int cmd_lcd(int argc, char **argv)
{
    char buf[PATH_LEN];

    if (argc > 2) {
        fprintf(stderr, "Usage: lcd [dir]\n");
        return -1;
    }
    if (argc == 2) {
#ifdef _WIN32
        if (!SetCurrentDirectoryA(argv[1])) {
#else
        if (chdir(argv[1]) != 0) {
#endif
            fprintf(stderr, "Error: cannot change local directory to '%s'\n", argv[1]);
            return -1;
        }
    }
#ifdef _WIN32
    if (GetCurrentDirectoryA((unsigned long)sizeof buf, buf) == 0 ||
        strlen(buf) >= sizeof buf - 1) {
#else
    if (getcwd(buf, sizeof buf) == NULL) {
#endif
        fprintf(stderr, "Error: cannot read local directory\n");
        return -1;
    }
    printf("Local directory: %s\n", buf);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Network scan (-S): find SMB1 servers on the local network                */
/* ------------------------------------------------------------------------ */


static const unsigned short scan_ports[2] = { 445, 139 };

/* SMB1 NEGOTIATE offering only "NT LM 0.12", inside a NetBIOS session message */
static const unsigned char neg_req[] = {
    0x00, 0x00, 0x00, 0x2F,                         /* NetBIOS message, 47 bytes follow */
    0xFF, 'S', 'M', 'B',                            /* SMB1 magic                       */
    0x72,                                           /* command: NEGOTIATE               */
    0x00, 0x00, 0x00, 0x00,                         /* status                           */
    0x18,                                           /* flags                            */
    0x01, 0x40,                                     /* flags2: long names, NT status    */
    0x00, 0x00,                                     /* PID high                         */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* signature                        */
    0x00, 0x00,                                     /* reserved                         */
    0x00, 0x00,                                     /* TID                              */
    0xFF, 0xFE,                                     /* PID                              */
    0x00, 0x00,                                     /* UID                              */
    0x00, 0x00,                                     /* MID                              */
    0x00,                                           /* word count                       */
    0x0C, 0x00,                                     /* byte count: 12                   */
    0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00
};
typedef char neg_req_size_check[(sizeof neg_req == 51) ? 1 : -1];

/*
 * now_ms - millisecond clock for timeouts
 * Inputs : none
 * Outputs: milliseconds from an arbitrary start; compare with a signed
 *          difference, (long)(a - b), because the value wraps
 * Clobbers: none
 */
static unsigned long now_ms(void)
{
#ifdef _WIN32
    return (unsigned long)GetTickCount();
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000L);
#endif
}

/*
 * sock_nonblock - put a socket into non-blocking mode
 * Inputs : s = open socket
 * Outputs: 0 on success, -1 on failure
 * Clobbers: socket flags
 */
static int sock_nonblock(sock_t s)
{
#ifdef _WIN32
    u_long on = 1;

    return ioctlsocket(s, FIONBIO, &on) == 0 ? 0 : -1;
#else
    int fl = fcntl(s, F_GETFL, 0);

    return (fl >= 0 && fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0) ? 0 : -1;
#endif
}

/*
 * sock_would_block - was the last socket error "operation in progress"?
 * Inputs : none (reads WSAGetLastError / errno)
 * Outputs: non-zero if the call would block or is still in progress
 * Clobbers: none
 */
static int sock_would_block(void)
{
#ifdef _WIN32
    int e = WSAGetLastError();

    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
#else
    return errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

/*
 * ip_text - format an address as dotted quad
 * Inputs : ip = host byte order, buf = at least 16 bytes
 * Outputs: buf holds the text
 * Clobbers: buf
 */
static void ip_text(uint32_t ip, char *buf)
{
    sprintf(buf, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 255),
            (unsigned)((ip >> 8) & 255), (unsigned)(ip & 255));
}

/*
 * prefix_of_mask - prefix length of a netmask
 * Inputs : mask = host byte order
 * Outputs: 0..32, or -1 if the mask is not contiguous
 * Clobbers: none
 */
static int prefix_of_mask(uint32_t mask)
{
    int n = 0;
    uint32_t bit = 0x80000000U, m;

    while (n < 32 && (mask & bit) != 0) {
        n++;
        bit >>= 1;
    }
    m = (n == 0) ? 0 : (uint32_t)(0xFFFFFFFFU << (32 - n));
    return (m == mask) ? n : -1;
}

/*
 * make_net - describe the network containing an address
 * Inputs : ip = host byte order, prefix = 0..32, out = result
 * Outputs: *out; hosts are first..last, which leaves out the network and
 *          broadcast addresses except for /31 and /32
 * Clobbers: *out
 */
static void make_net(uint32_t ip, int prefix, ScanNet *out)
{
    uint32_t mask = (prefix == 0) ? 0 : (uint32_t)(0xFFFFFFFFU << (32 - prefix));
    uint32_t net = ip & mask, bcast = net | (uint32_t)~mask;

    out->net = net;
    out->prefix = prefix;
    out->orig_prefix = prefix;
    out->first = (prefix <= 30) ? net + 1 : net;
    out->last = (prefix <= 30) ? bcast - 1 : bcast;
}

/*
 * get_local_addrs - list this machine's IPv4 addresses and netmasks
 * Inputs : out = array, max = its size
 * Outputs: number of entries filled (0 if the adapters cannot be read); host
 *          byte order. Includes loopback and link-local; callers filter
 * Clobbers: out
 */
#ifdef _WIN32
static int get_local_addrs(LocalAddr *out, int max)
{
    IfInfo info[SCAN_MAX_LOCAL];
    unsigned long bytes = 0;
    sock_t s;
    int i, cnt, n = 0;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == SOCK_BAD)
        return 0;
    if (WSAIoctl(s, SMB_SIO_GET_INTERFACE_LIST, NULL, 0, info, (unsigned long)sizeof info,
                 &bytes, NULL, NULL) != 0)
        bytes = 0;
    sock_close(s);
    cnt = (int)(bytes / sizeof(IfInfo));
    for (i = 0; i < cnt && n < max; i++) {
        if ((info[i].flags & SMB_IFF_UP) == 0 || info[i].addr[0] != AF_INET)
            continue;
        out[n].ip = ((uint32_t)info[i].addr[4] << 24) | ((uint32_t)info[i].addr[5] << 16) |
                    ((uint32_t)info[i].addr[6] << 8) | (uint32_t)info[i].addr[7];
        out[n].mask = ((uint32_t)info[i].mask[4] << 24) | ((uint32_t)info[i].mask[5] << 16) |
                      ((uint32_t)info[i].mask[6] << 8) | (uint32_t)info[i].mask[7];
        if (out[n].ip != 0)
            n++;
    }
    return n;
}
#else
static int get_local_addrs(LocalAddr *out, int max)
{
    struct ifaddrs *list, *ifa;
    int n = 0;

    if (getifaddrs(&list) != 0)
        return 0;
    for (ifa = list; ifa != NULL && n < max; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL ||
            ifa->ifa_addr->sa_family != AF_INET || (ifa->ifa_flags & IFF_UP) == 0)
            continue;
        out[n].ip = ntohl(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);
        out[n].mask = ntohl(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr);
        n++;
    }
    freeifaddrs(list);
    return n;
}
#endif

/*
 * parse_cidr - parse "a.b.c.d/n" (or a bare address, meaning a single host)
 * Inputs : text = user argument, out = result
 * Outputs: 0 on success, -1 if malformed or the prefix is outside
 *          SCAN_MIN_PREFIX..32
 * Clobbers: *out only on success
 */
static int parse_cidr(const char *text, ScanNet *out)
{
    char addr[20], *end;
    const char *slash = strchr(text, '/');
    size_t n = (slash != NULL) ? (size_t)(slash - text) : strlen(text);
    unsigned long prefix = 32;
    uint32_t ip;

    if (n == 0 || n >= sizeof addr)
        return -1;
    memcpy(addr, text, n);
    addr[n] = '\0';
    if (!parse_ipv4(addr, &ip))
        return -1;
    if (slash != NULL) {
        prefix = strtoul(slash + 1, &end, 10);
        if (*end != '\0' || prefix < SCAN_MIN_PREFIX || prefix > 32)
            return -1;
    }
    make_net(ntohl(ip), (int)prefix, out);
    return 0;
}

/*
 * auto_nets - work out which networks to scan from the local adapters
 * Inputs : la/nl = local addresses, nets/max = result array
 * Outputs: number of networks. Skips loopback, link-local (169.254/16),
 *          unreadable masks and /31, /32 links. A subnet wider than
 *          SCAN_AUTO_PREFIX is clamped to the /24 holding the local address
 *          (orig_prefix keeps the adapter's real prefix). Duplicates removed
 * Clobbers: nets
 */
static int auto_nets(const LocalAddr *la, int nl, ScanNet *nets, int max)
{
    ScanNet t;
    int i, k, n = 0, prefix, orig;

    for (i = 0; i < nl && n < max; i++) {
        if (la[i].ip == 0 || (la[i].ip >> 24) == 127 || (la[i].ip >> 16) == 0xA9FEU)
            continue;
        prefix = prefix_of_mask(la[i].mask);
        if (prefix < 0 || prefix > 30)
            continue;
        orig = prefix;
        if (prefix < SCAN_AUTO_PREFIX)
            prefix = 24;
        make_net(la[i].ip, prefix, &t);
        t.orig_prefix = orig;
        for (k = 0; k < n; k++)
            if (nets[k].net == t.net && nets[k].prefix == t.prefix)
                break;
        if (k == n)
            nets[n++] = t;
    }
    return n;
}

/*
 * next_target - next host to probe, skipping this machine's own addresses
 * Inputs : it = iterator (zero it, set nets/nn/la/nl, fresh = 1, before use)
 * Outputs: 1 and *ip (host byte order), or 0 when every network is done
 * Clobbers: *it
 */
static int next_target(TargetIter *it, uint32_t *ip)
{
    int i;

    for (;;) {
        if (it->ni >= it->nn)
            return 0;
        if (it->fresh) {
            it->cur = it->nets[it->ni].first;
            it->fresh = 0;
        } else if (it->cur >= it->nets[it->ni].last) {
            it->ni++;
            it->fresh = 1;
            continue;
        } else {
            it->cur++;
        }
        for (i = 0; i < it->nl; i++)
            if (it->la[i].ip == it->cur)
                break;
        if (i < it->nl)
            continue;
        *ip = it->cur;
        return 1;
    }
}

/*
 * nb_encode - first-level NetBIOS name encoding (RFC 1001)
 * Inputs : name = up to 15 characters, suffix = 16th byte, out = 34 bytes
 * Outputs: out = length byte 0x20, 32 encoded characters, terminating 0
 * Clobbers: out
 */
static void nb_encode(const char *name, int suffix, unsigned char *out)
{
    unsigned char raw[16];
    size_t n = strlen(name);
    int i;

    memset(raw, ' ', 15);
    memcpy(raw, name, n > 15 ? 15 : n);
    raw[15] = (unsigned char)suffix;
    out[0] = 0x20;
    for (i = 0; i < 16; i++) {
        out[1 + 2 * i] = (unsigned char)('A' + (raw[i] >> 4));
        out[2 + 2 * i] = (unsigned char)('A' + (raw[i] & 0x0F));
    }
    out[33] = 0;
}

/*
 * smb1_reply - classify a reply to neg_req
 * Inputs : b/n = bytes received so far (NetBIOS header included)
 * Outputs: 1 = SMB1 NEGOTIATE accepted with dialect NT LM 0.12,
 *          0 = anything else (SMB2 reply, error status, no common dialect),
 *          -1 = not enough bytes yet
 * Clobbers: none
 */
static int smb1_reply(const unsigned char *b, int n)
{
    if (n < 8)
        return -1;
    if (memcmp(b + 4, "\xff" "SMB", 4) != 0)
        return 0;
    if (n < 39)
        return -1;
    if (b[8] != 0x72 || b[9] != 0 || b[10] != 0 || b[11] != 0 || b[12] != 0 ||
        b[36] < 1 || b[37] != 0 || b[38] != 0)
        return 0;
    return 1;
}

static void job_start_port(Job *j);

/*
 * job_finish_port - end the current port probe, then start tcp/139 after
 *                   tcp/445, or mark the host done after tcp/139
 * Inputs : j = job, res = R_NONE (no connection), R_OPEN (connected, no SMB1
 *          reply) or R_SMB1
 * Outputs: j->res[] updated; j->state = ST_DONE when both ports are finished
 * Clobbers: closes j->s and may open a new socket
 */
static void job_finish_port(Job *j, int res)
{
    if (j->s != SOCK_BAD) {
        sock_close(j->s);
        j->s = SOCK_BAD;
    }
    j->res[j->pidx] = res;
    if (j->pidx == 0) {
        j->pidx = 1;
        job_start_port(j);
    } else {
        j->state = ST_DONE;
    }
}

/*
 * job_on_connected - the TCP connection is up: send the first request
 * Inputs : j = job in ST_CONNECT
 * Outputs: tcp/445: NEGOTIATE sent, state ST_NEGRESP. tcp/139: NetBIOS session
 *          request (called name *SMBSERVER) sent, state ST_SESSRESP. A failed
 *          send ends the port as R_OPEN
 * Clobbers: j->state, j->got
 */
static void job_on_connected(Job *j)
{
    unsigned char pkt[72];
    const unsigned char *p = neg_req;
    int len = (int)sizeof neg_req, next = ST_NEGRESP;

    if (scan_ports[j->pidx] == 139) {
        pkt[0] = 0x81;
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 68;
        nb_encode("*SMBSERVER", 0x20, pkt + 4);
        nb_encode("SMBFTP", 0x00, pkt + 38);
        p = pkt;
        len = 72;
        next = ST_SESSRESP;
    }
    j->got = 0;
    if (send(j->s, (const char *)p, len, MSG_NOSIGNAL) != len) {
        job_finish_port(j, R_OPEN);
        return;
    }
    j->state = next;
}

/*
 * job_on_readable - read a reply and advance the probe
 * Inputs : j = job in ST_SESSRESP or ST_NEGRESP with data (or EOF) waiting
 * Outputs: positive session response -> NEGOTIATE sent; complete SMB1 reply
 *          -> R_SMB1; closed connection or anything else -> R_OPEN
 * Clobbers: j->rx, j->got, j->state
 */
static void job_on_readable(Job *j)
{
    int n, v;

    n = (int)recv(j->s, (char *)j->rx + j->got, (int)sizeof j->rx - j->got, 0);
    if (n < 0 && sock_would_block())
        return;
    if (n <= 0) {
        job_finish_port(j, R_OPEN);
        return;
    }
    j->got += n;
    if (j->state == ST_SESSRESP) {
        if (j->got < 4)
            return;
        if (j->rx[0] != 0x82) {
            job_finish_port(j, R_OPEN);
            return;
        }
        j->got = 0;
        if (send(j->s, (const char *)neg_req, (int)sizeof neg_req, MSG_NOSIGNAL) !=
            (int)sizeof neg_req) {
            job_finish_port(j, R_OPEN);
            return;
        }
        j->state = ST_NEGRESP;
        return;
    }
    v = smb1_reply(j->rx, j->got);
    if (v > 0)
        job_finish_port(j, R_SMB1);
    else if (v == 0 || j->got >= (int)sizeof j->rx)
        job_finish_port(j, R_OPEN);
}

/*
 * job_start_port - open a socket and start connecting to the job's host on
 *                  the port selected by j->pidx
 * Inputs : j = job with ip, pidx and wait set
 * Outputs: state ST_CONNECT (or later if the connect completed at once); an
 *          immediate failure ends the port as R_NONE
 * Clobbers: j->s, j->deadline, j->state, j->got
 */
static void job_start_port(Job *j)
{
    struct sockaddr_in sa;
    int rc;

    j->deadline = now_ms() + j->wait;
    j->got = 0;
    j->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (j->s == SOCK_BAD) {
        job_finish_port(j, R_NONE);
        return;
    }
    if (sock_nonblock(j->s) != 0) {
        job_finish_port(j, R_NONE);
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(scan_ports[j->pidx]);
    sa.sin_addr.s_addr = htonl(j->ip);
    rc = connect(j->s, (struct sockaddr *)&sa, sizeof sa);
    if (rc == 0) {
        j->state = ST_CONNECT;
        job_on_connected(j);
    } else if (sock_would_block()) {
        j->state = ST_CONNECT;
    } else {
        job_finish_port(j, R_NONE);
    }
}

/*
 * scan_hosts - probe every target from the iterator, many hosts in parallel
 * Inputs : it = target iterator, wait_ms = time limit per port, hits/maxhits =
 *          result array
 * Outputs: number of hosts with at least one open port (stored in hits, in
 *          completion order), or -1 on a select() failure; *scanned = hosts
 *          probed, *dropped = hosts not stored because hits was full
 * Clobbers: *it, hits, *scanned, *dropped; opens and closes sockets
 */
static int scan_hosts(TargetIter *it, unsigned long wait_ms, Hit *hits, int maxhits,
                      unsigned long *scanned, unsigned long *dropped)
{
    Job jobs[SCAN_MAX_PAR];
    fd_set rd, wr, ex;
    struct timeval tv;
    sock_len_t el;
    unsigned long now;
    long left, soonest;
    uint32_t ip;
    int i, active = 0, nfd, err, nhit = 0, more = 1, maxfd, rc;
    Job *j;

    memset(jobs, 0, sizeof jobs);
    for (i = 0; i < SCAN_MAX_PAR; i++)
        jobs[i].s = SOCK_BAD;

    for (;;) {
        for (i = 0; i < SCAN_MAX_PAR; i++) {            /* collect finished hosts */
            j = &jobs[i];
            if (j->state != ST_DONE)
                continue;
            (*scanned)++;
            if (j->res[0] != R_NONE || j->res[1] != R_NONE) {
                if (nhit < maxhits) {
                    hits[nhit].ip = j->ip;
                    hits[nhit].res[0] = j->res[0];
                    hits[nhit].res[1] = j->res[1];
                    nhit++;
                } else {
                    (*dropped)++;
                }
            }
            j->state = ST_FREE;
            active--;
        }
        for (i = 0; i < SCAN_MAX_PAR && more; i++) {    /* start new hosts        */
            j = &jobs[i];
            if (j->state != ST_FREE)
                continue;
            if (!next_target(it, &ip)) {
                more = 0;
                break;
            }
            memset(j, 0, sizeof *j);
            j->ip = ip;
            j->wait = wait_ms;
            j->s = SOCK_BAD;
            active++;
            job_start_port(j);
        }
        if (active == 0)
            break;

        FD_ZERO(&rd);
        FD_ZERO(&wr);
        FD_ZERO(&ex);
        nfd = 0;
        maxfd = -1;
        soonest = (long)wait_ms;
        now = now_ms();
        for (i = 0; i < SCAN_MAX_PAR; i++) {
            j = &jobs[i];
            if (j->state != ST_CONNECT && j->state != ST_SESSRESP && j->state != ST_NEGRESP)
                continue;
            if (j->state == ST_CONNECT) {
                FD_SET(j->s, &wr);
                FD_SET(j->s, &ex);
            } else {
                FD_SET(j->s, &rd);
            }
            nfd++;
#ifndef _WIN32
            if ((int)j->s > maxfd)
                maxfd = (int)j->s;
#endif
            left = (long)(j->deadline - now);
            if (left < 0)
                left = 0;
            if (left < soonest)
                soonest = left;
        }
        if (nfd == 0)
            continue;                                   /* only finished hosts    */
        tv.tv_sec = soonest / 1000;
        tv.tv_usec = (soonest % 1000) * 1000;
        rc = select(maxfd + 1, &rd, &wr, &ex, &tv);
        if (rc < 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            for (i = 0; i < SCAN_MAX_PAR; i++)
                if (jobs[i].s != SOCK_BAD)
                    sock_close(jobs[i].s);
            return -1;
        }
        now = now_ms();
        for (i = 0; i < SCAN_MAX_PAR; i++) {
            j = &jobs[i];
            if (j->state == ST_CONNECT) {
                if (FD_ISSET(j->s, &wr) || FD_ISSET(j->s, &ex)) {
                    err = 1;
                    el = (sock_len_t)sizeof err;
                    if (getsockopt(j->s, SOL_SOCKET, SO_ERROR, (char *)&err, &el) != 0)
                        err = 1;
                    if (err == 0 && FD_ISSET(j->s, &wr))
                        job_on_connected(j);
                    else
                        job_finish_port(j, R_NONE);
                }
            } else if (j->state == ST_SESSRESP || j->state == ST_NEGRESP) {
                if (FD_ISSET(j->s, &rd))
                    job_on_readable(j);
            }
            if ((j->state == ST_CONNECT || j->state == ST_SESSRESP ||
                 j->state == ST_NEGRESP) && (long)(now - j->deadline) >= 0)
                job_finish_port(j, j->state == ST_CONNECT ? R_NONE : R_OPEN);
        }
    }
    return nhit;
}

/*
 * cmp_hit - qsort comparator, ascending address
 * Inputs : a, b = Hit pointers
 * Outputs: <0, 0, >0
 * Clobbers: none
 */
static int cmp_hit(const void *a, const void *b)
{
    uint32_t x = ((const Hit *)a)->ip, y = ((const Hit *)b)->ip;

    return (x > y) - (x < y);
}

/*
 * print_hits - report the scan result
 * Inputs : hits/nh = results, scanned = hosts probed, dropped = results that
 *          did not fit in the array
 * Outputs: SMB1 servers first (with the ports that answered), then hosts with
 *          an SMB port open but no SMB1 reply, then a summary line
 * Clobbers: hits (sorted by address); stdout
 */
static void print_hits(Hit *hits, int nh, unsigned long scanned, unsigned long dropped)
{
    char a[20];
    int i, p, n1 = 0, n2 = 0;

    qsort(hits, (size_t)nh, sizeof hits[0], cmp_hit);
    for (i = 0; i < nh; i++) {
        if (hits[i].res[0] != R_SMB1 && hits[i].res[1] != R_SMB1)
            continue;
        if (n1++ == 0)
            puts("\nSMB1 servers:");
        ip_text(hits[i].ip, a);
        printf("  %-15s", a);
        for (p = 0; p < 2; p++)
            if (hits[i].res[p] == R_SMB1)
                printf("  tcp/%u", (unsigned)scan_ports[p]);
        if (hits[i].res[0] != R_SMB1)
            printf("  (connect with -t nbt)");
        puts("");
    }
    for (i = 0; i < nh; i++) {
        if (hits[i].res[0] == R_SMB1 || hits[i].res[1] == R_SMB1)
            continue;
        if (n2++ == 0)
            puts("\nSMB port open but no SMB1 reply (SMB1 disabled, or access restricted):");
        ip_text(hits[i].ip, a);
        printf("  %-15s", a);
        for (p = 0; p < 2; p++)
            if (hits[i].res[p] == R_OPEN)
                printf("  tcp/%u", (unsigned)scan_ports[p]);
        puts("");
    }
    printf("\nScanned %lu host%s: %d SMB1 server%s, %d other%s with SMB open.\n",
           scanned, scanned == 1 ? "" : "s", n1, n1 == 1 ? "" : "s", n2, n2 == 1 ? "" : "s");
    if (dropped != 0)
        printf("%lu further hosts were not listed (result table full).\n", dropped);
    if (n1 > 0)
        puts("Connect with:  smbftp <address>");
}

/*
 * run_scan - scan for SMB1 servers and print them (the -S mode)
 * Inputs : cidr = "a.b.c.d/n" or a single address to scan, or NULL to scan
 *          the subnet of every local adapter; wait_ms = time limit per port
 * Outputs: 0 on success, 1 on failure, 2 on a bad network argument. This
 *          machine's own addresses are never probed
 * Clobbers: stdout, stderr; starts and stops Winsock on Windows
 */
static int run_scan(const char *cidr, unsigned long wait_ms)
{
#ifdef _WIN32
    WSADATA wsa;
#endif
    static Hit hits[SCAN_MAX_HITS];
    LocalAddr la[SCAN_MAX_LOCAL];
    ScanNet nets[SCAN_MAX_NETS];
    TargetIter it;
    unsigned long total = 0, scanned = 0, dropped = 0, count;
    char a[20], b[20];
    int nl, nn, i, k, nh, rc = 1;

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Error: Winsock initialisation failed.\n");
        return 1;
    }
#endif
    nl = get_local_addrs(la, SCAN_MAX_LOCAL);
    if (cidr != NULL) {
        if (parse_cidr(cidr, &nets[0]) != 0) {
            fprintf(stderr, "Error: '%s' is not a valid network; use a.b.c.d/n with n = %d..32\n",
                    cidr, SCAN_MIN_PREFIX);
            rc = 2;
            goto out;
        }
        nn = 1;
    } else {
        nn = auto_nets(la, nl, nets, SCAN_MAX_NETS);
        if (nn == 0) {
            fprintf(stderr, "Error: no usable local IPv4 network found; name one, e.g.  "
                            "smbftp -S 192.168.4.0/24\n");
            goto out;
        }
    }

    printf("Scanning for SMB1 servers (tcp/445 and tcp/139, %lu ms limit per port)\n", wait_ms);
    for (i = 0; i < nn; i++) {
        count = (unsigned long)(nets[i].last - nets[i].first) + 1UL;
        ip_text(nets[i].net, a);
        printf("  %s/%d, %lu address%s", a, nets[i].prefix, count, count == 1 ? "" : "es");
        for (k = 0; k < nl; k++) {
            if (la[k].ip >= nets[i].first && la[k].ip <= nets[i].last) {
                ip_text(la[k].ip, b);
                printf(", own %s excluded", b);
                count--;
            }
        }
        if (nets[i].orig_prefix != nets[i].prefix)
            printf("; adapter subnet is /%d, scanning its /%d only",
                   nets[i].orig_prefix, nets[i].prefix);
        puts("");
        total += count;
    }
    if (total == 0) {
        puts("Nothing to scan.");
        rc = 0;
        goto out;
    }
    fflush(stdout);

    memset(&it, 0, sizeof it);
    it.nets = nets;
    it.nn = nn;
    it.fresh = 1;
    it.la = la;
    it.nl = nl;
    nh = scan_hosts(&it, wait_ms, hits, SCAN_MAX_HITS, &scanned, &dropped);
    if (nh < 0) {
        fprintf(stderr, "Error: scan aborted (select failed)\n");
        goto out;
    }
    print_hits(hits, nh, scanned, dropped);
    rc = 0;

out:
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Connection setup and main loop                                           */
/* ------------------------------------------------------------------------ */

/*
 * usage - print command-line help
 * Inputs : exe = program name
 * Outputs: text on stderr
 * Clobbers: stderr
 */
static void usage(const char *exe)
{
    fprintf(stderr, "smbftp %s - FTP-style SMB1 client\n\n", SMBFTP_VERSION);
    fprintf(stderr, "Usage: %s [options] <IPv4-address>\n\n", exe);
    fprintf(stderr, "  -u user     login name          (default: guest)\n");
    fprintf(stderr, "  -p pass     password            (default: empty)\n");
    fprintf(stderr, "  -d domain   domain/workgroup    (default: WORKGROUP)\n");
    fprintf(stderr, "  -n name     server NetBIOS name, max %d chars\n", NBNAME_MAX);
    fprintf(stderr, "  -t mode     auto | tcp | nbt    (default: auto)\n");
    fprintf(stderr, "  -s share    connect to this share after login\n");
    fprintf(stderr, "  -b bytes    transfer chunk size %d..%d (default %d)\n",
            MIN_CHUNK, MAX_CHUNK, DEF_CHUNK);
    fprintf(stderr, "  -h          this help\n\n");
    fprintf(stderr, "Scan for SMB1 servers (no subnet mask needed):\n");
    fprintf(stderr, "  %s -S [-w ms] [network]\n", exe);
    fprintf(stderr, "  -S          scan the local subnet(s); own addresses are skipped\n");
    fprintf(stderr, "  network     optional a.b.c.d/n (n = %d..32) or one address\n", SCAN_MIN_PREFIX);
    fprintf(stderr, "  -w ms       time limit per port probe %d..%d (default %d)\n\n",
            MIN_WAIT_MS, MAX_WAIT_MS, DEF_WAIT_MS);
    fprintf(stderr, "Example: %s 192.168.4.20\n", exe);
    fprintf(stderr, "         %s -u fred -p secret -s docs 192.168.4.20\n", exe);
    fprintf(stderr, "         %s -S\n", exe);
    fprintf(stderr, "         %s -S 192.168.4.0/24\n", exe);
}

/*
 * connect_server - open an SMB1 session using the requested transport(s)
 * Inputs : ip = server address (network byte order), ip_text = same as text,
 *          mode = 0 auto (tcp then nbt), 1 tcp, 2 nbt,
 *          nbname = NetBIOS name or NULL for the defaults
 * Outputs: new connected (not yet logged in) session, or NULL if every attempt
 *          failed; progress and reasons on stderr
 * Clobbers: stdout, stderr. Each attempt uses a fresh session
 */
static smb_session *connect_server(uint32_t ip, const char *ip_text, int mode,
                                   const char *nbname)
{
    static const int order_auto[2] = { SMB_TRANSPORT_TCP, SMB_TRANSPORT_NBT };
    int attempt[2];
    int natt, i, rc;
    smb_session *s;
    const char *name, *tname;

    if (mode == 1) {
        attempt[0] = SMB_TRANSPORT_TCP;
        natt = 1;
    } else if (mode == 2) {
        attempt[0] = SMB_TRANSPORT_NBT;
        natt = 1;
    } else {
        attempt[0] = order_auto[0];
        attempt[1] = order_auto[1];
        natt = 2;
    }

    for (i = 0; i < natt; i++) {
        tname = (attempt[i] == SMB_TRANSPORT_TCP) ? "direct TCP (445)" : "NetBIOS (139)";
        name = (nbname != NULL) ? nbname
             : (attempt[i] == SMB_TRANSPORT_TCP ? ip_text : "*SMBSERVER");
        printf("Connecting to %s using SMB1 over %s...\n", ip_text, tname);
        fflush(stdout);
        s = smb_session_new();
        if (s == NULL) {
            fprintf(stderr, "Error: could not allocate SMB session\n");
            return NULL;
        }
        rc = smb_session_connect(s, name, ip, attempt[i]);
        if (rc == DSM_SUCCESS)
            return s;
        report_rc("negotiation failed", rc, s);
        smb_session_destroy(s);
    }
    return NULL;
}

/*
 * main - parse options, connect, log in, run the command loop
 * Inputs : argc/argv = command line (see the file header)
 * Outputs: exit status 0 / 1 / 2
 * Clobbers: everything it owns; Winsock is started and cleaned up here
 */
int main(int argc, char **argv)
{
#ifdef _WIN32
    WSADATA wsa;
#endif
    Ctx ctx;
    const char *user = "guest", *pass = "", *domain = "WORKGROUP";
    const char *nbname = NULL, *init_share = NULL, *host = NULL;
    char line[LINE_LEN], prompt[SERVER_LEN + SHARE_LEN + PATH_LEN];
    char *av[MAX_ARGS];
    char *end;
    uint32_t ip;
    unsigned long chunk = DEF_CHUNK, wait_ms = DEF_WAIT_MS;
    int mode = 0, scan = 0, i, ac, rc, guest, ret = 1;
    size_t ll;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "/?") == 0 ||
            strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            char opt = argv[i][1];

            if (opt == 'S' && argv[i][2] == '\0') {     /* flag, takes no value */
                scan = 1;
                continue;
            }
            if (argv[i][2] != '\0' || strchr("updntsbw", opt) == NULL) {
                fprintf(stderr, "Error: unknown option '%s'\n\n", argv[i]);
                usage(argv[0]);
                return 2;
            }
            if (++i >= argc) {
                fprintf(stderr, "Error: option -%c needs a value\n\n", opt);
                usage(argv[0]);
                return 2;
            }
            switch (opt) {
            case 'u': user = argv[i]; break;
            case 'p': pass = argv[i]; break;
            case 'd': domain = argv[i]; break;
            case 'n': nbname = argv[i]; break;
            case 's': init_share = argv[i]; break;
            case 't':
                if (ci_cmp(argv[i], "auto") == 0) mode = 0;
                else if (ci_cmp(argv[i], "tcp") == 0) mode = 1;
                else if (ci_cmp(argv[i], "nbt") == 0) mode = 2;
                else {
                    fprintf(stderr, "Error: -t must be auto, tcp or nbt\n");
                    return 2;
                }
                break;
            case 'b':
                chunk = strtoul(argv[i], &end, 10);
                if (*end != '\0' || chunk < MIN_CHUNK || chunk > MAX_CHUNK) {
                    fprintf(stderr, "Error: -b must be %d..%d\n", MIN_CHUNK, MAX_CHUNK);
                    return 2;
                }
                break;
            case 'w':
                wait_ms = strtoul(argv[i], &end, 10);
                if (*end != '\0' || wait_ms < MIN_WAIT_MS || wait_ms > MAX_WAIT_MS) {
                    fprintf(stderr, "Error: -w must be %d..%d\n", MIN_WAIT_MS, MAX_WAIT_MS);
                    return 2;
                }
                break;
            }
        } else if (host == NULL) {
            host = argv[i];
        } else {
            fprintf(stderr, "Error: unexpected argument '%s'\n\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }
    if (scan)
        return run_scan(host, wait_ms);     /* host, if given, is the network */
    if (host == NULL) {
        usage(argv[0]);
        return 2;
    }
    if (!parse_ipv4(host, &ip)) {
        fprintf(stderr, "Error: '%s' is not a valid IPv4 address.\n", host);
        return 2;
    }
    if (nbname != NULL && (strlen(nbname) == 0 || strlen(nbname) > NBNAME_MAX)) {
        fprintf(stderr, "Error: NetBIOS name must be 1..%d characters\n", NBNAME_MAX);
        return 2;
    }
    if (strlen(user) >= SMB_CREDS_MAXLEN || strlen(pass) >= SMB_CREDS_MAXLEN ||
        strlen(domain) >= SMB_CREDS_MAXLEN) {
        fprintf(stderr, "Error: user, password and domain are limited to %d characters\n",
                SMB_CREDS_MAXLEN - 1);
        return 2;
    }

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Error: Winsock initialisation failed.\n");
        return 1;
    }
#endif

    memset(&ctx, 0, sizeof ctx);
    ctx.chunk = chunk;
    str_copy(ctx.server, sizeof ctx.server, host);

    ctx.sess = connect_server(ip, host, mode, nbname);
    if (ctx.sess == NULL) {
        fprintf(stderr, "Error: could not establish an SMB1 session with %s.\n", host);
        goto finish;
    }

    smb_session_set_creds(ctx.sess, domain, user, pass);
    rc = smb_session_login(ctx.sess);
    if (rc != DSM_SUCCESS) {
        report_rc("login failed", rc, ctx.sess);
        fprintf(stderr, "Hint: try -u, -p and -d (the default is user 'guest', empty password).\n");
        goto finish;
    }
    guest = smb_session_is_guest(ctx.sess);
    printf("Logged in as %s\\%s%s.\n", domain, user, guest == 1 ? " (mapped to guest by server)" : "");
    puts("Type 'help' for commands.");

    if (init_share != NULL) {
        av[0] = (char *)"use";
        av[1] = (char *)init_share;
        cmd_use(&ctx, 2, av);
    }

    ret = 0;
    for (;;) {
        if (ctx.have_share)
            sprintf(prompt, "smb:\\%s%s> ", ctx.share, ctx.cwd);
        else
            strcpy(prompt, "smb> ");
        fputs(prompt, stdout);
        fflush(stdout);
        if (fgets(line, sizeof line, stdin) == NULL) {
            puts("");
            break;
        }
        ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\n') {
            line[--ll] = '\0';
            if (ll > 0 && line[ll - 1] == '\r')
                line[--ll] = '\0';
        } else if (!feof(stdin)) {
            int ch;
            while ((ch = getc(stdin)) != '\n' && ch != EOF)
                ;
            fprintf(stderr, "Error: command line too long\n");
            continue;
        }

        ac = tokenize(line, av, MAX_ARGS);
        if (ac < 0) {
            fprintf(stderr, "Error: too many arguments\n");
            continue;
        }
        if (ac == 0)
            continue;

        if (ci_cmp(av[0], "quit") == 0 || ci_cmp(av[0], "exit") == 0 ||
            ci_cmp(av[0], "bye") == 0)
            break;
        else if (ci_cmp(av[0], "help") == 0 || strcmp(av[0], "?") == 0)
            cmd_help();
        else if (ci_cmp(av[0], "shares") == 0)
            cmd_shares(&ctx);
        else if (ci_cmp(av[0], "use") == 0 || ci_cmp(av[0], "open") == 0)
            cmd_use(&ctx, ac, av);
        else if (ci_cmp(av[0], "ls") == 0 || ci_cmp(av[0], "dir") == 0)
            cmd_ls(&ctx, ac, av);
        else if (ci_cmp(av[0], "cd") == 0)
            cmd_cd(&ctx, ac, av);
        else if (ci_cmp(av[0], "pwd") == 0)
            cmd_pwd(&ctx);
        else if (ci_cmp(av[0], "get") == 0)
            cmd_get(&ctx, ac, av);
        else if (ci_cmp(av[0], "put") == 0)
            cmd_put(&ctx, ac, av);
        else if (ci_cmp(av[0], "lcd") == 0)
            cmd_lcd(ac, av);
        else if (ci_cmp(av[0], "lpwd") == 0)
            cmd_lcd(1, av);
        else
            fprintf(stderr, "Unknown command '%s'. Type 'help'.\n", av[0]);
    }

finish:
    if (ctx.sess != NULL)
        smb_session_destroy(ctx.sess);
#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}
