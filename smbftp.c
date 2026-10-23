/*
 * smbftp - minimal FTP-style command-line client for SMB1 file servers
 *
 * Version : 0.8
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
 *   build.cmd                          Windows, TCC only: downloads, checks and
 *                                      patches libdsm (patches/), then builds it
 *                                      with smbftp.c and smb_engine.c into one
 *                                      smbftp.exe (no GNU tools, no WSL, no
 *                                      meson, no libtasn1)
 *   make                               Linux: the same download-and-patch, then
 *                                      the system C compiler -> ./smbftp
 *   smbftp.c needs smbftp.h and smb_engine.c/h (and, on Windows,
 *   winport/winmini.h) beside it, and the patched libdsm in ./libdsm.
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
 *     mismatch, leaving the truncated file behind. The fix is part of
 *     patches/0001-tcc-windows-port.diff, which build.cmd and the Makefile
 *     apply to the libdsm they download (see README.md).
 *   - 0.6 and later need the patched libdsm (patches/0002-v0.6-fixes.diff adds
 *     smb_session_get_find_flags and many reply-validation fixes). Built
 *     against a stock system libdsm it still compiles but lacks the "listing
 *     may be incomplete" warning and the fixes, so large or odd directories
 *     can list partially or crash.
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
 *
 * History
 *   0.8  2026-10-23  Leaves cleanly: quit, end of input and a failed login now
 *                    end with eng_disconnect() (SMB logoff, then close the
 *                    connection) instead of just closing the connection.
 *   0.7  2026-10-23  Merged with the SMBFTP-main 0.6 lineage (same libdsm
 *                    hardening, found with an ASan build against Samba and
 *                    impacket SMB1 servers): libdsm is no longer bundled but
 *                    downloaded, SHA-256 checked and patched by build.cmd and
 *                    the Makefile (patches/). ls now says when a listing may be
 *                    incomplete ("Warning: ...") or was recovered ("Note: ...")
 *                    via eng_find_flags(), and reports a listing libdsm flagged
 *                    incomplete as an error. Wording of those messages is the
 *                    SMBFTP-main 0.6 wording; this file's own code is otherwise
 *                    the 0.6 engine-split version.
 *   0.6  2026-10-13  No functional change. Split everything that talks to
 *                    libdsm (session connect/login, shares, ls, cd, get, put,
 *                    plus the string/path/error-text utilities they use) out
 *                    into smb_engine.c/h, so a future GUI frontend
 *                    (WinSMBFTP.exe, winsmbftp.c) can share it instead of
 *                    reimplementing it. The cmd_* functions here are now thin
 *                    wrappers: call the engine, print the result - wording
 *                    unchanged. Checked by scripting both versions through an
 *                    impacket SMB1 test server and diffing the transcripts
 *                    and transferred file hashes; see archive/REGRESSION.md.
 *                    (2026-10-22: this header's Version line still said 0.5;
 *                    corrected to 0.6. No code change.)
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

#include "smb_engine.h"

/* ------------------------------------------------------------------------ */
/* Small utilities                                                          */
/* ------------------------------------------------------------------------ */
/* str_copy, ci_cmp, u64_str, ft_str, base_name moved to smb_engine.c; this  */
/* file uses them as declared in smb_engine.h.                              */

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

/* parse_ipv4, nt_text, report_rc/report_fail (now eng_strerror/            */
/* eng_strerror_fail) and resolve_path/remote_stat moved to smb_engine.c.   */

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
 * Clobbers: stdout, stderr
 */
static int cmd_shares(Ctx *c)
{
    EngShareList list;
    char errbuf[ENG_ERRLEN];
    size_t i;

    if (eng_list_shares(c, &list, errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
    printf("Shares on %s:\n", c->server);
    for (i = 0; i < list.count; i++)
        printf("  %s\n", list.names[i]);
    if (list.count == 0)
        puts("  (none)");
    eng_free_shares(&list);
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
    char errbuf[ENG_ERRLEN];

    if (argc != 2) {
        fprintf(stderr, "Usage: use <share>\n");
        return -1;
    }
    if (eng_use_share(c, argv[1], errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
    printf("Connected to \\\\%s\\%s\n", c->server, c->share);
    return 0;
}

/* cmp_entries (the directories-first, case-insensitive sort) moved into    */
/* smb_engine.c's eng_list_dir().                                          */

/*
 * print_find_notes - tell the person when the listing just shown may be
 *                    incomplete or had to be recovered (see eng_find_flags)
 * Inputs : c = context
 * Outputs: none
 * Clobbers: stderr
 */
static void print_find_notes(const Ctx *c)
{
    unsigned long f = eng_find_flags(c);

    if (f & ENG_FIND_INCOMPLETE)
        fprintf(stderr, "Warning: the listing may be incomplete (the server sent a "
                        "malformed or cut-short reply)\n");
    else if (f & ENG_FIND_RESYNCED)
        fprintf(stderr, "Note: the server mis-sized its directory entries; the "
                        "listing was recovered\n");
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
    char tbuf[24], sbuf[24], sbuf2[24];
    char errbuf[ENG_ERRLEN];
    EngEntry *arr;
    size_t i, k;
    unsigned long ndirs = 0, nfiles = 0;
    uint64_t total = 0;
    const char *arg;

    if (!need_share(c))
        return -1;
    if (argc > 2) {
        fprintf(stderr, "Usage: ls [dir|pattern]\n");
        return -1;
    }
    arg = (argc == 2) ? argv[1] : ".";

    if (eng_list_dir(c, arg, &arr, &k, errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
    if (k == 0) {
        puts("No entries.");
        print_find_notes(c);
        return 0;
    }

    for (i = 0; i < k; i++) {
        ft_str(arr[i].wtime, tbuf);
        if (arr[i].isdir) {
            strcpy(sbuf, "<DIR>");
            ndirs++;
        } else {
            u64_str(sbuf, arr[i].size);
            total += arr[i].size;
            nfiles++;
        }
        printf("%s  %12s  %s\n", tbuf, sbuf, arr[i].name);
    }
    printf("%lu file(s), %lu dir(s), %s bytes\n", nfiles, ndirs,
           u64_str(sbuf2, total));
    print_find_notes(c);

    eng_free_entries(arr, k);
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
    char errbuf[ENG_ERRLEN];

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
    if (eng_cd(c, argv[1], errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
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
/*
 * cli_xfer_progress - eng_xfer_cb that redraws the CLI's progress line
 * Inputs : done, total; user = unused
 * Outputs: line on stdout (see show_progress)
 * Clobbers: stdout
 */
static void cli_xfer_progress(uint64_t done, uint64_t total, void *user)
{
    (void)user;
    show_progress(done, total);
}

static int cmd_get(Ctx *c, int argc, char **argv)
{
    char errbuf[ENG_ERRLEN];
    const char *local;
    uint64_t done = 0;
    time_t t0;
    int rc;

    if (!need_share(c))
        return -1;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: get <remote> [local]\n");
        return -1;
    }
    local = (argc == 3) ? argv[2] : base_name(argv[1]);
    if (*local == '\0') {
        fprintf(stderr, "Error: no local file name\n");
        return -1;
    }

    t0 = time(NULL);
    rc = eng_get_file(c, argv[1], local, cli_xfer_progress, NULL, NULL,
                       &done, errbuf, sizeof errbuf);
    if (rc != 0) {
        if (rc == -2)                   /* failed after the transfer started */
            puts("");
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
    print_summary("Downloaded", done, t0);
    return 0;
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
/* verify_upload moved into smb_engine.c (part of eng_put_file).            */

/*
 * cmd_put - upload one local file (creates or overwrites the remote file)
 * Inputs : c = context, argc/argv = argv[1] = local file, optional argv[2] =
 *          remote path; if that is an existing directory the local base name
 *          is appended (default: local base name in the remote cwd)
 * Outputs: 0 on success, -1 on failure
 * Clobbers: creates/overwrites the remote file (partial file left on failure);
 *          stdout, stderr
 */
static int cmd_put(Ctx *c, int argc, char **argv)
{
    char errbuf[ENG_ERRLEN];
    const char *remote_arg, *lname;
    uint64_t done = 0;
    time_t t0;
    int rc;

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

    t0 = time(NULL);
    rc = eng_put_file(c, argv[1], remote_arg, cli_xfer_progress, NULL, NULL,
                       &done, errbuf, sizeof errbuf);
    if (rc < 0) {
        if (rc == -2)                   /* failed after the transfer started */
            puts("");
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }
    if (rc == 1) {                      /* uploaded, but could not verify */
        puts("");
        fprintf(stderr, "Warning: %s\n", errbuf);
    }
    print_summary("Uploaded", done, t0);
    return 0;
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

/* connect_server moved into smb_engine.c as eng_connect(); main() drives it */
/* with the callback below so the printed trace is unchanged.               */

/*
 * connect_notify - eng_notify_cb that reproduces smbftp 0.5's connect trace
 * Inputs : line = message text (no newline/prefix), is_error = 0 for a
 *          progress line (smbftp 0.5 printed it to stdout), 1 for a failed
 *          attempt (smbftp 0.5 printed it to stderr as "Error: <line>");
 *          user = unused
 * Outputs: line on stdout or stderr
 * Clobbers: stdout or stderr
 */
static void connect_notify(const char *line, int is_error, void *user)
{
    (void)user;
    if (is_error) {
        fprintf(stderr, "Error: %s\n", line);
    } else {
        puts(line);
        fflush(stdout);
    }
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
    char errbuf[ENG_ERRLEN];
    char *av[MAX_ARGS];
    char *end;
    uint32_t ip;
    unsigned long chunk = DEF_CHUNK, wait_ms = DEF_WAIT_MS;
    int mode = 0, scan = 0, i, ac, guest, ret = 1;
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

    ctx.sess = eng_connect(ip, host, mode, nbname, connect_notify, NULL,
                            errbuf, sizeof errbuf);
    if (ctx.sess == NULL) {
        fprintf(stderr, "Error: could not establish an SMB1 session with %s.\n", host);
        goto finish;
    }

    if (eng_login(&ctx, domain, user, pass, &guest, errbuf, sizeof errbuf) != 0) {
        fprintf(stderr, "Error: %s\n", errbuf);
        fprintf(stderr, "Hint: try -u, -p and -d (the default is user 'guest', empty password).\n");
        goto finish;
    }
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
    eng_disconnect(&ctx);               /* SMB logoff if logged in, then close */
#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}
