/*
 * smb_engine.h - SMB1 session/transfer engine shared by smbftp.c (CLI) and
 *                winsmbftp.c (GUI, WinSMBFTP.exe)
 *
 * Version : 1.5
 * Author  : VinCBR900
 *
 * Purpose
 *   Everything here used to be static functions inside smbftp.c, mixed in
 *   with the printf/fprintf calls that displayed their results. This header
 *   and smb_engine.c split that logic out so it has no idea whether it is
 *   being driven by a command-line loop or a Win32 ListView: every function
 *   either returns data (counted arrays, structs) or a status code plus an
 *   error message in a caller-supplied buffer. Nothing in here writes to
 *   stdout/stderr or reads stdin.
 *
 *   smbftp.c's cmd_* functions are now thin wrappers: call one of these,
 *   then printf the result. winsmbftp.c will call the same functions and put
 *   the result in a ListView row, a status bar or a message box instead.
 *
 * Usage
 *   #include "smb_engine.h" (pulls in smbftp.h for Ctx, the portability
 *   layer and the libdsm includes). Link smb_engine.c's object file in.
 *   Blocking calls (eng_connect, eng_login, eng_list_shares, eng_use_share,
 *   eng_list_dir, eng_cd, eng_get_file, eng_put_file) do real network I/O and
 *   will not return until it completes or fails - callers that must not
 *   block (a GUI's message-loop thread) are expected to run them on a worker
 *   thread. eng_get_file/eng_put_file take a progress callback and a
 *   cancel flag for that reason.
 *
 *   Every *errbuf is filled with a short, human-readable message (bare text:
 *   no "Error: " prefix, no trailing newline, no leading cause like "cannot
 *   open remote file" baked in beyond what is documented per-function) on a
 *   non-zero/NULL return. errbuf is left untouched on success. ENG_ERRLEN is
 *   enough for any message this module produces.
 *
 * History
 *   1.5  2026-10-23  eng_disconnect() sends the logoff whenever the session is
 *                    logged in (smb_session_is_guest() >= 0), not only when a
 *                    share is connected - a CLI session that only ran 'shares',
 *                    or a GUI connect that failed at the share step, is logged
 *                    in too. smbftp.c now ends with eng_disconnect().
 *   1.4  2026-10-23  eng_disconnect(): end a session with an SMB logoff and close
 *                    the connection. WinSMBFTP uses it before replacing a
 *                    connection and when it exits (it only dropped the socket
 *                    before, and a failed second Connect left a NULL session
 *                    behind a still-set have_share).
 *   1.3  2026-10-23  Merge with SMBFTP-main 0.6 (libdsm is now downloaded and
 *                    patched, not bundled): eng_find_flags() with
 *                    ENG_FIND_INCOMPLETE / ENG_FIND_RESYNCED (0 when libdsm has
 *                    no smb_session_get_find_flags()), and eng_list_dir() now
 *                    fails with "listing failed: malformed or cut-short server
 *                    reply" when libdsm flags the listing incomplete and no NT
 *                    status explains it. The "put" verification message no
 *                    longer points at the retired patches/libdsm-write-
 *                    bytecount.patch (the fix is part of patches/0001).
 *   1.2  2026-10-22  Scan support for WinSMBFTP's Scan window.
 *                    - eng_default_range(), eng_parse_range(): the address text
 *                      the Scan window shows/accepts (this machine's network, or
 *                      a.b.c.d or a.b.c.d/n, n = 16..32, same rules as smbftp -S).
 *                    - eng_probe_range(): TCP-probes a whole range, many hosts at
 *                      once, so a /24 costs roughly one timeout per batch of 64
 *                      hosts instead of up to two timeouts per silent address
 *                      (eng_scan_host() alone is sequential). Skips this
 *                      machine's own addresses, like smbftp -S.
 *                    - EngScanHit gained .status (ENG_SCAN_SMB1_SHARES,
 *                      ENG_SCAN_SMB1_NOGUEST, ENG_SCAN_PORT_ONLY) so a caller can
 *                      tell an SMB1 server from a host that merely has tcp/445 or
 *                      tcp/139 open (typically SMB1 switched off).
 *                    - eng_probe_tcp() now also watches select()'s exception set:
 *                      Winsock reports a refused non-blocking connect there, not
 *                      in the write set, so 1.1 waited out the whole timeout on a
 *                      refusing port (smbftp.c's own scanner already handled this).
 *                    - eng_scan_host() now sends its own bounded SMB1 NEGOTIATE (the
 *                      same bytes smbftp -S uses; NetBIOS session request first on
 *                      tcp/139) and only hands a host that answers in SMB1 to
 *                      libdsm, over the transport that answered. Measured: a host
 *                      that accepts TCP but never speaks SMB held the old code in
 *                      eng_connect() for about 60 s, and no cancel flag can
 *                      interrupt a libdsm call.
 *                    smbftp.c's -S code is still untouched; these are engine-side
 *                    equivalents for the GUI.
 *   1.1  2026-10-20  Added eng_probe_tcp()/eng_scan_host() for WinSMBFTP's
 *                    Scan button. These are new code, not an extraction of
 *                    anything smbftp.c 0.5 already had - the CLI's own -S
 *                    scan mode (main()/scan_hosts() et al.) is a separate,
 *                    more elaborate concurrent prober built directly into
 *                    smbftp.c and is untouched by this. A GUI scan does not
 *                    need that concurrency (it already runs off the UI
 *                    thread), so this is a simpler sequential one-host-at-
 *                    a-time primitive instead, reusing eng_connect()/
 *                    eng_login()/eng_list_shares() for the parts that
 *                    overlap rather than duplicating them.
 *   1.0  2026-10-13  Initial extraction from smbftp.c 0.5. Behavior and
 *                    wording were kept identical on purpose and checked by
 *                    scripting the old and new smbftp.c through an impacket
 *                    SMB1 test server (shares/use/ls/cd/get/put, including
 *                    error paths) and diffing the transcripts and the
 *                    transferred file hashes - see archive/REGRESSION.md.
 */
#ifndef SMB_ENGINE_H
#define SMB_ENGINE_H

#include "smbftp.h"

#define ENG_ERRLEN 200      /* big enough for any message this module builds */

/* ------------------------------------------------------------------------ */
/* String / number utilities (no I/O, no libdsm calls)                      */
/* ------------------------------------------------------------------------ */

int         str_copy(char *dst, size_t dsz, const char *src);
int         ci_cmp(const char *a, const char *b);
char       *u64_str(char *buf, uint64_t v);         /* buf >= 21 bytes       */
char       *ft_str(uint64_t ft, char *buf);         /* buf >= 17 bytes       */
const char *base_name(const char *path);
int         parse_ipv4(const char *text, uint32_t *ip_net);

/* ------------------------------------------------------------------------ */
/* Error text                                                               */
/* ------------------------------------------------------------------------ */

/*
 * eng_strerror / eng_strerror_fail - format the same wording smbftp 0.5's
 * report_rc()/report_fail() printed, into a caller-supplied buffer instead
 * of stderr. "what" is a short description of the failed operation, e.g.
 * "cannot list shares". Always writes a NUL-terminated string to buf.
 */
void eng_strerror(const char *what, int rc, smb_session *s, char *buf, size_t bufsz);
void eng_strerror_fail(const char *what, smb_session *s, char *buf, size_t bufsz);

/* ------------------------------------------------------------------------ */
/* Remote path handling                                                     */
/* ------------------------------------------------------------------------ */

int resolve_path(const Ctx *c, const char *arg, char *out, size_t outsz);
int remote_stat(Ctx *c, const char *path, int *isdir, uint64_t *size);

/* ------------------------------------------------------------------------ */
/* Session: connect and log in                                              */
/* ------------------------------------------------------------------------ */

/* eng_notify_cb - a progress or per-attempt-failure line from eng_connect.
 * line has no trailing newline and no "Error: " prefix; is_error tells the
 * caller which stream/styling smbftp 0.5 used (0 = plain progress line that
 * went to stdout, 1 = failure line that went to stderr as "Error: <line>").
 * user is passed through unchanged */
typedef void (*eng_notify_cb)(const char *line, int is_error, void *user);

/*
 * eng_connect - open an SMB1 session using the requested transport(s)
 * Inputs : ip/ip_text = server address, mode = 0 auto (tcp then nbt), 1 tcp,
 *          2 nbt; nbname = NetBIOS name or NULL for the defaults (validated:
 *          1..NBNAME_MAX characters when given); on_attempt/user = optional,
 *          called once before each transport is tried (is_error=0) and again
 *          if that attempt fails (is_error=1), same order/wording smbftp 0.5
 *          printed
 * Outputs: new connected (not yet logged in) session, or NULL with errbuf
 *          set to the last attempt's reason (or the nbname length complaint)
 * Clobbers: *errbuf on failure. Each attempt uses a fresh smb_session
 */
smb_session *eng_connect(uint32_t ip, const char *ip_text, int mode,
                          const char *nbname, eng_notify_cb on_attempt, void *user,
                          char *errbuf, size_t errsz);

/*
 * eng_login - set credentials and log in on an already-connected session
 * Inputs : c = context with c->sess set (by eng_connect), domain/user/pass
 *          (each validated: < SMB_CREDS_MAXLEN characters)
 * Outputs: 0 on success with *out_guest set (1 if the server mapped the
 *          login to Guest, else 0; pass NULL if not wanted), -1 with errbuf
 * Clobbers: c->sess's credentials/login state; *out_guest, *errbuf
 */
int eng_login(Ctx *c, const char *domain, const char *user, const char *pass,
              int *out_guest, char *errbuf, size_t errsz);

/* ------------------------------------------------------------------------ */
/* Shares                                                                   */
/* ------------------------------------------------------------------------ */

typedef struct {
    char   **names;          /* heap array of heap strings; NULL if count==0 */
    size_t   count;
} EngShareList;

/*
 * eng_list_shares - list the shares offered by the server
 * Inputs : c = context with a logged-in session
 * Outputs: 0 and *out filled (possibly count==0), or -1 with errbuf
 * Clobbers: *out, *errbuf
 */
int  eng_list_shares(Ctx *c, EngShareList *out, char *errbuf, size_t errsz);
void eng_free_shares(EngShareList *list);

/*
 * eng_use_share - connect to a share and make it current (cwd = share root)
 * Inputs : c = context, share = share name (< SHARE_LEN characters)
 * Outputs: 0 on success, -1 with errbuf on failure. On failure the previous
 *          share, if any, stays current
 * Clobbers: on success, c->tid, c->have_share, c->share, c->cwd. The
 *          previous tree connection (if any) is not explicitly disconnected,
 *          same as smbftp 0.5 - it is released when the session ends
 */
int eng_use_share(Ctx *c, const char *share, char *errbuf, size_t errsz);

/*
 * eng_disconnect - end the session: SMB logoff, then close the connection
 * Inputs : c = context; may have no session (then nothing is sent)
 * Outputs: none. c->sess = NULL, c->tid = 0, c->have_share = 0, c->share and
 *          c->cwd empty (c->server and c->chunk are left alone)
 * Clobbers: *c. If the session is logged in the logoff request is sent but its
 *          reply is not waited for, so a server that has gone away cannot
 *          hold this up (libdsm's own 60 s I/O limit still applies to the
 *          send itself, which is a few bytes). Safe to call twice
 */
void eng_disconnect(Ctx *c);

/* ------------------------------------------------------------------------ */
/* Directory listing                                                        */
/* ------------------------------------------------------------------------ */

typedef struct {
    char    *name;            /* heap-allocated                            */
    int      isdir;
    uint64_t size;             /* 0 for directories                        */
    uint64_t wtime;            /* raw SMB FILETIME; format with ft_str()    */
} EngEntry;

/*
 * eng_list_dir - list a remote directory, a single file, or a wildcard
 *                pattern (same rules smbftp 0.5's "ls" used)
 * Inputs : c = context, arg = directory/file/pattern as the user would type
 *          it (NULL or "" means the current directory, same as "ls" with no
 *          argument)
 * Outputs: 0 and *out / *count filled (sorted directories-first, then
 *          case-insensitive name; count==0 with *out==NULL means "no
 *          entries", not an error), or -1 with errbuf. After a 0 return call
 *          eng_find_flags(): the listing may still have been cut short or
 *          recovered, and the person should be told
 * Clobbers: *out, *count, *errbuf
 */
int  eng_list_dir(Ctx *c, const char *arg, EngEntry **out, size_t *count,
                   char *errbuf, size_t errsz);
void eng_free_entries(EngEntry *entries, size_t count);

/* eng_find_flags() result bits */
#define ENG_FIND_INCOMPLETE 0x01UL  /* entries may be missing: network failure,
                                     * or a malformed / cut-short server reply */
#define ENG_FIND_RESYNCED   0x02UL  /* the server mis-sized its directory entries
                                     * (impacket does); the listing was recovered */

/*
 * eng_find_flags - how the most recent directory listing on this session ended
 * Inputs : c = context (must have a session)
 * Outputs: ENG_FIND_xxx bits, 0 = clean. Always 0 when libdsm lacks
 *          smb_session_get_find_flags() (a stock libdsm, built without the
 *          patches in patches/)
 * Clobbers: none
 */
unsigned long eng_find_flags(const Ctx *c);

/*
 * eng_cd - change the remote current directory
 * Inputs : c = context, arg = target directory (.. and \ or / supported);
 *          must be non-empty - a caller that wants "show current directory"
 *          behavior (as smbftp 0.5's bare "cd" did) should read c->cwd/
 *          c->share/c->server itself rather than call this
 * Outputs: 0 on success (c->cwd updated), -1 with errbuf on failure
 * Clobbers: c->cwd on success; *errbuf on failure
 */
int eng_cd(Ctx *c, const char *arg, char *errbuf, size_t errsz);

/* ------------------------------------------------------------------------ */
/* Transfers                                                                */
/* ------------------------------------------------------------------------ */

/* eng_xfer_cb - progress callback, called about every PROGRESS_STEP bytes;
 * total is 0 if unknown (can happen for an upload whose local size could not
 * be read) */
typedef void (*eng_xfer_cb)(uint64_t done, uint64_t total, void *user);

/*
 * eng_get_file - download one remote file
 * Inputs : c = context, remote_arg = remote path as typed (resolved the same
 *          way "ls"/"cd" resolve paths), local_path = full local file name
 *          to create/overwrite, cb/user = optional progress callback,
 *          cancel = optional; if *cancel becomes non-zero between chunks the
 *          transfer stops and fails with errbuf = "cancelled"
 * Outputs: 0 on success with *out_done = bytes written. On failure, errbuf is
 *          set and the return is -1 for a failure before any local data was
 *          written (open/stat/allocate - a caller printing to a line-based
 *          UI does not need a blank line first) or -2 for a failure once the
 *          local file was open and the transfer had started, including
 *          cancellation (smbftp 0.5 always printed a blank line first here,
 *          to clear a possible in-progress "\r"-redrawn progress line).
 *          Partial local file left on failure, same as smbftp 0.5
 * Clobbers: creates/overwrites local_path; *out_done; *errbuf on failure
 */
int eng_get_file(Ctx *c, const char *remote_arg, const char *local_path,
                  eng_xfer_cb cb, void *user, volatile int *cancel,
                  uint64_t *out_done, char *errbuf, size_t errsz);

/*
 * eng_put_file - upload one local file (creates or overwrites the remote
 *                file; if remote_arg names an existing remote directory, the
 *                local file's base name is appended, same as smbftp 0.5)
 * Inputs : c = context, local_path = local file to read, remote_arg = remote
 *          target as typed, cb/user/cancel = as eng_get_file
 * Outputs: 0 on clean success (verified by reading the remote size back), or
 *          1 on success but verification could not be performed - either way
 *          *out_done is set. 1 means errbuf holds a non-fatal warning (same
 *          wording smbftp 0.5 printed); a caller printing it should treat
 *          the upload as having succeeded (smbftp 0.5 did). On failure,
 *          errbuf is set and the return is -1 for a failure before any
 *          remote data was written (open local/stat/allocate/create remote -
 *          no blank line needed first) or -2 for a failure once the remote
 *          file was open and the transfer had started, including
 *          cancellation and a failed verification (smbftp 0.5 always printed
 *          a blank line first here). Partial remote file left on failure,
 *          same as smbftp 0.5
 * Clobbers: creates/overwrites the remote file; *out_done; *errbuf on 1/-1/-2
 */
int eng_put_file(Ctx *c, const char *local_path, const char *remote_arg,
                  eng_xfer_cb cb, void *user, volatile int *cancel,
                  uint64_t *out_done, char *errbuf, size_t errsz);

/* ------------------------------------------------------------------------ */
/* Scan: find SMB1 servers and their shares                                 */
/* ------------------------------------------------------------------------ */

/*
 * eng_probe_tcp - check whether a TCP port accepts a connection, within a
 *                 short bounded time. For deciding whether to bother with a
 *                 full eng_connect() (which has its own, much longer
 *                 timeout meant for a single already-chosen server, not for
 *                 ruling out silent addresses quickly).
 * Inputs : ip = address (network byte order), port = host byte order,
 *          timeout_ms = longest time to wait
 * Outputs: 1 if a connection completed, 0 otherwise (closed, filtered,
 *          timed out, or any local error)
 * Clobbers: none (opens and closes one socket)
 */
int eng_probe_tcp(uint32_t ip, unsigned short port, unsigned long timeout_ms);

/* EngScanHit.status */
#define ENG_SCAN_SMB1_SHARES  1  /* SMB1 session set up, guest login and share
                                   * listing worked: shares/share_count valid */
#define ENG_SCAN_SMB1_NOGUEST 2  /* SMB1 session set up, but guest login or the
                                   * share listing failed: credentials needed */
#define ENG_SCAN_PORT_ONLY    3  /* tcp/445 or tcp/139 open, but no SMB1 session
                                   * could be set up (SMB1 off, or not SMB) */

typedef struct {
    char     ip_text[16];    /* "a.b.c.d" */
    char   **shares;         /* heap array of heap strings; NULL if none */
    int      share_count;    /* 0 if a guest login or share listing failed -
                               * the host still answered, just could not be
                               * enumerated as guest */
    int      status;         /* ENG_SCAN_xxx above; 0 = not found */
} EngScanHit;

/*
 * eng_scan_host - probe one IPv4 address for an SMB1 server and, if found,
 *                 try a guest login (user "guest", no password, domain
 *                 "WORKGROUP") and list its shares
 * Inputs : ip (network byte order), ip_text = same address as text (for
 *          hit->ip_text and eng_connect()'s own display use),
 *          timeout_ms = limit for each connect and each NEGOTIATE exchange
 *          (a stalled host costs a few of these, not a libdsm timeout)
 * Outputs: 1 if something answered on 445 or 139 (hit->status says how far
 *          it got; hit->shares/share_count filled in only for
 *          ENG_SCAN_SMB1_SHARES), 0 if nothing answered either port
 *          (hit->status = 0)
 * Clobbers: *hit; opens and closes a probe socket and, if that succeeds, a
 *          full temporary SMB1 session (always logged out and destroyed
 *          before returning, win or lose - this never touches a caller's
 *          own Ctx/session)
 */
int eng_scan_host(uint32_t ip, const char *ip_text, unsigned long timeout_ms,
                   EngScanHit *hit);
void eng_free_scan_hit(EngScanHit *hit);

/*
 * eng_default_range - the network Scan should offer by default
 * Inputs : buf/bufsz = output text buffer (>= 20 bytes)
 * Outputs: 1 and buf = "a.b.c.0/p" for the first local adapter that has a
 *          usable address (not loopback or 169.254.x.x, not a /31 or /32
 *          link; a subnet wider than /22 is cut down to the /24 holding the
 *          address, as smbftp -S does); 0 and buf = "" if none
 * Clobbers: *buf
 */
int eng_default_range(char *buf, size_t bufsz);

/*
 * eng_parse_range - parse Scan's address text
 * Inputs : text = "a.b.c.d" (one host) or "a.b.c.d/n" (n = 16..32); leading
 *          and trailing blanks are ignored
 * Outputs: 0 and the first and last host to probe stored through first and
 *          last, host byte order (network and broadcast addresses left out
 *          for n <= 30);
 *          -1 if the text is malformed or n is out of range
 * Clobbers: *first, *last on success only
 */
int eng_parse_range(const char *text, uint32_t *first, uint32_t *last);

/* eng_scan_prog_cb - called by eng_probe_range after every batch of hosts.
 * done/total are addresses handled so far / in the range. Runs on the
 * caller's thread, inside eng_probe_range. */
typedef void (*eng_scan_prog_cb)(unsigned long done, unsigned long total, void *user);

/*
 * eng_probe_range - find which addresses in a range have tcp/445 or tcp/139
 *                   open. Plain sockets only (no libdsm), 64 hosts at a time
 * Inputs : first/last = range, host byte order (from eng_parse_range);
 *          timeout_ms = longest wait per batch (100..30000 sensible; 1000
 *          matches smbftp -S); cancel = optional flag polled between batches
 *          (nonzero stops early); cb/user = optional progress callback;
 *          out_ips = result pointer
 * Outputs: number of responding hosts (0..1024; more are dropped), *out_ips =
 *          malloc'd array of their addresses in network byte order, ascending
 *          (NULL if none) - caller free()s it. -1 on out-of-memory (*out_ips
 *          NULL). A cancelled scan returns the hosts found so far
 * Clobbers: *out_ips; opens and closes sockets
 */
int eng_probe_range(uint32_t first, uint32_t last, unsigned long timeout_ms,
                    volatile int *cancel, eng_scan_prog_cb cb, void *user,
                    uint32_t **out_ips);

#endif /* SMB_ENGINE_H */
