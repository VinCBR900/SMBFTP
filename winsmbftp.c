/*
 * winsmbftp.c - WinSMBFTP, an Explorer-style GUI for smb_engine's SMB1 client
 *
 * Version : 0.8
 * Author  : VinCBR900
 *
 * Usage
 *   WinSMBFTP.exe (no command-line arguments yet)
 *   Toolbar: Connect (host/user/password/domain/share), Scan (find SMB1
 *   servers and list their shares; double-click a share to open Connect
 *   with it filled in), Up, Refresh, Get, Put, Cancel.
 *   Build: build.cmd gui. build.cmd gui debug also defines WINSMB_DEBUG,
 *   which makes dbg_log() write winsmbftp-debug.log next to the exe and to
 *   OutputDebugStringA; a normal build has no logging code at all.

 * Purpose
 *   A Connect window (built from CreateWindowExA calls like every other
 *   window in this program - no resource compiler, no DIALOGEX) collects
 *   host/user/password/domain/share; "Up", "Refresh" and double-clicking a
 *   directory row drive smb_engine for real. Phase 5 adds real transfers:
 *   Get (the toolbar button, with a file selected, or double-clicking a
 *   file row) opens a Save dialog and downloads it; Put opens an Open
 *   dialog and uploads the chosen local file into the current remote
 *   directory; Cancel sets the flag eng_get_file()/eng_put_file() check
 *   between chunks; a progress bar (hidden the rest of the time) tracks
 *   the transfer.
 *
 *   Scan (Phase 6) opens a small window (again just CreateWindowExA calls)
 *   showing the address range to probe - this machine's network by default,
 *   or any a.b.c.d / a.b.c.d/n (n = 16..32) the person types - and a Host /
 *   Share list. The scan is one more worker-thread job (JOB_SCAN):
 *   eng_probe_range() finds hosts with tcp/445 or tcp/139 open many at a
 *   time, then eng_scan_host() asks each of those for an SMB1 session, a
 *   guest login and its share list. Each answering host is posted back to
 *   the frame (WM_APP_SCAN_HIT) as soon as it is known, so rows appear while
 *   the scan is still running. Guest login only: a server that wants
 *   credentials is listed as "login required" with no shares, and a host
 *   with an SMB port open that does not answer in SMB1 is listed as such.
 *   Stop (or closing the window) sets the same cancel flag Get/Put use; it
 *   is polled between batches and between hosts, not inside a blocking
 *   libdsm call, so a host that stalls mid-session can delay it.
 *
 *   Filename handling is option A from the project's own decision: smbftp
 *   and smb_engine already convert remote names through the ANSI code page
 *   (SMB_WIN_CODEPAGE), so this program stays on the *A Win32 functions
 *   throughout - no wide-character work needed for this phase. A name
 *   containing a character outside that code page will show (and round-
 *   trip) as "?", same as the CLI.
 *
 *   Every smb_engine call that touches the network blocks, and libdsm has
 *   no internal locking, so exactly one such call may be in flight at a
 *   time: every one of them runs on a single worker thread (job_thread),
 *   never on the UI thread, and the toolbar/ListView actions that would
 *   start a new one are ignored (via g_job_running) while it is running.
 *   The worker thread never touches a Win32 window directly - it only
 *   PostMessageA's its result back to the frame, which applies it from the
 *   UI thread as usual. Ctx (g_ctx) is likewise only ever touched by
 *   whichever one of (UI thread with no job running) / (the worker thread)
 *   currently "owns" it; nothing makes that true except the discipline of
 *   checking g_job_running before starting another one.
 *
 *   Declarations come from wingui.h (plus smb_engine.h for Ctx and the
 *   engine itself, included first so its winmini.h sets up the __stdcall
 *   macro - see wingui.h's own header comment).
 *
 * History
 *   0.8  2026-10-23  Closing the connection properly. Connect now ends the
 *                    previous session (eng_disconnect: SMB logoff + close)
 *                    before opening a new one - before, it overwrote g_ctx.sess,
 *                    leaking the old connection, and a failed second Connect
 *                    left a NULL session while g_ctx.have_share was still set
 *                    (the next Refresh/Get would have passed NULL to the
 *                    engine). A connect that fails after the session was
 *                    created (login refused, share missing) now closes that
 *                    half-open session. On exit the frame waits up to 3 s for
 *                    a running job (asking it to stop), then, if the worker has
 *                    finished, logs off and closes; if the worker is stuck in a
 *                    blocking call it skips that and lets the process exit
 *                    close the socket. A failed second Connect leaves the old
 *                    listing on screen but not connected (status bar says why).
 *   0.7  2026-10-23  SMBFTP-main merge (libdsm downloaded and patched, see
 *                    build.cmd). After a successful listing the status bar
 *                    now says so when eng_find_flags() reports it may be
 *                    incomplete or was recovered (smbftp's ls prints the same
 *                    warning). No change to Scan. STATUS: the Scan window is
 *                    still the 0.6 code, not yet confirmed on Windows.
 *   0.6  2026-10-22  Scan: the Scan button now opens a Scan window (range
 *                    box, Scan/Stop, Host/Share list, Use/Close) backed by
 *                    JOB_SCAN and smb_engine 1.2's eng_default_range()/
 *                    eng_parse_range()/eng_probe_range()/eng_scan_host().
 *                    Double-clicking a share (or Use) closes the Scan window
 *                    and opens Connect with host and share filled in, which
 *                    answers "how do I find a share name from the GUI".
 *                    dbg_log() is now compiled in only when WINSMB_DEBUG is
 *                    defined (build.cmd gui debug); dbg_log() calls are
 *                    ((void)0) otherwise. open_connect_window() takes
 *                    optional host/share to pre-fill. Cancel also stops a
 *                    scan.
 *                    STATUS / KNOWN ISSUES: the Scan window itself has not
 *                    been run yet (no Windows or Wine GUI session was used
 *                    for this version) - it builds clean with the real
 *                    win32 TCC at -Wall. What was exercised, on Linux
 *                    against an impacket SMB1 server: the engine calls it
 *                    drives. First thing to check on Windows: Scan opens
 *                    with this machine's /24 filled in, rows appear while
 *                    scanning, Stop works, and double-clicking a share opens
 *                    Connect with host and share filled in.
 *   0.5  2026-10-18  Added Get/Put (GetSaveFileNameA/GetOpenFileNameA, a
 *                    progress bar, and the Cancel button's real job), on
 *                    the same worker-thread job mechanism as Phase 4 -
 *                    eng_get_file()/eng_put_file()'s progress callback
 *                    PostMessageA's from the worker thread rather than
 *                    touching the progress bar directly, same reasoning as
 *                    every other cross-thread result in this file.
 *   0.4  2026-10-17  Fixed a real bug 0.3 shipped with: WinMain never called
 *                    WSAStartup, so every connect attempt failed with
 *                    "negotiation failed: network error or unexpected
 *                    server reply" - the same error text a genuine network
 *                    problem produces, which is why it looked at first like
 *                    an environment/Wine issue rather than a missing
 *                    four-line fix. Found by comparing a dbg_log() trace of
 *                    the GUI's failing connect attempt against the known-
 *                    good CLI (smbftp.exe, which does call WSAStartup)
 *                    reaching the same live server through the same Wine
 *                    session seconds apart - see archive/REGRESSION.md.
 *                    Added OutputDebugStringA-based logging (dbg_log(),
 *                    winsmbftp-debug.log) through the Connect flow and the
 *                    worker thread for exactly this kind of diagnosis,
 *                    since screen captures of this Wine session had become
 *                    unreliable by this point.
 *   0.3  2026-10-15  Added the Connect window, the worker-thread job
 *                    mechanism, and real Up/Refresh/double-click navigation
 *                    backed by smb_engine. Verified with the real
 *                    win32-targeting TCC under Wine against a live impacket
 *                    SMB1 server: Connect reaches the share root, Up and
 *                    double-clicking a directory navigate correctly, the
 *                    address bar and status bar reflect the real session -
 *                    see archive/REGRESSION.md.
 *   0.2  2026-10-14  Added the toolbar, address bar and ListView, and the
 *                    layout that places all four controls together and
 *                    re-lays them out on WM_SIZE.
 *   0.1  2026-10-14  Initial skeleton: frame window, status bar, message
 *                    loop.
 */
#include "smb_engine.h"
#include "wingui.h"

#define WINCLASS_NAME     "WinSMBFTPFrame"
#define WINTITLE          "WinSMBFTP"
#define CONNECT_CLASS     "WinSMBFTPConnect"
#define SCANWIN_CLASS     "WinSMBFTPScan"

#define TOOLBAR_H   28     /* fixed heights: a single-row text toolbar, one- */
#define ADDRBAR_H   22     /* line edit control and status bar at the system */
#define STATUS_H    20     /* font size do not need to be measured for this */

#define ID_TB_UP       1001
#define ID_TB_REFRESH  1002
#define ID_TB_CONNECT  1003
#define ID_TB_SCAN     1004
#define ID_TB_GET      1005
#define ID_TB_PUT      1006
#define ID_TB_CANCEL   1007

#define ID_CONNECT_HOST    1101
#define ID_CONNECT_USER    1102
#define ID_CONNECT_PASS    1103
#define ID_CONNECT_DOMAIN  1104
#define ID_CONNECT_SHARE   1105
#define ID_CONNECT_OK      1106
#define ID_CONNECT_CANCEL  1107

#define ID_SCAN_RANGE   1201
#define ID_SCAN_GO      1202
#define ID_SCAN_STOP    1203
#define ID_SCAN_USE     1204
#define ID_SCAN_CLOSE   1205

#define WM_APP_JOB_DONE       (WM_APP + 1)
#define WM_APP_PROGRESS       (WM_APP + 2)
#define WM_APP_SCAN_PROGRESS  (WM_APP + 3)   /* wp = done, lp = total; lp 0 =
                                                * probing over, wp hosts to check */
#define WM_APP_SCAN_HIT       (WM_APP + 4)   /* lp = heap EngScanHit, UI frees */

static HWND g_frame, g_toolbar, g_addrbar, g_listview, g_status, g_progress;
static HWND g_connect_wnd, g_connect_host, g_connect_user, g_connect_pass, g_connect_domain, g_connect_share;
static HWND g_scan_wnd, g_scan_range, g_scan_list, g_scan_text, g_scan_go, g_scan_stop;
static int  g_scan_rows;                 /* rows currently in g_scan_list */
static HANDLE g_worker;
static volatile int g_job_running;
static volatile int g_cancel_flag;
static Ctx g_ctx;

/*
 * JobKind / JobRequest / JobResult - the worker-thread job mechanism. A
 * JobRequest is built on the UI thread and handed to job_thread() via
 * CreateThread's parameter; job_thread allocates a JobResult, fills it in,
 * and PostMessageA's it back as WM_APP_JOB_DONE's lParam. Ownership of each
 * struct transfers with the handoff - whichever side receives one is the
 * only side that may free it. g_job_kind mirrors the running job's kind so
 * Cancel knows whether there is a transfer to cancel.
 */
typedef enum { JOB_CONNECT, JOB_NAVIGATE, JOB_REFRESH, JOB_GET, JOB_PUT, JOB_SCAN } JobKind;

static JobKind g_job_kind;

typedef struct {
    JobKind kind;
    char    host[SERVER_LEN];
    char    user[SMB_CREDS_MAXLEN];
    char    pass[SMB_CREDS_MAXLEN];
    char    domain[SMB_CREDS_MAXLEN];
    char    share[SHARE_LEN];
    char    target[PATH_LEN];        /* JOB_NAVIGATE: arg for eng_cd */
    char    remote_arg[PATH_LEN];    /* JOB_GET: remote file to fetch;
                                       * JOB_PUT: remote target (the local
                                       * file's own base name) */
    char    local_path[PATH_LEN];    /* JOB_GET: where to save; JOB_PUT: the
                                       * local file to read */
    char    range[64];               /* JOB_SCAN: address text for
                                       * eng_parse_range() */
} JobRequest;

typedef struct {
    JobKind   kind;
    int       ok;
    int       warning;      /* JOB_PUT: uploaded, but eng_put_file could not
                              * verify it (errbuf holds why); JOB_SCAN: the
                              * scan was stopped before it finished */
    char      errbuf[ENG_ERRLEN];
    EngEntry *entries;
    size_t    count;         /* directory entries; JOB_SCAN: hosts that answered */
    char      addr_text[SERVER_LEN + SHARE_LEN + PATH_LEN];
    uint64_t  done;          /* JOB_GET/JOB_PUT: bytes transferred */
} JobResult;

/*
 * dbg_log - write a line to OutputDebugStringA (visible in a real debugger
 *           or DebugView on actual Windows) and append it to a local log
 *           file (winsmbftp-debug.log, next to the exe) so this can be
 *           inspected directly without either one - added specifically
 *           because screen captures of a Wine session proved unreliable in
 *           the environment this was tested in (see archive/REGRESSION.md)
 * Inputs : msg = line to log (no trailing newline needed)
 * Outputs: none
 * Clobbers: appends to winsmbftp-debug.log
 *
 * Compiled in only when WINSMB_DEBUG is defined (build.cmd gui debug);
 * otherwise dbg_log(x) is ((void)0) and its argument is not evaluated. The
 * sprintf() calls that format a line into a local buffer first are still
 * there in a normal build - cheap, and their result is simply never used.
 */
#ifdef WINSMB_DEBUG
static void dbg_log(const char *msg)
{
    FILE *f;

    OutputDebugStringA(msg);
    f = fopen("winsmbftp-debug.log", "a");
    if (f != NULL) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}
#else
#define dbg_log(msg) ((void)0)
#endif

/*
 * layout_frame - position the toolbar, address bar, ListView and status bar
 *                within the frame's current client area
 * Inputs : frame = the frame window
 * Outputs: none
 * Clobbers: the size/position of all four child controls
 */
static void layout_frame(HWND frame)
{
    RECT rc;
    int y, list_h;

    GetClientRect(frame, &rc);

    MoveWindow(g_toolbar, 0, 0, rc.right, TOOLBAR_H, TRUE);
    SendMessageA(g_toolbar, TB_AUTOSIZE, 0, 0);
    y = TOOLBAR_H;

    MoveWindow(g_addrbar, 2, y + 2, rc.right - 4, ADDRBAR_H - 4, TRUE);
    y += ADDRBAR_H;

    MoveWindow(g_status, 0, rc.bottom - STATUS_H, rc.right, STATUS_H, TRUE);
    MoveWindow(g_progress, rc.right - 150, rc.bottom - STATUS_H + 2, 146, STATUS_H - 4, TRUE);

    list_h = rc.bottom - STATUS_H - y;
    if (list_h < 0)
        list_h = 0;
    MoveWindow(g_listview, 0, y, rc.right, list_h, TRUE);
}

/*
 * add_toolbar_buttons - create the toolbar's fixed button set
 * Inputs : none (uses g_toolbar)
 * Outputs: none
 * Clobbers: g_toolbar's button list
 */
static void add_toolbar_buttons(void)
{
    TBBUTTON b[10];
    int n = 0;

    memset(b, 0, sizeof b);

#define ADD_BTN(id, text) \
    do { \
        b[n].iBitmap = I_IMAGENONE; \
        b[n].idCommand = (id); \
        b[n].fsState = TBSTATE_ENABLED; \
        b[n].fsStyle = TBSTYLE_BUTTON; \
        b[n].iString = (LONG)(text); \
        n++; \
    } while (0)
#define ADD_SEP() \
    do { b[n].fsStyle = TBSTYLE_SEP; n++; } while (0)

    ADD_BTN(ID_TB_UP, "Up");
    ADD_BTN(ID_TB_REFRESH, "Refresh");
    ADD_SEP();
    ADD_BTN(ID_TB_CONNECT, "Connect");
    ADD_BTN(ID_TB_SCAN, "Scan");
    ADD_SEP();
    ADD_BTN(ID_TB_GET, "Get");
    ADD_BTN(ID_TB_PUT, "Put");
    ADD_BTN(ID_TB_CANCEL, "Cancel");

#undef ADD_BTN
#undef ADD_SEP

    SendMessageA(g_toolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessageA(g_toolbar, TB_ADDBUTTONSA, n, (LPARAM)b);
}

/*
 * add_listview_columns - set up the Name/Size/Type/Modified report columns
 * Inputs : none (uses g_listview)
 * Outputs: none
 * Clobbers: g_listview's column list
 */
static void add_listview_columns(void)
{
    LVCOLUMNA col;

    memset(&col, 0, sizeof col);
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.pszText = "Name";     col.cx = 220; col.iSubItem = 0;
    SendMessageA(g_listview, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.pszText = "Size";     col.cx = 90;  col.iSubItem = 1;
    SendMessageA(g_listview, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    col.pszText = "Type";     col.cx = 90;  col.iSubItem = 2;
    SendMessageA(g_listview, LVM_INSERTCOLUMNA, 2, (LPARAM)&col);
    col.pszText = "Modified"; col.cx = 140; col.iSubItem = 3;
    SendMessageA(g_listview, LVM_INSERTCOLUMNA, 3, (LPARAM)&col);
}

/*
 * add_listview_row - insert one four-column row
 * Inputs : idx = 0-based row index to insert at, name/size/type/modified =
 *          the text for each column, isdir = stored in the row's lParam so
 *          a later double-click can tell a directory from a file without
 *          re-parsing the displayed text
 * Outputs: none
 * Clobbers: g_listview's item list
 */
static void add_listview_row(int idx, const char *name, const char *size,
                              const char *type, const char *modified, int isdir)
{
    LVITEMA item;

    memset(&item, 0, sizeof item);
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = idx;
    item.pszText = (LPSTR)name;
    item.lParam = isdir;
    SendMessageA(g_listview, LVM_INSERTITEMA, 0, (LPARAM)&item);

    item.mask = LVIF_TEXT;
    item.iSubItem = 1; item.pszText = (LPSTR)size;
    SendMessageA(g_listview, LVM_SETITEMA, 0, (LPARAM)&item);
    item.iSubItem = 2; item.pszText = (LPSTR)type;
    SendMessageA(g_listview, LVM_SETITEMA, 0, (LPARAM)&item);
    item.iSubItem = 3; item.pszText = (LPSTR)modified;
    SendMessageA(g_listview, LVM_SETITEMA, 0, (LPARAM)&item);
}

/*
 * populate_listview - clear the ListView and fill it from a real directory
 *                      listing (replaces Phase 3's hardcoded test rows)
 * Inputs : entries/count = as returned by eng_list_dir()
 * Outputs: none
 * Clobbers: g_listview's item list
 */
static void populate_listview(EngEntry *entries, size_t count)
{
    size_t i;
    char sizebuf[24], typebuf[16], timebuf[24];

    SendMessageA(g_listview, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < count; i++) {
        if (entries[i].isdir) {
            strcpy(sizebuf, "<DIR>");
            strcpy(typebuf, "Folder");
        } else {
            u64_str(sizebuf, entries[i].size);
            strcpy(typebuf, "File");
        }
        ft_str(entries[i].wtime, timebuf);
        add_listview_row((int)i, entries[i].name, sizebuf, typebuf, timebuf,
                          entries[i].isdir);
    }
}

/*
 * set_status - replace the status bar's text
 * Inputs : text
 * Outputs: none
 * Clobbers: g_status's displayed text
 */
static void set_status(const char *text)
{
    SendMessageA(g_status, SB_SETTEXTA, 0, (LPARAM)text);
}

/*
 * gui_xfer_progress - eng_xfer_cb passed to eng_get_file()/eng_put_file();
 *                      runs on the worker thread, so it only PostMessageA's
 *                      - it never touches the progress bar directly
 * Inputs : done, total = as eng_xfer_cb documents; user = unused
 * Outputs: none
 * Clobbers: none directly; queues a WM_APP_PROGRESS for the frame
 *
 * Note: done/total are truncated to 32 bits for the message parameters.
 * Fine for any file this project's SMB1 target is likely to see; a transfer
 * past 4 GiB would show a wrapped percentage (the transfer itself is not
 * affected - eng_get_file/eng_put_file still track the real 64-bit counts).
 */
static void gui_xfer_progress(uint64_t done, uint64_t total, void *user)
{
    (void)user;
    PostMessageA(g_frame, WM_APP_PROGRESS, (WPARAM)(DWORD)done, (LPARAM)(DWORD)total);
}

/*
 * ip_net_text - dotted-quad text of an IPv4 address held in network order
 * Inputs : ip_net = address as eng_probe_range() returns it, buf = output
 *          (>= 16 bytes)
 * Outputs: none
 * Clobbers: buf
 */
static void ip_net_text(uint32_t ip_net, char *buf)
{
    const unsigned char *b = (const unsigned char *)&ip_net;

    sprintf(buf, "%u.%u.%u.%u", (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3]);
}

/*
 * gui_scan_progress - eng_scan_prog_cb passed to eng_probe_range(); runs on
 *                     the worker thread, so it only PostMessageA's
 * Inputs : done, total = addresses handled / in the range; user = unused
 * Outputs: none
 * Clobbers: none directly; queues a WM_APP_SCAN_PROGRESS for the frame
 */
static void gui_scan_progress(unsigned long done, unsigned long total, void *user)
{
    (void)user;
    PostMessageA(g_frame, WM_APP_SCAN_PROGRESS, (WPARAM)done, (LPARAM)total);
}

/*
 * job_thread - worker-thread entry point for every blocking smb_engine call
 * Inputs : param = a heap-allocated JobRequest (freed here)
 * Outputs: 0 (unused)
 * Clobbers: g_ctx's session/share/cwd fields (JOB_CONNECT/JOB_NAVIGATE only;
 *          see the file header for why this is safe); posts
 *          WM_APP_JOB_DONE to g_frame with a heap-allocated JobResult that
 *          the message handler must free (and, on success, must also
 *          eng_free_entries() its entries)
 */
static DWORD SMB_STDCALL job_thread(void *param)
{
    JobRequest *req = (JobRequest *)param;
    JobResult *res = (JobResult *)malloc(sizeof *res);
    uint32_t ip;
    char dbgbuf[400];
    int rc;

    memset(res, 0, sizeof *res);
    res->kind = req->kind;
    sprintf(dbgbuf, "job_thread: start kind=%d", (int)req->kind);
    dbg_log(dbgbuf);

    if (req->kind == JOB_GET) {
        rc = eng_get_file(&g_ctx, req->remote_arg, req->local_path,
                           gui_xfer_progress, NULL, &g_cancel_flag,
                           &res->done, res->errbuf, sizeof res->errbuf);
        sprintf(dbgbuf, "job_thread: eng_get_file rc=%d done=%lu err='%s'",
                rc, (unsigned long)res->done, res->errbuf);
        dbg_log(dbgbuf);
        res->ok = (rc == 0);
        goto post;
    }
    if (req->kind == JOB_PUT) {
        rc = eng_put_file(&g_ctx, req->local_path, req->remote_arg,
                           gui_xfer_progress, NULL, &g_cancel_flag,
                           &res->done, res->errbuf, sizeof res->errbuf);
        sprintf(dbgbuf, "job_thread: eng_put_file rc=%d done=%lu err='%s'",
                rc, (unsigned long)res->done, res->errbuf);
        dbg_log(dbgbuf);
        res->ok = (rc >= 0);
        res->warning = (rc == 1);
        goto post;
    }

    if (req->kind == JOB_SCAN) {
        uint32_t first, last, *ips = NULL;
        EngScanHit *hit;
        char ipt[16];
        int n, i, found = 0;

        if (eng_parse_range(req->range, &first, &last) != 0) {
            str_copy(res->errbuf, sizeof res->errbuf, "invalid address range");
            goto post;
        }
        n = eng_probe_range(first, last, DEF_WAIT_MS, &g_cancel_flag,
                             gui_scan_progress, NULL, &ips);
        sprintf(dbgbuf, "job_thread: eng_probe_range '%s' -> %d", req->range, n);
        dbg_log(dbgbuf);
        if (n < 0) {
            str_copy(res->errbuf, sizeof res->errbuf, "out of memory");
            goto post;
        }
        PostMessageA(g_frame, WM_APP_SCAN_PROGRESS, (WPARAM)n, 0);
        for (i = 0; i < n && !g_cancel_flag; i++) {
            hit = (EngScanHit *)malloc(sizeof *hit);
            if (hit == NULL)
                break;
            ip_net_text(ips[i], ipt);
            if (eng_scan_host(ips[i], ipt, DEF_WAIT_MS, hit)) {
                sprintf(dbgbuf, "job_thread: scan_host %s status=%d shares=%d",
                        ipt, hit->status, hit->share_count);
                dbg_log(dbgbuf);
                found++;
                if (!PostMessageA(g_frame, WM_APP_SCAN_HIT, 0, (LPARAM)hit)) {
                    eng_free_scan_hit(hit);        /* frame already gone */
                    free(hit);
                }
            } else {
                free(hit);
            }
        }
        free(ips);
        res->count = (size_t)found;
        res->warning = g_cancel_flag ? 1 : 0;
        res->ok = 1;
        goto post;
    }

    if (req->kind == JOB_CONNECT) {
        if (!parse_ipv4(req->host, &ip)) {
            str_copy(res->errbuf, sizeof res->errbuf, "invalid IPv4 address");
            dbg_log("job_thread: parse_ipv4 failed");
            goto post;
        }
        eng_disconnect(&g_ctx);               /* a new Connect replaces any old session */
        g_ctx.sess = eng_connect(ip, req->host, 0, NULL, NULL, NULL,
                                  res->errbuf, sizeof res->errbuf);
        sprintf(dbgbuf, "job_thread: eng_connect sess=%p err='%s'",
                (void *)g_ctx.sess, res->errbuf);
        dbg_log(dbgbuf);
        if (g_ctx.sess == NULL)
            goto post;
        str_copy(g_ctx.server, sizeof g_ctx.server, req->host);
        if (eng_login(&g_ctx, req->domain, req->user, req->pass, NULL,
                       res->errbuf, sizeof res->errbuf) != 0) {
            sprintf(dbgbuf, "job_thread: eng_login failed err='%s'", res->errbuf);
            dbg_log(dbgbuf);
            eng_disconnect(&g_ctx);           /* close the half-open session */
            goto post;
        }
        dbg_log("job_thread: eng_login OK");
        if (eng_use_share(&g_ctx, req->share, res->errbuf, sizeof res->errbuf) != 0) {
            sprintf(dbgbuf, "job_thread: eng_use_share failed err='%s'", res->errbuf);
            dbg_log(dbgbuf);
            eng_disconnect(&g_ctx);           /* close the half-open session */
            goto post;
        }
        dbg_log("job_thread: eng_use_share OK");
    } else if (req->kind == JOB_NAVIGATE) {
        sprintf(dbgbuf, "job_thread: eng_cd target='%s'", req->target);
        dbg_log(dbgbuf);
        if (eng_cd(&g_ctx, req->target, res->errbuf, sizeof res->errbuf) != 0) {
            sprintf(dbgbuf, "job_thread: eng_cd failed err='%s'", res->errbuf);
            dbg_log(dbgbuf);
            goto post;
        }
    }
    /* JOB_REFRESH falls straight through to the listing below */

    if (eng_list_dir(&g_ctx, ".", &res->entries, &res->count,
                      res->errbuf, sizeof res->errbuf) != 0) {
        sprintf(dbgbuf, "job_thread: eng_list_dir failed err='%s'", res->errbuf);
        dbg_log(dbgbuf);
        goto post;
    }
    sprintf(dbgbuf, "job_thread: eng_list_dir OK count=%lu", (unsigned long)res->count);
    dbg_log(dbgbuf);

    sprintf(res->addr_text, "\\\\%s\\%s%s", g_ctx.server, g_ctx.share, g_ctx.cwd);
    res->ok = 1;

post:
    sprintf(dbgbuf, "job_thread: done ok=%d addr='%s'", res->ok, res->addr_text);
    dbg_log(dbgbuf);
    free(req);
    PostMessageA(g_frame, WM_APP_JOB_DONE, 0, (LPARAM)res);
    return 0;
}

/*
 * start_job - launch a job on the worker thread if none is already running
 * Inputs : req = heap-allocated request (job_thread frees it); busy_text =
 *          status bar text while the job runs
 * Outputs: none
 * Clobbers: g_job_running, g_worker, the status bar; frees req immediately
 *          (without starting a thread) if a job is already running
 */
static void start_job(JobRequest *req, const char *busy_text)
{
    if (g_job_running) {
        free(req);
        return;
    }
    g_job_running = 1;
    g_job_kind = req->kind;
    g_cancel_flag = 0;
    if (req->kind == JOB_GET || req->kind == JOB_PUT) {
        SendMessageA(g_progress, PBM_SETPOS, 0, 0);
        ShowWindow(g_progress, SW_SHOW);
    }
    set_status(busy_text);
    g_worker = CreateThread(NULL, 0, job_thread, req, 0, NULL);
    if (g_worker == NULL) {
        g_job_running = 0;
        set_status("Error: could not start worker thread.");
        if (req->kind == JOB_GET || req->kind == JOB_PUT)
            ShowWindow(g_progress, SW_HIDE);
        free(req);
    }
}

/*
 * get_selected_item - the ListView's currently selected row, if any
 * Inputs : none (uses g_listview)
 * Outputs: 0-based row index, or -1 if nothing is selected
 * Clobbers: none
 */
static int get_selected_item(void)
{
    return (int)SendMessageA(g_listview, LVM_GETNEXTITEM, (WPARAM)-1, (LPARAM)LVNI_SELECTED);
}

/*
 * do_get_row - start a download for one ListView row, after confirming with
 *              a Save dialog
 * Inputs : item = 0-based row index (from selection or a double-click)
 * Outputs: none
 * Clobbers: starts a JOB_GET job; shows a Save dialog
 */
static void do_get_row(int item)
{
    LVITEMA gi;
    char name[256];
    OPENFILENAMEA ofn;
    char filepath[PATH_LEN];
    JobRequest *req;

    if (item < 0) {
        set_status("Select a file first.");
        return;
    }
    memset(&gi, 0, sizeof gi);
    gi.mask = LVIF_TEXT | LVIF_PARAM;
    gi.iItem = item;
    gi.pszText = name;
    gi.cchTextMax = sizeof name;
    name[0] = '\0';
    SendMessageA(g_listview, LVM_GETITEMA, 0, (LPARAM)&gi);
    if (gi.lParam) {
        set_status("That's a folder - double-click it to open it, not Get.");
        return;
    }
    if (name[0] == '\0' || strcmp(name, "..") == 0) {
        set_status("Select a file first.");
        return;
    }

    str_copy(filepath, sizeof filepath, name);
    memset(&ofn, 0, sizeof ofn);
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g_frame;
    ofn.lpstrFilter = "All Files (*.*)\0*.*\0\0";
    ofn.lpstrFile = filepath;
    ofn.nMaxFile = sizeof filepath;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = "Save As";
    if (!GetSaveFileNameA(&ofn)) {
        set_status("Ready.");
        return;
    }

    {
        char dbgbuf[400];
        sprintf(dbgbuf, "do_get_row: remote='%s' local='%s'", name, filepath);
        dbg_log(dbgbuf);
    }
    req = (JobRequest *)malloc(sizeof *req);
    memset(req, 0, sizeof *req);
    req->kind = JOB_GET;
    str_copy(req->remote_arg, sizeof req->remote_arg, name);
    str_copy(req->local_path, sizeof req->local_path, filepath);
    start_job(req, "Downloading...");
}

/*
 * do_put - start an upload, after choosing a local file with an Open dialog
 * Inputs : none
 * Outputs: none
 * Clobbers: starts a JOB_PUT job; shows an Open dialog
 */
static void do_put(void)
{
    OPENFILENAMEA ofn;
    char filepath[PATH_LEN];
    JobRequest *req;
    const char *base;

    memset(&ofn, 0, sizeof ofn);
    filepath[0] = '\0';
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g_frame;
    ofn.lpstrFilter = "All Files (*.*)\0*.*\0\0";
    ofn.lpstrFile = filepath;
    ofn.nMaxFile = sizeof filepath;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_EXPLORER;
    ofn.lpstrTitle = "Open";
    if (!GetOpenFileNameA(&ofn)) {
        set_status("Ready.");
        return;
    }

    base = base_name(filepath);
    if (*base == '\0') {
        set_status("Error: invalid local file name.");
        return;
    }

    {
        char dbgbuf[400];
        sprintf(dbgbuf, "do_put: local='%s' remote_arg='%s'", filepath, base);
        dbg_log(dbgbuf);
    }
    req = (JobRequest *)malloc(sizeof *req);
    memset(req, 0, sizeof *req);
    req->kind = JOB_PUT;
    str_copy(req->local_path, sizeof req->local_path, filepath);
    str_copy(req->remote_arg, sizeof req->remote_arg, base);
    start_job(req, "Uploading...");
}

/*
 * connect_wndproc - window procedure for the Connect window
 * Inputs : standard Win32 window-procedure parameters
 * Outputs: standard Win32 window-procedure result
 * Clobbers: on OK, reads the edit controls and calls start_job(); on OK or
 *          Cancel, destroys the window and re-enables the frame
 */
static LRESULT SMB_STDCALL connect_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wp) == ID_CONNECT_OK) {
            JobRequest *req = (JobRequest *)malloc(sizeof *req);
            char dbgbuf[400];
            memset(req, 0, sizeof *req);
            req->kind = JOB_CONNECT;
            GetWindowTextA(g_connect_host, req->host, sizeof req->host);
            GetWindowTextA(g_connect_user, req->user, sizeof req->user);
            GetWindowTextA(g_connect_pass, req->pass, sizeof req->pass);
            GetWindowTextA(g_connect_domain, req->domain, sizeof req->domain);
            GetWindowTextA(g_connect_share, req->share, sizeof req->share);
            sprintf(dbgbuf, "connect: OK clicked host='%s' share='%s' user='%s' domain='%s' pass_len=%d",
                    req->host, req->share, req->user, req->domain, (int)strlen(req->pass));
            dbg_log(dbgbuf);
            if (req->host[0] == '\0' || req->share[0] == '\0') {
                dbg_log("connect: rejected (host or share empty)");
                MessageBoxA(hwnd, "Host and share are both required.", WINTITLE,
                            MB_OK | MB_ICONERROR);
                free(req);
                return 0;
            }
            start_job(req, "Connecting...");
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == ID_CONNECT_CANCEL) {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        g_connect_wnd = NULL;
        EnableWindow(g_frame, TRUE);
        SetForegroundWindow(g_frame);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

/*
 * add_connect_field - one label + edit control row in the Connect window
 * Inputs : parent, y = row's top in client coordinates, label, id = the
 *          edit control's id, initial = starting text, password = 1 for a
 *          masked password field
 * Outputs: the edit control's HWND
 * Clobbers: creates two child windows
 */
static HWND add_connect_field(HWND parent, int y, const char *label, int id,
                               const char *initial, int password)
{
    HWND edit;
    DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;

    CreateWindowExA(0, "STATIC", label, WS_CHILD | WS_VISIBLE,
                     10, y + 2, 70, 18, parent, NULL, GetModuleHandleA(NULL), NULL);
    if (password)
        style |= ES_PASSWORD;
    edit = CreateWindowExA(0, "EDIT", initial, style,
                            85, y, 190, 20, parent, (HMENU)(LONG)id,
                            GetModuleHandleA(NULL), NULL);
    return edit;
}

/*
 * open_connect_window - create and show the Connect window, disabling the
 *                        frame underneath it (a lightweight stand-in for a
 *                        true modal dialog, since there is no DIALOGEX here)
 * Inputs : host, share = text to pre-fill the Host and Share fields with
 *          (NULL for empty - the Scan window passes what was picked)
 * Outputs: none
 * Clobbers: g_connect_wnd and its field HWNDs; disables g_frame
 */
static void open_connect_window(const char *host, const char *share)
{
    WNDCLASSEXA wc;
    static int class_registered;
    int y = 10;

    if (g_connect_wnd != NULL)
        return;

    if (!class_registered) {
        memset(&wc, 0, sizeof wc);
        wc.cbSize = sizeof wc;
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = connect_wndproc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
        wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
        wc.hbrBackground = COLOR_BRUSH(COLOR_BTNFACE);
        wc.lpszClassName = CONNECT_CLASS;
        wc.hIconSm = wc.hIcon;
        if (RegisterClassExA(&wc) == 0)
            return;
        class_registered = 1;
    }

    g_connect_wnd = CreateWindowExA(0, CONNECT_CLASS, "Connect",
                                     WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                     CW_USEDEFAULT, CW_USEDEFAULT, 300, 230,
                                     g_frame, NULL, GetModuleHandleA(NULL), NULL);
    if (g_connect_wnd == NULL)
        return;

    g_connect_host   = add_connect_field(g_connect_wnd, y, "Host:",   ID_CONNECT_HOST,   host != NULL ? host : "", 0); y += 28;
    g_connect_user   = add_connect_field(g_connect_wnd, y, "User:",   ID_CONNECT_USER,   "guest", 0); y += 28;
    g_connect_pass   = add_connect_field(g_connect_wnd, y, "Password:", ID_CONNECT_PASS, "", 1); y += 28;
    g_connect_domain = add_connect_field(g_connect_wnd, y, "Domain:", ID_CONNECT_DOMAIN, "WORKGROUP", 0); y += 28;
    g_connect_share  = add_connect_field(g_connect_wnd, y, "Share:",  ID_CONNECT_SHARE,  share != NULL ? share : "", 0); y += 36;

    CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE,
                     85, y, 80, 24, g_connect_wnd, (HMENU)ID_CONNECT_OK,
                     GetModuleHandleA(NULL), NULL);
    CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
                     175, y, 80, 24, g_connect_wnd, (HMENU)ID_CONNECT_CANCEL,
                     GetModuleHandleA(NULL), NULL);

    EnableWindow(g_frame, FALSE);
    ShowWindow(g_connect_wnd, SW_SHOWDEFAULT);
    UpdateWindow(g_connect_wnd);
}

/*
 * scan_set_text - replace the Scan window's one-line status text
 * Inputs : text
 * Outputs: none
 * Clobbers: g_scan_text's displayed text (no-op if the window is closed)
 */
static void scan_set_text(const char *text)
{
    if (g_scan_text != NULL)
        SetWindowTextA(g_scan_text, text);
}

/*
 * scan_add_row - append one row to the Scan window's Host/Share list
 * Inputs : host = address text, what = share name or a bracketed status,
 *          kind = stored in the row's lParam: 1 = a share (Use fills host
 *          and share), 2 = host only (Use fills just the host), 0 = nothing
 *          to connect to
 * Outputs: none
 * Clobbers: g_scan_list's item list, g_scan_rows
 */
static void scan_add_row(const char *host, const char *what, int kind)
{
    LVITEMA item;

    memset(&item, 0, sizeof item);
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = g_scan_rows;
    item.pszText = (LPSTR)host;
    item.lParam = kind;
    SendMessageA(g_scan_list, LVM_INSERTITEMA, 0, (LPARAM)&item);

    item.mask = LVIF_TEXT;
    item.iSubItem = 1;
    item.pszText = (LPSTR)what;
    SendMessageA(g_scan_list, LVM_SETITEMA, 0, (LPARAM)&item);
    g_scan_rows++;
}

/*
 * scan_add_hit - show one scanned host: a row per share, or one status row
 * Inputs : h = hit as eng_scan_host() filled it (caller still owns it)
 * Outputs: none
 * Clobbers: g_scan_list's item list, g_scan_rows
 */
static void scan_add_hit(const EngScanHit *h)
{
    int i;

    if (h->status == ENG_SCAN_SMB1_SHARES && h->share_count > 0) {
        for (i = 0; i < h->share_count; i++)
            scan_add_row(h->ip_text, h->shares[i], 1);
    } else if (h->status == ENG_SCAN_SMB1_SHARES) {
        scan_add_row(h->ip_text, "(SMB1, no shares listed)", 2);
    } else if (h->status == ENG_SCAN_SMB1_NOGUEST) {
        scan_add_row(h->ip_text, "(SMB1 - login required)", 2);
    } else {
        scan_add_row(h->ip_text, "(SMB port open, but not SMB1)", 0);
    }
}

/*
 * scan_start - validate the range text and start a JOB_SCAN
 * Inputs : none (reads g_scan_range)
 * Outputs: none
 * Clobbers: empties g_scan_list; Scan/Stop button states; starts a job
 */
static void scan_start(void)
{
    char text[64];
    uint32_t first, last;
    JobRequest *req;

    if (g_job_running)
        return;
    GetWindowTextA(g_scan_range, text, sizeof text);
    if (eng_parse_range(text, &first, &last) != 0) {
        MessageBoxA(g_scan_wnd, "Enter one address (a.b.c.d) or a network (a.b.c.d/n, n = 16 to 32).",
                    WINTITLE, MB_OK | MB_ICONERROR);
        return;
    }
    SendMessageA(g_scan_list, LVM_DELETEALLITEMS, 0, 0);
    g_scan_rows = 0;
    EnableWindow(g_scan_go, FALSE);
    EnableWindow(g_scan_stop, TRUE);
    scan_set_text("Probing...");

    req = (JobRequest *)malloc(sizeof *req);
    if (req == NULL)
        return;
    memset(req, 0, sizeof *req);
    req->kind = JOB_SCAN;
    str_copy(req->range, sizeof req->range, text);
    dbg_log("scan: start");
    start_job(req, "Scanning...");
    if (!g_job_running) {                     /* thread could not be started */
        EnableWindow(g_scan_go, TRUE);
        EnableWindow(g_scan_stop, FALSE);
    }
}

/*
 * scan_use_selected - close the Scan window and open Connect with the
 *                     selected row's host (and share, for a share row)
 * Inputs : none (reads the selected row of g_scan_list)
 * Outputs: none
 * Clobbers: destroys g_scan_wnd and opens the Connect window; only a text
 *          message if nothing usable is selected or a scan is still running
 */
static void scan_use_selected(void)
{
    char host[SERVER_LEN], share[SHARE_LEN];
    LVITEMA item;
    int sel, kind;

    if (g_job_running) {
        scan_set_text("Press Stop (or wait for the scan to finish) first.");
        return;
    }
    sel = (int)SendMessageA(g_scan_list, LVM_GETNEXTITEM, (WPARAM)-1, (LPARAM)LVNI_SELECTED);
    if (sel < 0) {
        scan_set_text("Select a share in the list first.");
        return;
    }
    memset(&item, 0, sizeof item);
    item.mask = LVIF_PARAM;
    item.iItem = sel;
    SendMessageA(g_scan_list, LVM_GETITEMA, 0, (LPARAM)&item);
    kind = (int)item.lParam;
    if (kind == 0) {
        scan_set_text("That host does not answer in SMB1 - nothing to connect to.");
        return;
    }
    host[0] = '\0';
    share[0] = '\0';
    memset(&item, 0, sizeof item);
    item.iSubItem = 0;
    item.pszText = host;
    item.cchTextMax = sizeof host;
    SendMessageA(g_scan_list, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&item);
    if (kind == 1) {
        memset(&item, 0, sizeof item);
        item.iSubItem = 1;
        item.pszText = share;
        item.cchTextMax = sizeof share;
        SendMessageA(g_scan_list, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&item);
    }
    dbg_log("scan: use selected -> Connect");
    DestroyWindow(g_scan_wnd);                /* WM_DESTROY re-enables the frame */
    open_connect_window(host, share);
}

/*
 * scan_wndproc - window procedure for the Scan window
 * Inputs : standard Win32 window-procedure parameters
 * Outputs: standard Win32 window-procedure result
 * Clobbers: Scan/Stop/Use/Close start or stop a scan, open Connect or
 *          destroy the window; WM_DESTROY clears g_scan_wnd, re-enables the
 *          frame, and asks a running scan to stop
 */
static LRESULT SMB_STDCALL scan_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_SCAN_GO:
            scan_start();
            break;
        case ID_SCAN_STOP:
            if (g_job_running && g_job_kind == JOB_SCAN) {
                g_cancel_flag = 1;
                scan_set_text("Stopping...");
            }
            break;
        case ID_SCAN_USE:
            scan_use_selected();
            break;
        case ID_SCAN_CLOSE:
            DestroyWindow(hwnd);
            break;
        default:
            break;
        }
        return 0;
    case WM_NOTIFY: {
        NMHDR *hdr = (NMHDR *)lp;

        if (hdr->hwndFrom == g_scan_list && hdr->code == NM_DBLCLK)
            scan_use_selected();
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_job_running && g_job_kind == JOB_SCAN)
            g_cancel_flag = 1;
        g_scan_wnd = NULL;
        g_scan_text = NULL;
        EnableWindow(g_frame, TRUE);
        SetForegroundWindow(g_frame);
        return 0;
    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

/*
 * open_scan_window - create and show the Scan window, disabling the frame
 *                    underneath it the same way the Connect window does
 * Inputs : none
 * Outputs: none
 * Clobbers: g_scan_wnd and its control HWNDs; disables g_frame
 */
static void open_scan_window(void)
{
    WNDCLASSEXA wc;
    static int class_registered;
    LVCOLUMNA col;
    char range[32];
    HINSTANCE inst = GetModuleHandleA(NULL);

    if (g_scan_wnd != NULL)
        return;

    if (!class_registered) {
        memset(&wc, 0, sizeof wc);
        wc.cbSize = sizeof wc;
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = scan_wndproc;
        wc.hInstance = inst;
        wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
        wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
        wc.hbrBackground = COLOR_BRUSH(COLOR_BTNFACE);
        wc.lpszClassName = SCANWIN_CLASS;
        wc.hIconSm = wc.hIcon;
        if (RegisterClassExA(&wc) == 0)
            return;
        class_registered = 1;
    }

    g_scan_wnd = CreateWindowExA(0, SCANWIN_CLASS, "Scan for SMB1 servers",
                                  WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 450, 380,
                                  g_frame, NULL, inst, NULL);
    if (g_scan_wnd == NULL)
        return;

    if (!eng_default_range(range, sizeof range))
        range[0] = '\0';

    CreateWindowExA(0, "STATIC", "Range:", WS_CHILD | WS_VISIBLE,
                     10, 12, 50, 18, g_scan_wnd, NULL, inst, NULL);
    g_scan_range = CreateWindowExA(0, "EDIT", range,
                                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                    65, 10, 195, 20, g_scan_wnd, (HMENU)(LONG)ID_SCAN_RANGE,
                                    inst, NULL);
    g_scan_go = CreateWindowExA(0, "BUTTON", "Scan", WS_CHILD | WS_VISIBLE,
                                 268, 8, 75, 24, g_scan_wnd, (HMENU)ID_SCAN_GO, inst, NULL);
    g_scan_stop = CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE,
                                   348, 8, 75, 24, g_scan_wnd, (HMENU)ID_SCAN_STOP, inst, NULL);
    EnableWindow(g_scan_stop, FALSE);

    g_scan_list = CreateWindowExA(0, WC_LISTVIEWA, NULL,
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
                                   10, 42, 413, 230, g_scan_wnd, NULL, inst, NULL);
    SendMessageA(g_scan_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
    memset(&col, 0, sizeof col);
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = "Host";           col.cx = 120; col.iSubItem = 0;
    SendMessageA(g_scan_list, LVM_INSERTCOLUMNA, 0, (LPARAM)&col);
    col.pszText = "Share / status"; col.cx = 270; col.iSubItem = 1;
    SendMessageA(g_scan_list, LVM_INSERTCOLUMNA, 1, (LPARAM)&col);
    g_scan_rows = 0;

    g_scan_text = CreateWindowExA(0, "STATIC",
                                   range[0] != '\0' ? "Ready. Guest login only." :
                                   "Enter a network such as 192.168.1.0/24.",
                                   WS_CHILD | WS_VISIBLE,
                                   10, 280, 413, 18, g_scan_wnd, NULL, inst, NULL);
    CreateWindowExA(0, "BUTTON", "Use selected", WS_CHILD | WS_VISIBLE,
                     180, 304, 120, 24, g_scan_wnd, (HMENU)ID_SCAN_USE, inst, NULL);
    CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE,
                     348, 304, 75, 24, g_scan_wnd, (HMENU)ID_SCAN_CLOSE, inst, NULL);

    EnableWindow(g_frame, FALSE);
    ShowWindow(g_scan_wnd, SW_SHOWDEFAULT);
    UpdateWindow(g_scan_wnd);
}

/*
 * frame_wndproc - window procedure for the main frame
 * Inputs : standard Win32 window-procedure parameters
 * Outputs: standard Win32 window-procedure result
 * Clobbers: creates all four child controls on WM_CREATE; posts WM_QUIT on
 *          WM_DESTROY; starts jobs and applies their results as above
 */
static LRESULT SMB_STDCALL frame_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        dbg_log("frame: WM_CREATE");
        g_frame = hwnd;
        g_toolbar = CreateWindowExA(0, TOOLBARCLASSNAME, NULL,
                                     WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_LIST,
                                     0, 0, 0, 0, hwnd, NULL, GetModuleHandleA(NULL), NULL);
        add_toolbar_buttons();

        g_addrbar = CreateWindowExA(0, "EDIT", "(not connected)",
                                     WS_CHILD | WS_VISIBLE | WS_BORDER |
                                     ES_AUTOHSCROLL | ES_READONLY,
                                     0, 0, 0, 0, hwnd, NULL, GetModuleHandleA(NULL), NULL);

        g_listview = CreateWindowExA(0, WC_LISTVIEWA, NULL,
                                      WS_CHILD | WS_VISIBLE | WS_BORDER |
                                      LVS_REPORT | LVS_SHOWSELALWAYS,
                                      0, 0, 0, 0, hwnd, NULL, GetModuleHandleA(NULL), NULL);
        SendMessageA(g_listview, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
        add_listview_columns();

        g_status = CreateWindowExA(0, STATUSCLASSNAME, "Not connected.",
                                    WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                                    hwnd, NULL, GetModuleHandleA(NULL), NULL);

        g_progress = CreateWindowExA(0, PROGRESS_CLASS, NULL, WS_CHILD,
                                      0, 0, 0, 0, hwnd, NULL, GetModuleHandleA(NULL), NULL);
        SendMessageA(g_progress, PBM_SETRANGE, 0, (LPARAM)((0 & 0xFFFF) | ((100 & 0xFFFF) << 16)));

        layout_frame(hwnd);
        return 0;

    case WM_SIZE:
        if (g_status != NULL)
            layout_frame(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_TB_UP:
            if (!g_ctx.have_share) {
                set_status("Not connected.");
            } else if (!g_job_running) {
                JobRequest *req = (JobRequest *)malloc(sizeof *req);
                memset(req, 0, sizeof *req);
                req->kind = JOB_NAVIGATE;
                str_copy(req->target, sizeof req->target, "..");
                start_job(req, "Loading...");
            }
            break;
        case ID_TB_REFRESH:
            if (!g_ctx.have_share) {
                set_status("Not connected.");
            } else if (!g_job_running) {
                JobRequest *req = (JobRequest *)malloc(sizeof *req);
                memset(req, 0, sizeof *req);
                req->kind = JOB_REFRESH;
                start_job(req, "Loading...");
            }
            break;
        case ID_TB_CONNECT:
            if (!g_job_running)
                open_connect_window(NULL, NULL);
            break;
        case ID_TB_SCAN:
            if (!g_job_running)
                open_scan_window();
            break;
        case ID_TB_GET:
            if (!g_ctx.have_share)
                set_status("Not connected.");
            else if (!g_job_running)
                do_get_row(get_selected_item());
            break;
        case ID_TB_PUT:
            if (!g_ctx.have_share)
                set_status("Not connected.");
            else if (!g_job_running)
                do_put();
            break;
        case ID_TB_CANCEL:
            if (g_job_running && (g_job_kind == JOB_GET || g_job_kind == JOB_PUT ||
                                  g_job_kind == JOB_SCAN)) {
                g_cancel_flag = 1;
                set_status("Cancelling...");
            } else {
                set_status("Nothing to cancel.");
            }
            break;
        default: break;
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *hdr = (NMHDR *)lp;
        if (hdr->hwndFrom == g_listview && hdr->code == NM_DBLCLK) {
            NMITEMACTIVATE *nm = (NMITEMACTIVATE *)lp;
            if (!g_ctx.have_share) {
                set_status("Not connected.");
            } else if (nm->iItem >= 0 && !g_job_running) {
                if (nm->lParam) {        /* isdir, stashed at insert time */
                    char name[256];
                    LVITEMA gi;
                    memset(&gi, 0, sizeof gi);
                    gi.mask = LVIF_TEXT;
                    gi.iItem = nm->iItem;
                    gi.pszText = name;
                    gi.cchTextMax = sizeof name;
                    name[0] = '\0';
                    SendMessageA(g_listview, LVM_GETITEMTEXTA, (WPARAM)nm->iItem, (LPARAM)&gi);
                    {
                        JobRequest *req = (JobRequest *)malloc(sizeof *req);
                        memset(req, 0, sizeof *req);
                        req->kind = JOB_NAVIGATE;
                        str_copy(req->target, sizeof req->target, name);
                        start_job(req, "Loading...");
                    }
                } else {
                    do_get_row(nm->iItem);  /* a file: double-click downloads it */
                }
            }
        }
        return 0;
    }

    case WM_APP_PROGRESS: {
        DWORD done = (DWORD)wp;
        DWORD total = (DWORD)lp;
        if (total > 0) {
            int pct = (int)(((unsigned long long)done * 100) / total);
            SendMessageA(g_progress, PBM_SETPOS, (WPARAM)pct, 0);
        }
        return 0;
    }

    case WM_APP_SCAN_PROGRESS:
        if (g_scan_wnd != NULL) {
            char line[96];

            if (lp == 0)
                sprintf(line, "%lu host(s) answered on an SMB port - checking for SMB1...",
                        (unsigned long)wp);
            else
                sprintf(line, "Probing... %lu of %lu addresses", (unsigned long)wp,
                        (unsigned long)lp);
            scan_set_text(line);
        }
        return 0;

    case WM_APP_SCAN_HIT: {
        EngScanHit *h = (EngScanHit *)lp;

        if (g_scan_wnd != NULL)
            scan_add_hit(h);
        eng_free_scan_hit(h);
        free(h);
        return 0;
    }

    case WM_APP_JOB_DONE: {
        JobResult *res = (JobResult *)lp;
        char dbgbuf[ENG_ERRLEN + 80];

        sprintf(dbgbuf, "WM_APP_JOB_DONE: kind=%d ok=%d count=%lu done=%lu err='%s'",
                (int)res->kind, res->ok, (unsigned long)res->count,
                (unsigned long)res->done, res->errbuf);
        dbg_log(dbgbuf);
        g_job_running = 0;
        if (g_worker != NULL) {
            CloseHandle(g_worker);
            g_worker = NULL;
        }

        if (res->kind == JOB_GET || res->kind == JOB_PUT) {
            ShowWindow(g_progress, SW_HIDE);
            if (res->ok) {
                char line[ENG_ERRLEN + 64], sizebuf[24];
                u64_str(sizebuf, res->done);
                if (res->kind == JOB_GET)
                    sprintf(line, "Downloaded %s bytes.", sizebuf);
                else if (res->warning)
                    sprintf(line, "Uploaded %s bytes (warning: %s).", sizebuf, res->errbuf);
                else
                    sprintf(line, "Uploaded %s bytes.", sizebuf);
                set_status(line);
            } else {
                char line[ENG_ERRLEN + 16];
                sprintf(line, "Error: %s", res->errbuf);
                set_status(line);
            }
            free(res);
            return 0;
        }

        if (res->kind == JOB_SCAN) {
            char line[ENG_ERRLEN + 64];

            if (res->ok)
                sprintf(line, "%s: %lu host(s) answered.",
                        res->warning ? "Scan stopped" : "Scan finished",
                        (unsigned long)res->count);
            else
                sprintf(line, "Error: %s", res->errbuf);
            if (g_scan_wnd != NULL) {
                scan_set_text(line);
                EnableWindow(g_scan_go, TRUE);
                EnableWindow(g_scan_stop, FALSE);
            }
            set_status(line);
            free(res);
            return 0;
        }

        if (res->ok) {
            populate_listview(res->entries, res->count);
            eng_free_entries(res->entries, res->count);
            SetWindowTextA(g_addrbar, res->addr_text);
            if (eng_find_flags(&g_ctx) & ENG_FIND_INCOMPLETE)
                set_status("Ready - warning: the listing may be incomplete (malformed or cut-short server reply).");
            else if (eng_find_flags(&g_ctx) & ENG_FIND_RESYNCED)
                set_status("Ready - note: the server mis-sized its directory entries; the listing was recovered.");
            else
                set_status("Ready.");
        } else {
            char line[ENG_ERRLEN + 16];
            sprintf(line, "Error: %s", res->errbuf);
            set_status(line);
        }
        free(res);
        return 0;
    }


    case WM_DESTROY:
        /* The window is already hidden here, so waiting a moment is invisible.
         * Ask a running job to stop and give it 3 s. Only when the worker has
         * really finished is g_ctx ours to touch; otherwise leave the session
         * alone and let the process exit close the socket. */
        if (g_worker != NULL) {
            g_cancel_flag = 1;
            dbg_log("exit: waiting for the worker");
            if (WaitForSingleObject(g_worker, 3000) == WAIT_OBJECT_0) {
                CloseHandle(g_worker);
                g_worker = NULL;
            } else {
                dbg_log("exit: worker still busy - not closing the session");
            }
        }
        if (g_worker == NULL && g_ctx.sess != NULL) {
            dbg_log("exit: logoff and close");
            eng_disconnect(&g_ctx);
        }
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

/*
 * WinMain - program entry point (GUI subsystem; TCC selects it by detecting
 *           this function, see archive/REGRESSION.md for how that was
 *           checked)
 * Inputs : hInstance = this module's handle, the rest unused so far
 * Outputs: 0 (message loop ran to WM_QUIT) or 1 (setup failed)
 * Clobbers: registers a window class, opens the frame window, initializes
 *          g_ctx
 */
int SMB_STDCALL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                         LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSEXA wc;
    INITCOMMONCONTROLSEX icc;
    HWND frame;
    MSG msg;
    WSADATA wsa;

    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxA(NULL, "Winsock initialisation failed.", WINTITLE, MB_OK | MB_ICONERROR);
        return 1;
    }

    memset(&g_ctx, 0, sizeof g_ctx);
    g_ctx.chunk = DEF_CHUNK;

    icc.dwSize = sizeof icc;
    icc.dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = frame_wndproc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = COLOR_BRUSH(COLOR_BTNFACE);
    wc.lpszClassName = WINCLASS_NAME;
    wc.hIconSm = wc.hIcon;

    if (RegisterClassExA(&wc) == 0) {
        MessageBoxA(NULL, "RegisterClassExA failed.", WINTITLE, MB_OK | MB_ICONERROR);
        return 1;
    }

    frame = CreateWindowExA(0, WINCLASS_NAME, WINTITLE,
                             WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                             CW_USEDEFAULT, CW_USEDEFAULT, 640, 420,
                             NULL, NULL, hInstance, NULL);
    if (frame == NULL) {
        MessageBoxA(NULL, "CreateWindowExA failed.", WINTITLE, MB_OK | MB_ICONERROR);
        return 1;
    }

    dbg_log("WinMain: showing frame");
    ShowWindow(frame, SW_SHOWDEFAULT);
    UpdateWindow(frame);
    dbg_log("WinMain: entering message loop");

    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    WSACleanup();
    return 0;
}
