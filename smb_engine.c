/*
 * smb_engine.c - implementation of smb_engine.h
 *
 * Version : 1.5
 * Author  : VinCBR900
 * Usage   : compile and link with smbftp.c or winsmbftp.c plus libdsm (see
 *           build.cmd); the API and its rules are documented in smb_engine.h
 *
 * Purpose: see smb_engine.h. Every function below is a direct port of a
 *          function that used to live in smbftp.c 0.5 - same algorithm, same
 *          message wording - with printf/fprintf replaced by a return value
 *          plus an error buffer, and the connect-mode progress replaced by a
 *          callback. See smb_engine.h's History note for how this was
 *          checked against the original.
 *
 * History
 *   1.5  2026-10-23  eng_disconnect() logs off whenever logged in.
 *   1.4  2026-10-23  eng_disconnect(). Details in smb_engine.h's History note.
 *   1.3  2026-10-23  eng_find_flags(); eng_list_dir() reports a listing libdsm
 *                    flagged incomplete as an error; put-verification text no
 *                    longer names the retired libdsm-write-bytecount.patch.
 *                    Details in smb_engine.h's History note.
 *   1.2  2026-10-22  Range scan for WinSMBFTP's Scan window: eng_default_range(),
 *                    eng_parse_range(), eng_probe_range() (concurrent TCP
 *                    pre-probe); eng_scan_host() sets hit->status;
 *                    eng_probe_tcp() watches the exception set too; eng_scan_host()
 *                    sends its own bounded SMB1 NEGOTIATE before involving
 *                    libdsm. Details in smb_engine.h's History note.
 *   1.1  2026-10-20  Added eng_probe_tcp()/eng_scan_host() for WinSMBFTP's
 *                    Scan button (see smb_engine.h's History note).
 *   1.0  2026-10-13  Initial extraction from smbftp.c 0.5.
 */

#include "smb_engine.h"

/* ------------------------------------------------------------------------ */
/* String / number utilities                                                */
/* ------------------------------------------------------------------------ */

/*
 * str_copy - bounded string copy that reports truncation
 * Inputs : dst/dsz = destination buffer and its size, src = NUL-terminated
 * Outputs: 0 on success, -1 if src did not fit (dst is then left empty)
 * Clobbers: dst
 */
int str_copy(char *dst, size_t dsz, const char *src)
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
int ci_cmp(const char *a, const char *b)
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
char *u64_str(char *buf, uint64_t v)
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
char *ft_str(uint64_t ft, char *buf)
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
const char *base_name(const char *path)
{
    const char *p, *b = path;

    for (p = path; *p; p++)
        if (*p == '\\' || *p == '/')
            b = p + 1;
    return b;
}

/*
 * parse_ipv4 - strict dotted-quad parser (no short forms, no hex/octal)
 * Inputs : text = e.g. "192.168.4.20"
 * Outputs: 1 and *ip_net (network byte order) on success, 0 if invalid
 * Clobbers: *ip_net only on success
 */
int parse_ipv4(const char *text, uint32_t *ip_net)
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

/*
 * estrdup - malloc'd copy of a NUL-terminated string. Written instead of
 *           calling the standard strdup(), which Windows C runtimes do not
 *           reliably export (msvcrt.dll traditionally has only _strdup) -
 *           same reasoning as libdsm's bundled strlcpy/strndup compat.
 * Inputs : s = NUL-terminated string to copy
 * Outputs: malloc'd copy, or NULL if out of memory
 * Clobbers: none
 */
static char *estrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);

    if (p != NULL)
        memcpy(p, s, n);
    return p;
}

/* ------------------------------------------------------------------------ */
/* Error text                                                               */
/* ------------------------------------------------------------------------ */

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
 * eng_strerror - format an error for a libdsm int return code (see header)
 * Inputs : what, rc, s; buf/bufsz = output
 * Outputs: buf filled, same wording smbftp 0.5's report_rc() printed, minus
 *          the "Error: " prefix and trailing newline
 * Clobbers: buf
 */
void eng_strerror(const char *what, int rc, smb_session *s, char *buf, size_t bufsz)
{
    uint32_t st;

    switch (rc) {
    case DSM_ERROR_NT:
        st = smb_session_get_nt_status(s);
        sprintf(buf, "%.80s: %.100s (NT status 0x%08lX)", what, nt_text(st), (unsigned long)st);
        break;
    case DSM_ERROR_NETWORK:
        sprintf(buf, "%.80s: network error or unexpected server reply", what);
        break;
    case DSM_ERROR_CHARSET:
        sprintf(buf, "%.80s: character set conversion failed", what);
        break;
    default:
        sprintf(buf, "%.80s: failed (code %d)", what, rc);
        break;
    }
    (void)bufsz; /* every branch above fits ENG_ERRLEN; %.Ns guards what */
}

/*
 * eng_strerror_fail - format an error for a libdsm call that returns NULL or
 *                     -1 and gives no code (see header)
 * Inputs : what, s; buf/bufsz = output
 * Outputs: buf filled, same wording smbftp 0.5's report_fail() printed
 * Clobbers: buf
 */
void eng_strerror_fail(const char *what, smb_session *s, char *buf, size_t bufsz)
{
    uint32_t st = smb_session_get_nt_status(s);

    if (st != 0)
        sprintf(buf, "%.80s: %.100s (NT status 0x%08lX)", what, nt_text(st), (unsigned long)st);
    else
        sprintf(buf, "%.80s", what);
    (void)bufsz;
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
int resolve_path(const Ctx *c, const char *arg, char *out, size_t outsz)
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
int remote_stat(Ctx *c, const char *path, int *isdir, uint64_t *size)
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

/* ------------------------------------------------------------------------ */
/* Session: connect and log in                                              */
/* ------------------------------------------------------------------------ */

smb_session *eng_connect(uint32_t ip, const char *ip_text, int mode,
                          const char *nbname, eng_notify_cb on_attempt, void *user,
                          char *errbuf, size_t errsz)
{
    static const int order_auto[2] = { SMB_TRANSPORT_TCP, SMB_TRANSPORT_NBT };
    char line[ENG_ERRLEN];
    int attempt[2];
    int natt, i, rc;
    smb_session *s;
    const char *name, *tname;

    if (nbname != NULL && (strlen(nbname) == 0 || strlen(nbname) > NBNAME_MAX)) {
        sprintf(errbuf, "NetBIOS name must be 1..%d characters", NBNAME_MAX);
        return NULL;
    }

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
        if (on_attempt != NULL) {
            sprintf(line, "Connecting to %.48s using SMB1 over %s...", ip_text, tname);
            on_attempt(line, 0, user);
        }
        s = smb_session_new();
        if (s == NULL) {
            str_copy(errbuf, errsz, "could not allocate SMB session");
            return NULL;
        }
        rc = smb_session_connect(s, name, ip, attempt[i]);
        if (rc == DSM_SUCCESS)
            return s;
        eng_strerror("negotiation failed", rc, s, errbuf, errsz);
        if (on_attempt != NULL)
            on_attempt(errbuf, 1, user);
        smb_session_destroy(s);
    }
    return NULL;
}

int eng_login(Ctx *c, const char *domain, const char *user, const char *pass,
              int *out_guest, char *errbuf, size_t errsz)
{
    int rc;

    if (strlen(user) >= SMB_CREDS_MAXLEN || strlen(pass) >= SMB_CREDS_MAXLEN ||
        strlen(domain) >= SMB_CREDS_MAXLEN) {
        sprintf(errbuf, "user, password and domain are limited to %d characters",
                SMB_CREDS_MAXLEN - 1);
        return -1;
    }
    smb_session_set_creds(c->sess, domain, user, pass);
    rc = smb_session_login(c->sess);
    if (rc != DSM_SUCCESS) {
        eng_strerror("login failed", rc, c->sess, errbuf, errsz);
        return -1;
    }
    if (out_guest != NULL)
        *out_guest = smb_session_is_guest(c->sess);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Shares                                                                   */
/* ------------------------------------------------------------------------ */

int eng_list_shares(Ctx *c, EngShareList *out, char *errbuf, size_t errsz)
{
    smb_share_list list = NULL;
    size_t count = 0, i;
    const char *name;
    char **names;
    int rc;

    out->names = NULL;
    out->count = 0;

    rc = smb_share_get_list(c->sess, &list, &count);
    if (rc != DSM_SUCCESS || list == NULL) {
        if (rc == DSM_SUCCESS)
            rc = DSM_ERROR_GENERIC;
        eng_strerror("cannot list shares", rc, c->sess, errbuf, errsz);
        return -1;
    }

    if (count == 0) {
        smb_share_list_destroy(list);
        return 0;
    }
    names = (char **)malloc(count * sizeof *names);
    if (names == NULL) {
        smb_share_list_destroy(list);
        str_copy(errbuf, errsz, "out of memory");
        return -1;
    }
    out->count = 0;
    for (i = 0; i < count; i++) {       /* a NULL name (shouldn't happen) is
                                          * skipped, same as smbftp 0.5's
                                          * "if (name != NULL)" print guard */
        name = smb_share_list_at(list, i);
        if (name == NULL)
            continue;
        names[out->count] = estrdup(name);
        if (names[out->count] == NULL) {
            smb_share_list_destroy(list);
            out->names = names;         /* let eng_free_shares clean up what */
            eng_free_shares(out);       /* was allocated so far              */
            str_copy(errbuf, errsz, "out of memory");
            return -1;
        }
        out->count++;
    }
    smb_share_list_destroy(list);
    out->names = names;
    return 0;
}

void eng_free_shares(EngShareList *list)
{
    size_t i;

    if (list == NULL || list->names == NULL)
        return;
    for (i = 0; i < list->count; i++)
        free(list->names[i]);
    free(list->names);
    list->names = NULL;
    list->count = 0;
}

int eng_use_share(Ctx *c, const char *share, char *errbuf, size_t errsz)
{
    smb_tid tid = 0;
    int rc;

    if (strlen(share) >= SHARE_LEN) {
        str_copy(errbuf, errsz, "share name too long");
        return -1;
    }
    rc = smb_tree_connect(c->sess, share, &tid);
    if (rc != DSM_SUCCESS) {
        eng_strerror("cannot connect to share", rc, c->sess, errbuf, errsz);
        return -1;
    }
    c->tid = tid;
    c->have_share = 1;
    str_copy(c->share, sizeof c->share, share);
    c->cwd[0] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Directory listing                                                        */
/* ------------------------------------------------------------------------ */

/*
 * cmp_entries - qsort comparator: directories first, then name (ASCII,
 *               case-insensitive). Same ordering smbftp 0.5's "ls" used.
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

void eng_disconnect(Ctx *c)
{
    if (c->sess != NULL) {
        if (smb_session_is_guest(c->sess) >= 0)     /* >= 0: logged in */
            smb_session_logoff(c->sess);    /* send only; see header comment */
        smb_session_destroy(c->sess);       /* closes the connection */
    }
    c->sess = NULL;
    c->tid = 0;
    c->have_share = 0;
    c->share[0] = '\0';
    c->cwd[0] = '\0';
}

#ifdef SMB_FIND_INCOMPLETE
unsigned long eng_find_flags(const Ctx *c)
{
    return (unsigned long)smb_session_get_find_flags(c->sess);
}
#else
unsigned long eng_find_flags(const Ctx *c)
{
    (void)c;
    return 0;
}
#endif

int eng_list_dir(Ctx *c, const char *arg, EngEntry **out, size_t *count,
                  char *errbuf, size_t errsz)
{
    char path[PATH_LEN], pat[PATH_LEN];
    smb_stat_list list;
    smb_stat *arr, e;
    EngEntry *entries;
    size_t n, i, k, plen;
    const char *name;
    int isdir, rc;

    *out = NULL;
    *count = 0;
    if (arg == NULL || arg[0] == '\0')
        arg = ".";

    if (resolve_path(c, arg, path, sizeof path) != 0) {
        str_copy(errbuf, errsz, "path too long");
        return -1;
    }

    if (strpbrk(arg, "*?") != NULL) {
        if (str_copy(pat, sizeof pat, path) != 0) {
            str_copy(errbuf, errsz, "path too long");
            return -1;
        }
    } else {
        rc = remote_stat(c, path, &isdir, NULL);
        if (rc != DSM_SUCCESS) {
            eng_strerror("cannot access remote path", rc, c->sess, errbuf, errsz);
            return -1;
        }
        plen = strlen(path);
        if (isdir) {
            if (plen + 3 > sizeof pat) {
                str_copy(errbuf, errsz, "path too long");
                return -1;
            }
            memcpy(pat, path, plen);
            pat[plen] = '\\';
            pat[plen + 1] = '*';
            pat[plen + 2] = '\0';
        } else if (str_copy(pat, sizeof pat, path) != 0) {
            str_copy(errbuf, errsz, "path too long");
            return -1;
        }
    }

    list = smb_find(c->sess, c->tid, pat);
    if (list == NULL) {
        if (smb_session_get_nt_status(c->sess) != 0) {
            eng_strerror_fail("listing failed", c->sess, errbuf, errsz);
            return -1;
        }
        if (eng_find_flags(c) & ENG_FIND_INCOMPLETE) {
            str_copy(errbuf, errsz, "listing failed: malformed or cut-short server reply");
            return -1;
        }
        return 0;                       /* "No entries.", not an error */
    }

    n = smb_stat_list_count(list);
    arr = (smb_stat *)malloc((n ? n : 1) * sizeof *arr);
    if (arr == NULL) {
        smb_stat_list_destroy(list);
        str_copy(errbuf, errsz, "out of memory");
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

    if (k == 0) {
        free(arr);
        smb_stat_list_destroy(list);
        return 0;                       /* "No entries.", not an error */
    }

    entries = (EngEntry *)malloc(k * sizeof *entries);
    if (entries == NULL) {
        free(arr);
        smb_stat_list_destroy(list);
        str_copy(errbuf, errsz, "out of memory");
        return -1;
    }
    for (i = 0; i < k; i++) {
        e = arr[i];
        name = smb_stat_name(e);
        entries[i].name  = estrdup(name != NULL ? name : "");
        entries[i].isdir = smb_stat_get(e, SMB_STAT_ISDIR) != 0;
        entries[i].size  = smb_stat_get(e, SMB_STAT_SIZE);
        entries[i].wtime = smb_stat_get(e, SMB_STAT_WTIME);
        if (entries[i].name == NULL) {
            free(arr);
            smb_stat_list_destroy(list);
            eng_free_entries(entries, i);   /* frees names 0..i-1, and the array */
            str_copy(errbuf, errsz, "out of memory");
            return -1;
        }
    }
    free(arr);
    smb_stat_list_destroy(list);
    *out = entries;
    *count = k;
    return 0;
}

void eng_free_entries(EngEntry *entries, size_t count)
{
    size_t i;

    if (entries == NULL)
        return;
    for (i = 0; i < count; i++)
        free(entries[i].name);
    free(entries);
}

int eng_cd(Ctx *c, const char *arg, char *errbuf, size_t errsz)
{
    char path[PATH_LEN];
    int isdir, rc;

    if (resolve_path(c, arg, path, sizeof path) != 0) {
        str_copy(errbuf, errsz, "path too long");
        return -1;
    }
    rc = remote_stat(c, path, &isdir, NULL);
    if (rc != DSM_SUCCESS) {
        eng_strerror("cannot access remote path", rc, c->sess, errbuf, errsz);
        return -1;
    }
    if (!isdir) {
        str_copy(errbuf, errsz, "not a directory");
        return -1;
    }
    str_copy(c->cwd, sizeof c->cwd, path);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Transfers                                                                 */
/* ------------------------------------------------------------------------ */

int eng_get_file(Ctx *c, const char *remote_arg, const char *local_path,
                  eng_xfer_cb cb, void *user, volatile int *cancel,
                  uint64_t *out_done, char *errbuf, size_t errsz)
{
    char path[PATH_LEN];
    unsigned char *buf = NULL;
    FILE *out = NULL;
    smb_fd fd = 0;
    smb_stat st;
    uint64_t size, done = 0, shown = 0;
    ssize_t n;
    int rc, ret = -1;

    *out_done = 0;
    if (resolve_path(c, remote_arg, path, sizeof path) != 0 || path[0] == '\0') {
        str_copy(errbuf, errsz, "invalid remote path");
        return -1;
    }

    rc = smb_fopen(c->sess, c->tid, path, SMB_MOD_RO, &fd);
    if (rc != DSM_SUCCESS) {
        eng_strerror("cannot open remote file", rc, c->sess, errbuf, errsz);
        return -1;
    }
    st = smb_stat_fd(c->sess, fd);
    if (st == NULL) {
        str_copy(errbuf, errsz, "cannot get remote file information");
        goto done;
    }
    if (smb_stat_get(st, SMB_STAT_ISDIR)) {
        str_copy(errbuf, errsz, "remote path is a directory");
        goto done;
    }
    size = smb_stat_get(st, SMB_STAT_SIZE);

    buf = (unsigned char *)malloc(c->chunk);
    if (buf == NULL) {
        str_copy(errbuf, errsz, "out of memory");
        goto done;
    }
    out = fopen(local_path, "wb");
    if (out == NULL) {
        sprintf(errbuf, "cannot create local file '%.100s'", local_path);
        goto done;
    }

    while (done < size) {
        if (cancel != NULL && *cancel) {
            str_copy(errbuf, errsz, "cancelled");
            ret = -2;
            goto done;
        }
        n = smb_fread(c->sess, fd, buf, c->chunk);
        if (n < 0) {
            str_copy(errbuf, errsz, "read failed (partial local file left)");
            ret = -2;
            goto done;
        }
        if (n == 0)
            break;
        if (fwrite(buf, 1, (size_t)n, out) != (size_t)n) {
            sprintf(errbuf, "write to '%.100s' failed (disk full?)", local_path);
            ret = -2;
            goto done;
        }
        done += (uint64_t)n;
        if (cb != NULL && done - shown >= PROGRESS_STEP) {
            cb(done, size, user);
            shown = done;
        }
    }
    if (fclose(out) != 0) {
        out = NULL;
        sprintf(errbuf, "closing '%.100s' failed", local_path);
        ret = -2;
        goto done;
    }
    out = NULL;
    if (done != size) {
        sprintf(errbuf, "server ended the file early (%lu of %lu bytes)",
                (unsigned long)done, (unsigned long)size);
        ret = -2;
        goto done;
    }
    *out_done = done;
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
 * Outputs: 0 if the remote size equals sent; 1 if the size cannot be read
 *          back (errbuf gets a non-fatal warning); -1 if the sizes differ
 *          (errbuf gets the error)
 * Clobbers: errbuf on 1 or -1; opens and closes one remote handle
 */
static int verify_upload(Ctx *c, const char *full, uint64_t sent, char *errbuf, size_t errsz)
{
    char a[24], b[24];
    uint64_t rsize = 0;
    int isdir = 0;

    if (remote_stat(c, full, &isdir, &rsize) != DSM_SUCCESS) {
        str_copy(errbuf, errsz, "upload not verified: cannot read back the remote size");
        return 1;
    }
    if (rsize == sent)
        return 0;
    sprintf(errbuf, "upload failed verification: sent %s bytes, server holds %s "
                    "(truncated remote file left). Likely cause: unpatched libdsm "
                    "write byte count; see README.md, \"libdsm write byte count\"",
                    u64_str(a, sent), u64_str(b, rsize));
    (void)errsz;
    return -1;
}

int eng_put_file(Ctx *c, const char *local_path, const char *remote_arg,
                  eng_xfer_cb cb, void *user, volatile int *cancel,
                  uint64_t *out_done, char *errbuf, size_t errsz)
{
    char path[PATH_LEN], full[PATH_LEN];
    const char *lname;
    unsigned char *buf = NULL;
    FILE *in = NULL;
    smb_fd fd = 0;
    uint64_t total = 0, done = 0, shown = 0;
    size_t got, off, plen;
    ssize_t w;
    long flen;
    int rc, isdir, ret = -1, vr;

    *out_done = 0;
    lname = base_name(local_path);
    if (*lname == '\0') {
        str_copy(errbuf, errsz, "invalid local file name");
        return -1;
    }
    if (resolve_path(c, remote_arg, path, sizeof path) != 0) {
        str_copy(errbuf, errsz, "remote path too long");
        return -1;
    }

    /* an existing remote directory (or the share root) as target: append name */
    if (remote_stat(c, path, &isdir, NULL) != DSM_SUCCESS)
        isdir = 0;                      /* does not exist yet: plain new file */
    if (isdir) {
        plen = strlen(path);
        if (plen + 1 + strlen(lname) + 1 > sizeof full) {
            str_copy(errbuf, errsz, "remote path too long");
            return -1;
        }
        memcpy(full, path, plen);
        full[plen] = '\\';
        strcpy(full + plen + 1, lname);
    } else if (str_copy(full, sizeof full, path) != 0) {
        str_copy(errbuf, errsz, "remote path too long");
        return -1;
    }

    in = fopen(local_path, "rb");
    if (in == NULL) {
        sprintf(errbuf, "cannot open local file '%.100s'", local_path);
        return -1;
    }
    if (fseek(in, 0, SEEK_END) == 0) {
        flen = ftell(in);
        if (flen > 0)
            total = (uint64_t)flen;
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        sprintf(errbuf, "cannot read local file '%.100s'", local_path);
        goto done;
    }
    buf = (unsigned char *)malloc(c->chunk);
    if (buf == NULL) {
        str_copy(errbuf, errsz, "out of memory");
        goto done;
    }

    rc = smb_fopen(c->sess, c->tid, full, SMB_MOD_RW, &fd);
    if (rc != DSM_SUCCESS) {
        eng_strerror("cannot create remote file", rc, c->sess, errbuf, errsz);
        goto done;
    }

    for (;;) {
        if (cancel != NULL && *cancel) {
            str_copy(errbuf, errsz, "cancelled");
            ret = -2;
            goto done;
        }
        got = fread(buf, 1, c->chunk, in);
        if (got == 0) {
            if (ferror(in)) {
                sprintf(errbuf, "read from '%.100s' failed", local_path);
                ret = -2;
                goto done;
            }
            break;
        }
        off = 0;
        while (off < got) {
            w = smb_fwrite(c->sess, fd, buf + off, got - off);
            if (w <= 0) {
                eng_strerror_fail("write failed (partial remote file left)", c->sess, errbuf, errsz);
                ret = -2;
                goto done;
            }
            off += (size_t)w;
        }
        done += (uint64_t)got;
        if (cb != NULL && done - shown >= PROGRESS_STEP) {
            cb(done, total, user);
            shown = done;
        }
    }
    smb_fclose(c->sess, fd);            /* close before the read-back check */
    fd = 0;
    vr = verify_upload(c, full, done, errbuf, errsz);
    if (vr < 0) {
        ret = -2;                       /* verify_upload's own message already
                                          * assumes a blank line first, same
                                          * as smbftp 0.5 */
        goto done;
    }
    *out_done = done;
    ret = vr;                           /* 0 clean, 1 success-with-warning */

done:
    if (fd != 0)
        smb_fclose(c->sess, fd);
    if (in != NULL)
        fclose(in);
    free(buf);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Scan: find SMB1 servers and their shares                                 */
/* ------------------------------------------------------------------------ */

static unsigned long eng_now_ms(void);      /* defined further down */

/*
 * eng_tcp_open - connect to ip:port, waiting at most timeout_ms
 * Inputs : ip (network byte order), port (host byte order), timeout_ms
 * Outputs: a connected socket (blocking mode), or SOCK_BAD if the connection
 *          was refused, timed out or any local call failed
 * Clobbers: opens one socket; the caller closes it
 */
static sock_t eng_tcp_open(uint32_t ip, unsigned short port, unsigned long timeout_ms)
{
    sock_t s;
    struct sockaddr_in sa;
    fd_set wr, ex;
    struct timeval tv;
    int rc, err;
#ifdef _WIN32
    u_long on = 1, off = 0;
    int elen = sizeof err;
#else
    int fl;
    socklen_t elen = sizeof err;
#endif

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == SOCK_BAD)
        return SOCK_BAD;
#ifdef _WIN32
    ioctlsocket(s, FIONBIO, &on);
#else
    fl = fcntl(s, F_GETFL, 0);
    if (fl >= 0)
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;

    rc = connect(s, (struct sockaddr *)&sa, sizeof sa);
    if (rc != 0) {
        FD_ZERO(&wr);
        FD_SET(s, &wr);
        FD_ZERO(&ex);
        FD_SET(s, &ex);           /* Winsock reports a refused connect here */
        tv.tv_sec = (long)(timeout_ms / 1000);
        tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
        rc = select((int)s + 1, NULL, &wr, &ex, &tv);
        if (rc <= 0) {
            sock_close(s);
            return SOCK_BAD;      /* timed out, or select() itself failed */
        }
        err = 1;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) != 0)
            err = 1;
        if (err != 0 || !FD_ISSET(s, &wr)) {
            sock_close(s);
            return SOCK_BAD;
        }
    }
#ifdef _WIN32
    ioctlsocket(s, FIONBIO, &off);
#else
    if (fl >= 0)
        fcntl(s, F_SETFL, fl);
#endif
    return s;
}

int eng_probe_tcp(uint32_t ip, unsigned short port, unsigned long timeout_ms)
{
    sock_t s = eng_tcp_open(ip, port, timeout_ms);

    if (s == SOCK_BAD)
        return 0;
    sock_close(s);
    return 1;
}

/* SMB1 NEGOTIATE offering only "NT LM 0.12", inside a NetBIOS session message
 * (same bytes smbftp.c's -S scanner sends) */
static const unsigned char eng_neg_req[] = {
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
typedef char eng_neg_req_size_check[(sizeof eng_neg_req == 51) ? 1 : -1];

/*
 * eng_nb_encode - first-level NetBIOS name encoding (RFC 1001)
 * Inputs : name = up to 15 characters, suffix = 16th byte, out = 34 bytes
 * Outputs: out = length byte 0x20, 32 encoded characters, terminating 0
 * Clobbers: out
 */
static void eng_nb_encode(const char *name, int suffix, unsigned char *out)
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
 * eng_smb1_reply - classify a reply to eng_neg_req
 * Inputs : b/n = bytes received so far (NetBIOS header included)
 * Outputs: 1 = SMB1 NEGOTIATE accepted with dialect NT LM 0.12,
 *          0 = anything else (SMB2 reply, error status, no common dialect),
 *          -1 = not enough bytes yet
 * Clobbers: none
 */
static int eng_smb1_reply(const unsigned char *b, int n)
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

/*
 * eng_recv_some - wait (bounded) for data on a connected socket, read it
 * Inputs : s = connected socket, buf/max = destination, start/timeout_ms =
 *          the overall budget (eng_now_ms() at its start, and its length)
 * Outputs: bytes read (> 0), or 0 if the budget ran out, the peer closed the
 *          connection or an error occurred
 * Clobbers: buf
 */
static int eng_recv_some(sock_t s, unsigned char *buf, int max, unsigned long start,
                         unsigned long timeout_ms)
{
    fd_set rd;
    struct timeval tv;
    unsigned long used = eng_now_ms() - start, left;
    int rc;

    if (used >= timeout_ms)
        return 0;
    left = timeout_ms - used;
    FD_ZERO(&rd);
    FD_SET(s, &rd);
    tv.tv_sec = (long)(left / 1000);
    tv.tv_usec = (long)((left % 1000) * 1000);
    rc = select((int)s + 1, &rd, NULL, NULL, &tv);
    if (rc <= 0 || !FD_ISSET(s, &rd))
        return 0;
    rc = (int)recv(s, (char *)buf, max, 0);
    return (rc > 0) ? rc : 0;
}

/*
 * eng_smb1_check - does ip:port answer an SMB1 NEGOTIATE, within a bound?
 *                  tcp/445 gets the NEGOTIATE directly; tcp/139 first gets a
 *                  NetBIOS session request (called name *SMBSERVER), as
 *                  smbftp -S does
 * Inputs : ip (network byte order), port = 445 or 139, timeout_ms = limit for
 *          the connect, and again for the whole exchange after it
 * Outputs: 2 = SMB1 answered, 1 = connected but no SMB1 answer (SMB2 only,
 *          not SMB, silent, or closed on us), 0 = could not connect
 * Clobbers: opens and closes one socket
 */
static int eng_smb1_check(uint32_t ip, unsigned short port, unsigned long timeout_ms)
{
    sock_t s;
    unsigned char pkt[72], rx[64];
    unsigned long start;
    int got, n, v, plen, result = 1;

    s = eng_tcp_open(ip, port, timeout_ms);
    if (s == SOCK_BAD)
        return 0;
    start = eng_now_ms();

    if (port == 139) {
        pkt[0] = 0x81;
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 68;
        eng_nb_encode("*SMBSERVER", 0x20, pkt + 4);
        eng_nb_encode("SMBFTP", 0x00, pkt + 38);
        if (send(s, (const char *)pkt, 72, MSG_NOSIGNAL) != 72)
            goto done;
        for (got = 0; got < 4; got += n) {
            n = eng_recv_some(s, rx + got, 4 - got, start, timeout_ms);
            if (n <= 0)
                goto done;
        }
        if (rx[0] != 0x82)                  /* not a positive session response */
            goto done;
        /* A standard response is just these 4 bytes (length 0). Consume the
         * length the header declares anyway: impacket's test server, for one,
         * appends 68 bytes of echoed names, which would otherwise be read
         * as the start of the NEGOTIATE reply. */
        for (plen = ((rx[1] & 1) << 16) | (rx[2] << 8) | rx[3]; plen > 0; plen -= n) {
            n = eng_recv_some(s, rx, plen > (int)sizeof rx ? (int)sizeof rx : plen,
                              start, timeout_ms);
            if (n <= 0)
                goto done;
        }
    }
    if (send(s, (const char *)eng_neg_req, (int)sizeof eng_neg_req, MSG_NOSIGNAL) !=
        (int)sizeof eng_neg_req)
        goto done;
    for (got = 0; got < (int)sizeof rx; ) {
        n = eng_recv_some(s, rx + got, (int)sizeof rx - got, start, timeout_ms);
        if (n <= 0)
            goto done;
        got += n;
        v = eng_smb1_reply(rx, got);
        if (v > 0) {
            result = 2;
            goto done;
        }
        if (v == 0)
            goto done;
    }
done:
    sock_close(s);
    return result;
}

int eng_scan_host(uint32_t ip, const char *ip_text, unsigned long timeout_ms,
                   EngScanHit *hit)
{
    Ctx tmp;
    char errbuf[ENG_ERRLEN];
    EngShareList list;
    int r445, r139 = 0;

    memset(hit, 0, sizeof *hit);
    str_copy(hit->ip_text, sizeof hit->ip_text, ip_text);

    /* Our own bounded NEGOTIATE first: libdsm alone can wait about a minute
     * on a host that accepts TCP but never answers (measured), and a scan
     * must not stall on one such host. Only a host that answers in SMB1
     * gets a libdsm session, over the transport that answered. */
    r445 = eng_smb1_check(ip, 445, timeout_ms);
    if (r445 != 2)
        r139 = eng_smb1_check(ip, 139, timeout_ms);
    if (r445 == 0 && r139 == 0)
        return 0;

    hit->status = ENG_SCAN_PORT_ONLY;
    if (r445 != 2 && r139 != 2)
        return 1;                 /* a port answered, but not in SMB1 */

    memset(&tmp, 0, sizeof tmp);
    tmp.sess = eng_connect(ip, ip_text, (r445 == 2) ? 1 : 2, NULL, NULL, NULL,
                           errbuf, sizeof errbuf);
    if (tmp.sess == NULL)
        return 1;                 /* SMB1 answered our probe but libdsm could
                                    * not set up a session - still "found" */

    hit->status = ENG_SCAN_SMB1_NOGUEST;
    if (eng_login(&tmp, "WORKGROUP", "guest", "", NULL, errbuf, sizeof errbuf) == 0 &&
        eng_list_shares(&tmp, &list, errbuf, sizeof errbuf) == 0) {
        hit->shares = list.names;
        hit->share_count = (int)list.count;
        hit->status = ENG_SCAN_SMB1_SHARES;
    }
    smb_session_destroy(tmp.sess);
    return 1;
}

void eng_free_scan_hit(EngScanHit *hit)
{
    EngShareList list;

    if (hit == NULL || hit->shares == NULL)
        return;
    list.names = hit->shares;
    list.count = (size_t)hit->share_count;
    eng_free_shares(&list);
    hit->shares = NULL;
    hit->share_count = 0;
}

/* ------------------------------------------------------------------------ */
/* Scan: address range, local networks, concurrent TCP pre-probe            */
/* ------------------------------------------------------------------------ */

#define ENG_PROBE_BATCH   128                 /* sockets in one select()    */
#define ENG_PROBE_HOSTS   (ENG_PROBE_BATCH / 2)   /* hosts per batch (2 ports) */

/*
 * eng_now_ms - millisecond clock for timeouts
 * Inputs : none
 * Outputs: milliseconds from an arbitrary start; compare with unsigned
 *          subtraction (the value wraps)
 * Clobbers: none
 */
static unsigned long eng_now_ms(void)
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
 * eng_prefix_of_mask - prefix length of a netmask
 * Inputs : mask = host byte order
 * Outputs: 0..32, or -1 if the mask is not contiguous
 * Clobbers: none
 */
static int eng_prefix_of_mask(uint32_t mask)
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
 * eng_local_addrs - list this machine's IPv4 addresses and netmasks
 * Inputs : out = array, max = its size
 * Outputs: number of entries filled (0 if the adapters cannot be read); host
 *          byte order. Includes loopback and link-local; callers filter
 * Clobbers: out
 */
#ifdef _WIN32
static int eng_local_addrs(LocalAddr *out, int max)
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
static int eng_local_addrs(LocalAddr *out, int max)
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

int eng_default_range(char *buf, size_t bufsz)
{
    LocalAddr la[SCAN_MAX_LOCAL];
    int i, nl, prefix;
    uint32_t net, mask;

    if (buf == NULL || bufsz == 0)
        return 0;
    buf[0] = '\0';
    nl = eng_local_addrs(la, SCAN_MAX_LOCAL);
    for (i = 0; i < nl; i++) {
        if (la[i].ip == 0 || (la[i].ip >> 24) == 127 || (la[i].ip >> 16) == 0xA9FEU)
            continue;                       /* unset, loopback, link-local */
        prefix = eng_prefix_of_mask(la[i].mask);
        if (prefix < 0 || prefix > 30)
            continue;                       /* odd mask, or a /31 or /32 link */
        if (prefix < SCAN_AUTO_PREFIX)
            prefix = 24;
        mask = (uint32_t)(0xFFFFFFFFU << (32 - prefix));
        net = la[i].ip & mask;
        {
            char tmp[24];

            sprintf(tmp, "%u.%u.%u.%u/%d", (unsigned)(net >> 24), (unsigned)((net >> 16) & 255U),
                    (unsigned)((net >> 8) & 255U), (unsigned)(net & 255U), prefix);
            if (str_copy(buf, bufsz, tmp) != 0)
                return 0;
        }
        return 1;
    }
    return 0;
}

int eng_parse_range(const char *text, uint32_t *first, uint32_t *last)
{
    char buf[40], addr[20], *end;
    const char *slash;
    size_t n, len;
    unsigned long prefix = 32;
    uint32_t ip, mask, net, bcast;

    if (text == NULL)
        return -1;
    while (*text == ' ' || *text == '\t')
        text++;
    len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                       text[len - 1] == '\r' || text[len - 1] == '\n'))
        len--;
    if (len == 0 || len >= sizeof buf)
        return -1;
    memcpy(buf, text, len);
    buf[len] = '\0';

    slash = strchr(buf, '/');
    n = (slash != NULL) ? (size_t)(slash - buf) : len;
    if (n == 0 || n >= sizeof addr)
        return -1;
    memcpy(addr, buf, n);
    addr[n] = '\0';
    if (!parse_ipv4(addr, &ip))
        return -1;
    if (slash != NULL) {
        if (slash[1] == '\0')
            return -1;
        prefix = strtoul(slash + 1, &end, 10);
        if (*end != '\0' || prefix < SCAN_MIN_PREFIX || prefix > 32)
            return -1;
    }
    ip = ntohl(ip);
    mask = (prefix == 0) ? 0 : (uint32_t)(0xFFFFFFFFU << (32 - prefix));
    net = ip & mask;
    bcast = net | (uint32_t)~mask;
    *first = (prefix <= 30) ? net + 1 : net;
    *last = (prefix <= 30) ? bcast - 1 : bcast;
    return 0;
}

/*
 * eng_probe_batch - connect to up to ENG_PROBE_BATCH (address, port) pairs at
 *                   once and note which accept
 * Inputs : ips = addresses (network byte order), ports = host byte order, n =
 *          number of pairs (<= ENG_PROBE_BATCH), timeout_ms = longest wait
 *          for the whole batch
 * Outputs: open_out[i] = 1 if pair i accepted a connection, else 0
 * Clobbers: open_out[0..n-1]; opens and closes up to n sockets
 */
static void eng_probe_batch(const uint32_t *ips, const unsigned short *ports, int n,
                            unsigned long timeout_ms, unsigned char *open_out)
{
    sock_t sk[ENG_PROBE_BATCH];
    struct sockaddr_in sa;
    fd_set wr, ex;
    struct timeval tv;
    unsigned long start, elapsed;
    sock_len_t el;
    int i, rc, err, pending = 0;
#ifdef _WIN32
    u_long on = 1;
#else
    int fl, maxfd;
#endif

    for (i = 0; i < n; i++) {
        open_out[i] = 0;
        sk[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sk[i] == SOCK_BAD)
            continue;
#ifdef _WIN32
        ioctlsocket(sk[i], FIONBIO, &on);
#else
        fl = fcntl(sk[i], F_GETFL, 0);
        if (fl >= 0)
            fcntl(sk[i], F_SETFL, fl | O_NONBLOCK);
#endif
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(ports[i]);
        sa.sin_addr.s_addr = ips[i];
        rc = connect(sk[i], (struct sockaddr *)&sa, sizeof sa);
        if (rc == 0) {                              /* connected at once */
            open_out[i] = 1;
            sock_close(sk[i]);
            sk[i] = SOCK_BAD;
            continue;
        }
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
        if (errno != EINPROGRESS) {
#endif
            sock_close(sk[i]);                      /* failed outright */
            sk[i] = SOCK_BAD;
            continue;
        }
        pending++;
    }

    start = eng_now_ms();
    while (pending > 0) {
        elapsed = eng_now_ms() - start;
        if (elapsed >= timeout_ms)
            break;
        FD_ZERO(&wr);
        FD_ZERO(&ex);
#ifndef _WIN32
        maxfd = -1;
#endif
        for (i = 0; i < n; i++) {
            if (sk[i] == SOCK_BAD)
                continue;
            FD_SET(sk[i], &wr);
            FD_SET(sk[i], &ex);                     /* Winsock: refused connect */
#ifndef _WIN32
            if ((int)sk[i] > maxfd)
                maxfd = (int)sk[i];
#endif
        }
        elapsed = timeout_ms - elapsed;
        tv.tv_sec = (long)(elapsed / 1000);
        tv.tv_usec = (long)((elapsed % 1000) * 1000);
#ifdef _WIN32
        rc = select(0, NULL, &wr, &ex, &tv);
#else
        rc = select(maxfd + 1, NULL, &wr, &ex, &tv);
        if (rc < 0 && errno == EINTR)
            continue;
#endif
        if (rc < 0)
            break;
        for (i = 0; i < n; i++) {
            if (sk[i] == SOCK_BAD)
                continue;
            if (FD_ISSET(sk[i], &wr) || FD_ISSET(sk[i], &ex)) {
                err = 1;
                el = (sock_len_t)sizeof err;
                if (getsockopt(sk[i], SOL_SOCKET, SO_ERROR, (char *)&err, &el) != 0)
                    err = 1;
                open_out[i] = (err == 0 && FD_ISSET(sk[i], &wr)) ? 1 : 0;
                sock_close(sk[i]);
                sk[i] = SOCK_BAD;
                pending--;
            }
        }
    }
    for (i = 0; i < n; i++)
        if (sk[i] != SOCK_BAD)
            sock_close(sk[i]);                      /* timed out: closed/filtered */
}

int eng_probe_range(uint32_t first, uint32_t last, unsigned long timeout_ms,
                    volatile int *cancel, eng_scan_prog_cb cb, void *user,
                    uint32_t **out_ips)
{
    static const unsigned short ports[2] = { 445, 139 };
    LocalAddr own[SCAN_MAX_LOCAL];
    uint32_t hosts[ENG_PROBE_HOSTS], tips[ENG_PROBE_BATCH], *found = NULL, *grown;
    unsigned short tports[ENG_PROBE_BATCH];
    unsigned char opn[ENG_PROBE_BATCH];
    unsigned long total, done = 0;
    int nown, nh, i, k, nfound = 0, cap = 0;
    uint32_t ip;

    *out_ips = NULL;
    if (last < first)
        return 0;
    total = (unsigned long)(last - first) + 1UL;
    nown = eng_local_addrs(own, SCAN_MAX_LOCAL);

    while (done < total) {
        if (cancel != NULL && *cancel)
            break;
        nh = 0;
        while (nh < ENG_PROBE_HOSTS && done < total) {
            ip = first + (uint32_t)done;
            done++;
            for (k = 0; k < nown; k++)
                if (own[k].ip == ip)
                    break;
            if (k < nown)
                continue;                           /* never probe ourselves */
            hosts[nh++] = ip;
        }
        if (nh > 0) {
            for (i = 0; i < nh; i++) {
                tips[2 * i] = tips[2 * i + 1] = htonl(hosts[i]);
                tports[2 * i] = ports[0];
                tports[2 * i + 1] = ports[1];
            }
            eng_probe_batch(tips, tports, 2 * nh, timeout_ms, opn);
            for (i = 0; i < nh; i++) {
                if (!opn[2 * i] && !opn[2 * i + 1])
                    continue;
                if (nfound >= SCAN_MAX_HITS)
                    continue;                       /* result list full */
                if (nfound == cap) {
                    cap = (cap == 0) ? 16 : cap * 2;
                    grown = (uint32_t *)realloc(found, (size_t)cap * sizeof *found);
                    if (grown == NULL) {
                        free(found);
                        return -1;
                    }
                    found = grown;
                }
                found[nfound++] = tips[2 * i];
            }
        }
        if (cb != NULL)
            cb(done, total, user);
    }
    *out_ips = found;
    return nfound;
}
