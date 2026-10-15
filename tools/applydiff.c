/*
 * applydiff.c - small, strict unified-diff applier (build helper for smbftp)
 *
 * Version : 1.0
 * Build   : tcc -o applydiff.exe applydiff.c        (also builds with gcc/clang)
 * Usage   : applydiff [-p N] [-d DIR] [-n] [-v] patchfile
 *             -p N   strip N leading path components from the file names (default 0)
 *             -d DIR apply to files below DIR (default: current directory)
 *             -n     dry run: check that everything applies, change nothing
 *             -v     say more (every hunk and its offset)
 * Exit    : 0 = applied, 1 = a hunk did not apply (nothing was changed),
 *           2 = bad usage, unreadable or unsupported patch, I/O error
 *
 * Why it exists: Windows has no patch(1) and the Windows build of smbftp uses
 * TCC only (no GNU tools, no WSL). build.cmd compiles this file with TCC and
 * uses it to patch the downloaded libdsm sources. The Makefile uses the same
 * tool on Linux, so both builds patch in exactly the same way.
 *
 * The name avoids "patch", "setup", "install" and "update": Windows' installer
 * detection asks for elevation when a 32-bit exe without a manifest has one of
 * those words in its name.
 *
 * What it does:
 *   - reads unified diffs (diff -u, git diff); text before the first "---" and
 *     git's "diff --git" / "index" lines are ignored
 *   - STRICT: every context and removed line must match exactly (no fuzz, no
 *     whitespace tolerance). A hunk may sit at a different line number than
 *     the diff says (like patch's "offset"), but never before the previous hunk
 *   - all-or-nothing: every file is patched in memory first, files are written
 *     only if every hunk of every file applied
 *   - handles "\ No newline at end of file"; files are read and written in
 *     binary mode, so line ends are never translated
 *   - a patch file with CR LF line ends (Git autocrlf checkout) is accepted;
 *     CR is dropped from its lines. Target files must use LF
 *
 * What it does not do: create, delete, rename or chmod files, binary patches,
 * reverse patches (-R), fuzz. A patch that needs those is refused (exit 2).
 * File names containing spaces are not supported.
 *
 * History : 1.0  first version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ---- small helpers ------------------------------------------------------ */

static void die(int code, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "applydiff: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(code);
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die(2, "out of memory");
    return q;
}

typedef struct {
    const char *p;          /* not NUL terminated for target lines */
    size_t      n;
} Str;

typedef struct {
    Str    *v;
    size_t  n, cap;
} StrVec;

static void sv_push(StrVec *a, const char *p, size_t n)
{
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 64;
        a->v = (Str *)xrealloc(a->v, a->cap * sizeof(Str));
    }
    a->v[a->n].p = p;
    a->v[a->n].n = n;
    a->n++;
}

typedef struct {
    char   *p;
    size_t  n, cap;
} Buf;

static void buf_add(Buf *b, const char *p, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = (char *)xrealloc(b->p, b->cap);
    }
    if (n) memcpy(b->p + b->n, p, n);
    b->n += n;
}

static int read_file(const char *path, char **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long  sz;
    char *buf;
    size_t got;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (char *)xrealloc(NULL, (size_t)sz + 1);
    got = sz ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -1; }
    buf[got] = '\0';
    *data = buf;
    *len = got;
    return 0;
}

/* ---- patch model -------------------------------------------------------- */

typedef struct {
    long   old_start, old_cnt, new_start, new_cnt;
    StrVec old_l, new_l;        /* the two sides of the hunk */
    int    old_no_nl, new_no_nl;/* "\ No newline at end of file" on that side */
    int    number;              /* 1-based, for messages */
} Hunk;

typedef struct {
    char  *name;                /* after -p stripping, as written in the patch */
    Hunk  *h;
    size_t nh, caph;
} FilePatch;

static int starts(const Str *s, const char *pre)
{
    size_t k = strlen(pre);
    return s->n >= k && memcmp(s->p, pre, k) == 0;
}

/* name from a "--- " / "+++ " line: up to the first TAB, trailing blanks cut */
static char *header_name(const Str *s, int strip)
{
    const char *p = s->p + 4;
    size_t n = s->n - 4, i;
    char *name;
    for (i = 0; i < n; i++)
        if (p[i] == '\t') { n = i; break; }
    while (n && (p[n - 1] == ' ' || p[n - 1] == '\r')) n--;
    if (n == 9 && memcmp(p, "/dev/null", 9) == 0)
        die(2, "creating or deleting files is not supported (\"/dev/null\" in the patch)");
    while (strip > 0) {
        for (i = 0; i < n && p[i] != '/'; i++) ;
        if (i == n) die(2, "cannot strip %d path components from \"%.*s\"", strip, (int)n, p);
        p += i + 1;
        n -= i + 1;
        strip--;
    }
    if (n == 0) die(2, "empty file name in the patch");
    name = (char *)xrealloc(NULL, n + 1);
    memcpy(name, p, n);
    name[n] = '\0';
    /* a patch must stay inside the target directory */
    if (name[0] == '/' || name[0] == '\\' || strchr(name, ':') || strchr(name, ' '))
        die(2, "unsupported or unsafe file name \"%s\"", name);
    for (i = 0; name[i]; i++)
        if ((i == 0 || name[i - 1] == '/' || name[i - 1] == '\\') &&
            name[i] == '.' && name[i + 1] == '.' &&
            (name[i + 2] == '\0' || name[i + 2] == '/' || name[i + 2] == '\\'))
            die(2, "file name \"%s\" leaves the target directory", name);
    return name;
}

static void parse_range(const char *s, char **end, long *start, long *cnt)
{
    *start = strtol(s, end, 10);
    if (**end == ',') { *cnt = strtol(*end + 1, end, 10); }
    else              { *cnt = 1; }
}

/* Parse the whole patch. Lines are NUL terminated in place. */
static FilePatch *parse_patch(char *buf, size_t len, int strip, size_t *nfiles)
{
    StrVec L = { 0, 0, 0 };
    size_t i, start = 0;
    int crlf = 0;
    FilePatch *fp = NULL;
    size_t nf = 0, capf = 0;

    /* CR LF patch file (autocrlf checkout)? decided by the first line end */
    for (i = 0; i < len; i++)
        if (buf[i] == '\n') { crlf = (i > 0 && buf[i - 1] == '\r'); break; }

    for (i = 0; i <= len; i++) {
        if (i == len || buf[i] == '\n') {
            size_t e = i;
            if (i == len && start == len) break;     /* no final partial line */
            if (crlf && e > start && buf[e - 1] == '\r') e--;
            buf[e] = '\0';                            /* i < len or the spare byte */
            sv_push(&L, buf + start, e - start);
            start = i + 1;
        }
    }

    for (i = 0; i < L.n; ) {
        Str *s = &L.v[i];
        if (starts(s, "--- ") && i + 1 < L.n && starts(&L.v[i + 1], "+++ ")) {
            FilePatch *f;
            size_t k;
            char *nm = header_name(&L.v[i + 1], strip);
            for (k = 0; k < nf; k++)
                if (strcmp(fp[k].name, nm) == 0)
                    die(2, "\"%s\" appears twice in the patch", nm);
            if (nf == capf) {
                capf = capf ? capf * 2 : 8;
                fp = (FilePatch *)xrealloc(fp, capf * sizeof(FilePatch));
            }
            f = &fp[nf++];
            memset(f, 0, sizeof(*f));
            f->name = nm;
            i += 2;
            while (i < L.n && starts(&L.v[i], "@@ ")) {
                Hunk *h;
                char *q, *end;
                long oc = 0, nc = 0;
                int last = 0;
                if (f->nh == f->caph) {
                    f->caph = f->caph ? f->caph * 2 : 8;
                    f->h = (Hunk *)xrealloc(f->h, f->caph * sizeof(Hunk));
                }
                h = &f->h[f->nh++];
                memset(h, 0, sizeof(*h));
                h->number = (int)f->nh;
                q = (char *)L.v[i].p + 3;
                if (*q != '-') die(2, "%s: malformed hunk header \"%s\"", f->name, L.v[i].p);
                parse_range(q + 1, &end, &h->old_start, &h->old_cnt);
                q = end;
                while (*q == ' ') q++;
                if (*q != '+') die(2, "%s: malformed hunk header \"%s\"", f->name, L.v[i].p);
                parse_range(q + 1, &end, &h->new_start, &h->new_cnt);
                if (h->old_start < 0 || h->old_cnt < 0 || h->new_cnt < 0)
                    die(2, "%s: malformed hunk header \"%s\"", f->name, L.v[i].p);
                i++;
                while (i < L.n && (oc < h->old_cnt || nc < h->new_cnt || L.v[i].p[0] == '\\')) {
                    Str *b = &L.v[i];
                    char c = b->n ? b->p[0] : ' ';   /* an empty line is a blank context line */
                    const char *txt = b->n ? b->p + 1 : b->p;
                    size_t tn = b->n ? b->n - 1 : 0;
                    if (c == ' ')      { sv_push(&h->old_l, txt, tn); sv_push(&h->new_l, txt, tn); oc++; nc++; last = ' '; }
                    else if (c == '-') { sv_push(&h->old_l, txt, tn); oc++; last = '-'; }
                    else if (c == '+') { sv_push(&h->new_l, txt, tn); nc++; last = '+'; }
                    else if (c == '\\') {
                        if (last == ' ')      { h->old_no_nl = h->new_no_nl = 1; }
                        else if (last == '-') { h->old_no_nl = 1; }
                        else if (last == '+') { h->new_no_nl = 1; }
                        else die(2, "%s: hunk %d: stray \"\\\" line", f->name, h->number);
                    }
                    else die(2, "%s: hunk %d: unexpected line \"%s\"", f->name, h->number, b->p);
                    if (oc > h->old_cnt || nc > h->new_cnt)
                        die(2, "%s: hunk %d is longer than its header says", f->name, h->number);
                    i++;
                }
                if (oc != h->old_cnt || nc != h->new_cnt)
                    die(2, "%s: hunk %d is shorter than its header says (truncated patch?)",
                        f->name, h->number);
            }
        } else if (starts(s, "new file mode") || starts(s, "deleted file mode") ||
                   starts(s, "rename ") || starts(s, "copy ") || starts(s, "old mode") ||
                   starts(s, "new mode") || starts(s, "GIT binary patch") ||
                   starts(s, "Binary files ")) {
            die(2, "unsupported patch feature: \"%s\"", s->p);
        } else {
            i++;                         /* free text, "diff --git", "index ..." */
        }
    }
    free(L.v);
    *nfiles = nf;
    return fp;
}

/* ---- applying ----------------------------------------------------------- */

typedef struct {
    StrVec line;        /* the target's lines, without line ends */
    int    last_nl;     /* the last line ends with '\n' (an empty file counts as yes) */
} Target;

static void split_target(const char *d, size_t n, Target *t)
{
    size_t i, s = 0;
    memset(t, 0, sizeof(*t));
    t->last_nl = 1;
    for (i = 0; i < n; i++)
        if (d[i] == '\n') { sv_push(&t->line, d + s, i - s); s = i + 1; }
    if (s < n) { sv_push(&t->line, d + s, n - s); t->last_nl = 0; }
}

static int match_at(const Target *t, long p, const Hunk *h)
{
    long k, n = (long)h->old_l.n;
    int at_eof;
    if (p < 0 || p + n > (long)t->line.n) return 0;
    for (k = 0; k < n; k++) {
        const Str *a = &t->line.v[p + k], *b = &h->old_l.v[k];
        if (a->n != b->n || memcmp(a->p, b->p, a->n) != 0) return 0;
    }
    at_eof = (p + n == (long)t->line.n);
    if (n > 0) {
        /* the hunk's view of the last line's line end must agree with the file */
        if (at_eof && h->old_no_nl == t->last_nl) return 0;
        if (!at_eof && h->old_no_nl) return 0;
    }
    return 1;
}

/* Returns 0 = ok, 1 = a hunk failed (message printed). Result in *out. */
static int apply_file(const char *path, const FilePatch *fp, int verbose, Buf *out)
{
    char  *data = NULL;
    size_t dlen = 0, hi;
    Target t;
    long   cursor = 0, drift = 0;
    int    final_nl;
    int    crlf_target = 0;
    size_t i;

    if (read_file(path, &data, &dlen) != 0)
        die(2, "cannot read \"%s\"", path);
    for (i = 0; i < dlen; i++)
        if (data[i] == '\n') { crlf_target = (i > 0 && data[i - 1] == '\r'); break; }
    split_target(data, dlen, &t);
    final_nl = t.last_nl;
    memset(out, 0, sizeof(*out));
    buf_add(out, "", 0);

    printf("patching file %s\n", path);
    for (hi = 0; hi < fp->nh; hi++) {
        const Hunk *h = &fp->h[hi];
        long nold = (long)h->old_l.n;
        long exp0 = (h->old_cnt == 0) ? h->old_start : h->old_start - 1;
        long base = exp0 + drift, p = -1, d, k;
        int  found = 0;

        if (nold == 0) {
            /* pure insertion: no context to search with, only the stated spot */
            if (base >= cursor && base <= (long)t.line.n) { p = base; found = 1; }
            if (found && base == (long)t.line.n && !t.last_nl && t.line.n > 0) found = 0;
        } else {
            long maxd = (long)t.line.n;
            for (d = 0; d <= maxd && !found; d++) {
                for (k = 0; k < 2 && !found; k++) {
                    long cand = (k == 0) ? base + d : base - d;
                    if (k == 1 && d == 0) continue;
                    if (cand < cursor) continue;
                    if (match_at(&t, cand, h)) { p = cand; found = 1; }
                }
            }
        }
        if (found && h->new_no_nl && p + nold != (long)t.line.n) found = 0;
        if (!found) {
            fprintf(stderr, "applydiff: %s: hunk #%d FAILED (expected near line %ld): "
                            "the lines do not match the file exactly\n",
                    path, h->number, exp0 + 1);
            if (crlf_target)
                fprintf(stderr, "applydiff: %s has CR LF line ends; the patch expects LF "
                                "(check git autocrlf / how the file was extracted)\n", path);
            free(data); free(t.line.v); free(out->p);
            memset(out, 0, sizeof(*out));
            return 1;
        }
        if (p != exp0)
            printf("  hunk #%d succeeded at line %ld (offset %ld)\n",
                   h->number, p + 1, p - exp0);
        else if (verbose)
            printf("  hunk #%d succeeded at line %ld\n", h->number, p + 1);
        drift = p - exp0;

        for (k = cursor; k < p; k++) {
            buf_add(out, t.line.v[k].p, t.line.v[k].n);
            buf_add(out, "\n", 1);
        }
        for (i = 0; i < h->new_l.n; i++) {
            buf_add(out, h->new_l.v[i].p, h->new_l.v[i].n);
            buf_add(out, "\n", 1);
        }
        cursor = p + nold;
        if (cursor == (long)t.line.n) final_nl = !h->new_no_nl;
    }
    for (; cursor < (long)t.line.n; cursor++) {
        buf_add(out, t.line.v[cursor].p, t.line.v[cursor].n);
        buf_add(out, "\n", 1);
    }
    if (!final_nl && out->n > 0 && out->p[out->n - 1] == '\n') out->n--;
    free(data);
    free(t.line.v);
    return 0;
}

/* ---- main --------------------------------------------------------------- */

static void usage(void)
{
    fprintf(stderr, "usage: applydiff [-p N] [-d DIR] [-n] [-v] patchfile\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int strip = 0, dry = 0, verbose = 0, a, failed = 0;
    const char *dir = NULL, *patchfile = NULL;
    char *pbuf = NULL;
    size_t plen = 0, nf = 0, i;
    FilePatch *fp;
    Buf *res;
    char **paths;

    for (a = 1; a < argc; a++) {
        const char *s = argv[a];
        if (s[0] == '-' && s[1] == 'p') {
            const char *v = s[2] ? s + 2 : (++a < argc ? argv[a] : NULL);
            if (!v || *v < '0' || *v > '9') usage();
            strip = atoi(v);
        } else if (s[0] == '-' && s[1] == 'd') {
            dir = s[2] ? s + 2 : (++a < argc ? argv[a] : NULL);
            if (!dir) usage();
        } else if (strcmp(s, "-n") == 0 || strcmp(s, "--dry-run") == 0) dry = 1;
        else if (strcmp(s, "-v") == 0) verbose = 1;
        else if (s[0] == '-' && s[1]) usage();
        else if (!patchfile) patchfile = s;
        else usage();
    }
    if (!patchfile) usage();

    if (read_file(patchfile, &pbuf, &plen) != 0)
        die(2, "cannot read the patch file \"%s\"", patchfile);
    fp = parse_patch(pbuf, plen, strip, &nf);
    if (nf == 0) die(2, "no file patches found in \"%s\"", patchfile);

    res = (Buf *)xrealloc(NULL, nf * sizeof(Buf));
    paths = (char **)xrealloc(NULL, nf * sizeof(char *));
    for (i = 0; i < nf; i++) {
        size_t dl = dir ? strlen(dir) : 0, nl = strlen(fp[i].name);
        paths[i] = (char *)xrealloc(NULL, dl + nl + 2);
        if (dir && dl) { memcpy(paths[i], dir, dl); paths[i][dl] = '/'; memcpy(paths[i] + dl + 1, fp[i].name, nl + 1); }
        else           { memcpy(paths[i], fp[i].name, nl + 1); }
        if (apply_file(paths[i], &fp[i], verbose, &res[i]) != 0) { failed = 1; break; }
    }
    if (failed) {
        fprintf(stderr, "applydiff: patch NOT applied, no file was changed\n");
        return 1;
    }
    if (dry) { printf("applydiff: dry run, all hunks apply\n"); return 0; }
    for (i = 0; i < nf; i++) {
        FILE *f = fopen(paths[i], "wb");
        if (!f || (res[i].n && fwrite(res[i].p, 1, res[i].n, f) != res[i].n) || fclose(f) != 0)
            die(2, "cannot write \"%s\" (files patched so far may be partly changed; "
                   "discard the source tree and start again)", paths[i]);
    }
    return 0;
}
