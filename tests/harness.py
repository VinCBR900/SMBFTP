#!/usr/bin/env python3
"""
harness.py - black-box test driver for smbftp (test-harness only, not part of the project)

Version : 1.1
Usage   : harness.py <binary> [--group listing|session|transfer|names|all] [--host 127.0.0.1]
          [--share-name pub] [--share-dir DIR] [--iterations N] [--json out.json]
          [--smb-args "-t tcp"]
History : 1.1  fixes: 'global' declaration order; binary path made absolute (cwd changes per
               test); --share-name (impacket calls the share PUB); scratch dir beside the
               script, no session path; C-locale comparison normalises names the local code
               page cannot show to '?' (a name shown with '?' is correct, a missing one is not).
        1.0    first version: listing ground-truth comparison, session repeat,
               transfer round-trips, name handling.
Notes   : needs a running SMB1 server whose share is backed by --share-dir
          (see make_share.sh, smb.conf, start_servers.sh).
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
SHARE = "pub"
SHARE_DIR = os.path.join(HERE, "share")
SCRATCH = os.path.join(HERE, "work")

RESULTS = []


def run(binary, cmds, args=None, env_extra=None, timeout=60, cwd=None):
    """run - launch smbftp, feed commands on stdin.
    Inputs : binary path, cmds = list of command lines, args = extra argv,
             env_extra = env overrides, timeout seconds, cwd = local directory
    Outputs: dict(rc, out, err, secs, timeout)
    Clobbers: none"""
    argv = [binary] + (args or ["-t", "tcp"]) + [HOST]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:exitcode=99:symbolize=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1"
    if env_extra:
        env.update(env_extra)
    inp = "\n".join(cmds) + "\n"
    t0 = time.time()
    try:
        p = subprocess.run(argv, input=inp.encode("utf-8", "surrogateescape"), capture_output=True,
                           timeout=timeout, env=env, cwd=cwd)
        return dict(rc=p.returncode, out=p.stdout.decode("utf-8", "replace"),
                    err=p.stderr.decode("utf-8", "replace"), secs=time.time() - t0, timeout=False)
    except subprocess.TimeoutExpired as e:
        return dict(rc=-999, out=(e.stdout or b"").decode("utf-8", "replace"),
                    err=(e.stderr or b"").decode("utf-8", "replace"), secs=time.time() - t0, timeout=True)


LS_RE = re.compile(r"^(.{16})  +(<DIR>|\d+)  (.*)$")


def parse_ls(out):
    """parse_ls - parse smbftp 'ls' output blocks
    Inputs : stdout text
    Outputs: (entries dict name -> (isdir,size), summary tuple or None)
    Clobbers: none"""
    ents = {}
    summ = None
    for line in out.splitlines():
        line = re.sub(r"^(smb:\\[^>]*> |smb> )+", "", line)
        m = re.match(r"^(\d+) file\(s\), (\d+) dir\(s\), (\d+) bytes$", line)
        if m:
            summ = tuple(int(x) for x in m.groups())
            continue
        m = LS_RE.match(line)
        if m:
            sz = m.group(2)
            ents[m.group(3)] = (sz == "<DIR>", 0 if sz == "<DIR>" else int(sz))
    return ents, summ


def truth(path):
    """truth - ground truth for a local directory
    Inputs : path
    Outputs: dict name -> (isdir,size)
    Clobbers: none"""
    d = {}
    for n in os.listdir(path):
        full = os.path.join(path, n)
        st = os.stat(full)
        d[n] = (os.path.isdir(full), 0 if os.path.isdir(full) else st.st_size)
    return d


def norm_c(d):
    """norm_c - C-locale view of a name map: every run of non-ASCII characters or '?' becomes
               one '?', because the C locale cannot show them (a '?' is correct, a gap is not)
    Inputs : d = dict name -> value
    Outputs: new dict with normalised keys (colliding names get a counter suffix)
    Clobbers: none"""
    out = {}
    for k, v in sorted(d.items()):
        nk = re.sub(r"[^\x00-\x7f?]+|\?+", "?", k)
        base, i = nk, 1
        while nk in out:
            i += 1
            nk = f"{base}#{i}"
        out[nk] = v
    return out


def compare(ents, t, lang):
    """compare - listing vs ground truth
    Inputs : ents = parsed listing, t = truth, lang = locale name
    Outputs: (ok, missing count, extra count)
    Clobbers: none"""
    if lang == "C":
        ents, t = norm_c(ents), norm_c(t)
        # normalisation can merge names; compare the sorted (isdir,size) lists plus ASCII names
        ok = sorted(ents.values()) == sorted(t.values()) and \
            {k for k in t if "?" not in k} <= set(ents)
        return ok, max(0, len(t) - len(ents)), max(0, len(ents) - len(t))
    ok = ents.keys() == t.keys() and all(ents[k] == t[k] for k in t)
    return ok, len(set(t) - set(ents)), len(set(ents) - set(t))


def sanitizer_hit(r):
    """sanitizer_hit - did the run report an ASan error or a UBSan error other than the two
                       known-benign libdsm shifts / memcpy(NULL,0) reports
    Inputs : r = run() result
    Outputs: bool
    Clobbers: none"""
    t = r["err"]
    if "AddressSanitizer" in t:
        return True
    for m in re.finditer(r"runtime error: ([^\n]*)", t):
        msg = m.group(1)
        if "left shift of 1 by 31" in msg or "null pointer passed as argument 2" in msg:
            continue
        return True
    return False


def record(group, name, ok, detail=""):
    """record - store and print one test result
    Inputs : group, name, ok flag, detail text
    Outputs: line on stdout
    Clobbers: RESULTS"""
    RESULTS.append(dict(group=group, name=name, ok=bool(ok), detail=detail))
    flag = "PASS" if ok else "FAIL"
    print(f"[{flag}] {group}/{name} {detail}".rstrip(), flush=True)


# --------------------------------------------------------------------------
# listing group
# --------------------------------------------------------------------------
def group_listing(binary, args):
    """group_listing - every directory listed by 'ls <dir>' and by 'cd <dir>; ls', two locales
    Inputs : binary, args
    Outputs: records
    Clobbers: none"""
    dirs = sorted(d for d in os.listdir(SHARE_DIR) if os.path.isdir(os.path.join(SHARE_DIR, d)))
    dirs = ["."] + dirs
    for lang in ("C.UTF-8", "C"):
        env = {"LANG": lang, "LC_ALL": lang}
        for d in dirs:
            local = SHARE_DIR if d == "." else os.path.join(SHARE_DIR, d)
            t = truth(local)
            arg = "" if d == "." else (f'"{d}"' if " " in d else d)
            r = run(binary, [f"use {SHARE}", f"ls {arg}".strip(), "quit"], args, env)
            ents, summ = parse_ls(r["out"])
            same, nmiss, nextra = compare(ents, t, lang)
            ok = same and r["rc"] == 0 and not sanitizer_hit(r)
            det = ""
            if not ok:
                det = f"rc={r['rc']} got={len(ents)}/{len(t)} missing={nmiss} extra={nextra}"
                if sanitizer_hit(r):
                    det += " SANITIZER"
                if r["timeout"]:
                    det += " TIMEOUT"
            record("listing", f"{lang}/ls_arg/{d}", ok, det)
            if d != ".":
                r = run(binary, [f"use {SHARE}", f"cd {arg}", "ls", "quit"], args, env)
                ents, summ = parse_ls(r["out"])
                same, nmiss, nextra = compare(ents, t, lang)
                ok = same and r["rc"] == 0 and not sanitizer_hit(r)
                det = "" if ok else f"rc={r['rc']} got={len(ents)}/{len(t)}"
                record("listing", f"{lang}/cd_ls/{d}", ok, det)


# --------------------------------------------------------------------------
# session group: repeat connect/use/ls cycles to expose intermittent failures
# --------------------------------------------------------------------------
def group_session(binary, args, iterations):
    """group_session - repeat a connect/use/ls/cd cycle to expose intermittent failures
    Inputs : binary, args, iterations
    Outputs: one record
    Clobbers: none"""
    fails = 0
    kinds = {}
    for i in range(iterations):
        r = run(binary, [f"use {SHARE}", "ls", "ls d_100", "cd d_50", "ls", "cd ..", "quit"], args,
                {"LANG": "C.UTF-8"})
        bad = r["rc"] != 0 or sanitizer_hit(r) or r["timeout"] or "out of memory" in r["err"]
        if bad:
            fails += 1
            k = f"rc={r['rc']}" + (" SAN" if sanitizer_hit(r) else "") + \
                (" OOM" if "out of memory" in r["err"] else "")
            kinds[k] = kinds.get(k, 0) + 1
    record("session", f"repeat_x{iterations}", fails == 0, f"failures={fails} kinds={kinds}")


# --------------------------------------------------------------------------
# transfer group
# --------------------------------------------------------------------------
def sha(path):
    """sha - SHA-256 of a file
    Inputs : path
    Outputs: hex digest
    Clobbers: none"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def group_transfer(binary, args):
    """group_transfer - get and put round-trips for many sizes and chunk sizes, SHA-256 compared
    Inputs : binary, args
    Outputs: records
    Clobbers: SCRATCH files (removed), temporary uploads on the share (removed)"""
    os.makedirs(SCRATCH, exist_ok=True)
    sizes = sorted(int(m.group(1)) for n in os.listdir(SHARE_DIR)
                   for m in [re.match(r"size_(\d+)\.bin$", n)] if m) + [0, 1]
    for chunk in ("32768", "512", "1000", "4096", "60000"):
        a = list(args) + ["-b", chunk]
        for sz in sizes:
            name = "zero.bin" if sz == 0 else "one.bin" if sz == 1 else f"size_{sz}.bin"
            wd = tempfile.mkdtemp(dir=SCRATCH)
            r = run(binary, [f"use {SHARE}", f"get {name}", "quit"], a, {"LANG": "C.UTF-8"}, cwd=wd)
            lp = os.path.join(wd, name)
            ok = os.path.exists(lp) and sha(lp) == sha(os.path.join(SHARE_DIR, name)) and r["rc"] == 0 \
                and not sanitizer_hit(r)
            record("transfer", f"get/b{chunk}/{sz}", ok, "" if ok else f"rc={r['rc']} err={r['err'][-200:]!r}")
            shutil.rmtree(wd, ignore_errors=True)
            wd = tempfile.mkdtemp(dir=SCRATCH)
            up = os.path.join(wd, f"up_{sz}.bin")
            with open(up, "wb") as f:
                f.write(os.urandom(sz))
            r = run(binary, [f"use {SHARE}", f"put {up} up_{sz}_{chunk}.bin", "quit"], a,
                    {"LANG": "C.UTF-8"}, cwd=wd)
            rp = os.path.join(SHARE_DIR, f"up_{sz}_{chunk}.bin")
            ok = os.path.exists(rp) and sha(rp) == sha(up) and r["rc"] == 0 and not sanitizer_hit(r)
            record("transfer", f"put/b{chunk}/{sz}", ok, "" if ok else f"rc={r['rc']} err={r['err'][-200:]!r}")
            if os.path.exists(rp):
                os.remove(rp)
            shutil.rmtree(wd, ignore_errors=True)


# --------------------------------------------------------------------------
# names group
# --------------------------------------------------------------------------
def group_names(binary, args):
    """group_names - directories with awkward names, entry counts compared
    Inputs : binary, args
    Outputs: records
    Clobbers: none"""
    for lang in ("C.UTF-8", "C"):
        env = {"LANG": lang, "LC_ALL": lang}
        for sub in ("d_unicode", "d_unicode_many", "d_with space", "d_specialnames", "d_long255", "d_varlen"):
            t = truth(os.path.join(SHARE_DIR, sub))
            r = run(binary, [f"use {SHARE}", f'ls "{sub}"', "quit"], args, env)
            ents, summ = parse_ls(r["out"])
            ok = len(ents) == len(t) and r["rc"] == 0 and not sanitizer_hit(r)
            record("names", f"{lang}/{sub}", ok,
                   "" if ok else f"rc={r['rc']} got={len(ents)}/{len(t)} err={r['err'][-160:]!r}")


def main():
    """main - parse options and run the selected groups
    Inputs : command line
    Outputs: exit status 0 (all pass) / 1; summary line; optional JSON file
    Clobbers: RESULTS, globals HOST/SHARE/SHARE_DIR"""
    global HOST, SHARE, SHARE_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--group", default="all")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--share-name", default="pub")
    ap.add_argument("--share-dir", default=SHARE_DIR)
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--json", default=None)
    ap.add_argument("--smb-args", default="-t tcp")
    o = ap.parse_args()
    HOST, SHARE, SHARE_DIR = o.host, o.share_name, o.share_dir
    binary = os.path.abspath(o.binary)
    args = o.smb_args.split()
    g = o.group
    if g in ("listing", "all"):
        group_listing(binary, args)
    if g in ("names", "all"):
        group_names(binary, args)
    if g in ("session", "all"):
        group_session(binary, args, o.iterations)
    if g in ("transfer", "all"):
        group_transfer(binary, args)
    nf = sum(1 for r in RESULTS if not r["ok"])
    print(f"\nSUMMARY: {len(RESULTS)} tests, {nf} failed")
    if o.json:
        with open(o.json, "w") as f:
            json.dump(RESULTS, f, indent=1)
    sys.exit(1 if nf else 0)


if __name__ == "__main__":
    main()
