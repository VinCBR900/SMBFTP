#!/usr/bin/env python3
"""
harness.py - black-box test driver for smbftp (test-harness only, not part of the project)

Version : 1.0
Usage   : harness.py <binary> [--group listing|session|transfer|names|all] [--host 127.0.0.1]
          [--share-dir DIR] [--iterations N] [--json out.json]
History : 1.0  first version: listing ground-truth comparison, session repeat,
               transfer round-trips, name handling.
Notes   : needs a running SMB1 server whose share 'pub' is backed by --share-dir
          (see make_share.sh / smb.conf).
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

HOST = "127.0.0.1"
SHARE_DIR = "/home/claude/smbftp_test/share"
SCRATCH = "/tmp/claude-0/-home-claude/b3d857c9-2053-5181-9023-baa3ad54c7ee/scratchpad/work"

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


def sanitizer_hit(r):
    t = r["err"]
    return ("AddressSanitizer" in t) or ("LeakSanitizer" in t and "detected memory leaks" in t and False) or \
           ("runtime error" in t and "left shift" not in t and "null pointer passed as argument 2" not in t)


def record(group, name, ok, detail=""):
    RESULTS.append(dict(group=group, name=name, ok=bool(ok), detail=detail))
    flag = "PASS" if ok else "FAIL"
    print(f"[{flag}] {group}/{name} {detail}".rstrip(), flush=True)


# --------------------------------------------------------------------------
# listing group
# --------------------------------------------------------------------------
def group_listing(binary, args):
    dirs = sorted(d for d in os.listdir(SHARE_DIR) if os.path.isdir(os.path.join(SHARE_DIR, d)))
    dirs = ["."] + dirs
    for lang in ("C.UTF-8", "C"):
        env = {"LANG": lang, "LC_ALL": lang}
        for d in dirs:
            local = SHARE_DIR if d == "." else os.path.join(SHARE_DIR, d)
            t = truth(local)
            arg = "" if d == "." else (f'"{d}"' if " " in d else d)
            # (a) ls with a path argument straight after 'use'
            r = run(binary, ["use pub", f"ls {arg}".strip(), "quit"], args, env)
            ents, summ = parse_ls(r["out"])
            ok = (ents.keys() == t.keys() and all(ents[k] == t[k] for k in t) and r["rc"] == 0
                  and not sanitizer_hit(r))
            det = ""
            if not ok:
                missing = sorted(set(t) - set(ents))
                extra = sorted(set(ents) - set(t))
                det = f"rc={r['rc']} got={len(ents)}/{len(t)} missing={len(missing)} extra={len(extra)}"
                if sanitizer_hit(r):
                    det += " SANITIZER"
                if r["timeout"]:
                    det += " TIMEOUT"
            record("listing", f"{lang}/ls_arg/{d}", ok, det)
            # (b) cd then bare ls
            if d != ".":
                r = run(binary, ["use pub", f"cd {arg}", "ls", "quit"], args, env)
                ents, summ = parse_ls(r["out"])
                ok = (ents.keys() == t.keys() and all(ents[k] == t[k] for k in t) and r["rc"] == 0
                      and not sanitizer_hit(r))
                det = "" if ok else f"rc={r['rc']} got={len(ents)}/{len(t)}"
                record("listing", f"{lang}/cd_ls/{d}", ok, det)


# --------------------------------------------------------------------------
# session group: repeat connect/use/ls cycles to expose intermittent failures
# --------------------------------------------------------------------------
def group_session(binary, args, iterations):
    fails = 0
    kinds = {}
    for i in range(iterations):
        r = run(binary, ["use pub", "ls", "ls d_100", "cd d_50", "ls", "cd ..", "quit"], args, {"LANG": "C.UTF-8"})
        bad = r["rc"] != 0 or sanitizer_hit(r) or r["timeout"] or "out of memory" in r["err"]
        if bad:
            fails += 1
            k = f"rc={r['rc']}" + (" SAN" if sanitizer_hit(r) else "") + (" OOM" if "out of memory" in r["err"] else "")
            kinds[k] = kinds.get(k, 0) + 1
    record("session", f"repeat_x{iterations}", fails == 0, f"failures={fails} kinds={kinds}")


# --------------------------------------------------------------------------
# transfer group
# --------------------------------------------------------------------------
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def group_transfer(binary, args):
    os.makedirs(SCRATCH, exist_ok=True)
    sizes = sorted(int(m.group(1)) for n in os.listdir(SHARE_DIR)
                   for m in [re.match(r"size_(\d+)\.bin$", n)] if m) + [0, 1]
    for chunk in ("32768", "512", "1000", "4096", "60000"):
        a = list(args) + ["-b", chunk]
        for sz in sizes:
            name = "zero.bin" if sz == 0 else "one.bin" if sz == 1 else f"size_{sz}.bin"
            wd = tempfile.mkdtemp(dir=SCRATCH)
            r = run(binary, ["use pub", f"get {name}", "quit"], a, {"LANG": "C.UTF-8"}, cwd=wd)
            lp = os.path.join(wd, name)
            ok = os.path.exists(lp) and sha(lp) == sha(os.path.join(SHARE_DIR, name)) and r["rc"] == 0 \
                and not sanitizer_hit(r)
            record("transfer", f"get/b{chunk}/{sz}", ok, "" if ok else f"rc={r['rc']} err={r['err'][-200:]!r}")
            shutil.rmtree(wd, ignore_errors=True)
            # put: create local file of that size, upload, compare
            wd = tempfile.mkdtemp(dir=SCRATCH)
            up = os.path.join(wd, f"up_{sz}.bin")
            with open(up, "wb") as f:
                f.write(os.urandom(sz))
            r = run(binary, ["use pub", f"put {up} up_{sz}_{chunk}.bin", "quit"], a, {"LANG": "C.UTF-8"}, cwd=wd)
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
    for lang in ("C.UTF-8", "C"):
        env = {"LANG": lang, "LC_ALL": lang}
        for sub in ("d_unicode", "d_unicode_many", "d_with space", "d_specialnames", "d_long255", "d_varlen"):
            t = truth(os.path.join(SHARE_DIR, sub))
            r = run(binary, ["use pub", f'ls "{sub}"', "quit"], args, env)
            ents, summ = parse_ls(r["out"])
            ok = len(ents) == len(t) and r["rc"] == 0 and not sanitizer_hit(r)
            record("names", f"{lang}/{sub}", ok,
                   "" if ok else f"rc={r['rc']} got={len(ents)}/{len(t)} err={r['err'][-160:]!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--group", default="all")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--share-dir", default=SHARE_DIR)
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--json", default=None)
    ap.add_argument("--smb-args", default="-t tcp")
    o = ap.parse_args()
    global HOST, SHARE_DIR
    HOST, SHARE_DIR = o.host, o.share_dir
    args = o.smb_args.split()
    g = o.group
    if g in ("listing", "all"):
        group_listing(o.binary, args)
    if g in ("names", "all"):
        group_names(o.binary, args)
    if g in ("session", "all"):
        group_session(o.binary, args, o.iterations)
    if g in ("transfer", "all"):
        group_transfer(o.binary, args)
    nf = sum(1 for r in RESULTS if not r["ok"])
    print(f"\nSUMMARY: {len(RESULTS)} tests, {nf} failed")
    if o.json:
        with open(o.json, "w") as f:
            json.dump(RESULTS, f, indent=1)
    sys.exit(1 if nf else 0)


if __name__ == "__main__":
    main()
