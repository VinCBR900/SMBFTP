#!/usr/bin/env python3
"""
faults.py - network fault-injection tests for smbftp (test harness only, not part of the project)

Version : 1.0
Usage   : faults.py <binary> [--target 127.0.0.1] [--share pub] [--share-dir DIR] [--json out.json]
Method  : runs smbftp through tcpproxy.py on 127.0.0.3:445 with each fault and checks the outcome:
          chunk    server replies delivered in 1/3/7/50/500-byte pieces, optional delay between
                   pieces: listings must still be complete and downloads byte-exact
          drop     connection closed after N server->client bytes (N sweeps across the listing
                   reply): the client must exit cleanly, never crash, never print a name that is
                   not in the share, and must say so when the listing is incomplete
          reconnect after a dropped connection a new run must work (no state left behind)
          leak     with ASan builds run with detect_leaks=1 and report leaks inside libdsm/smbftp
History : 1.0  first version.
"""
import argparse, hashlib, json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = []


def px_start(target, extra):
    """px_start - start tcpproxy in front of target
    Inputs : target = server ip, extra = list of proxy options
    Outputs: Popen object
    Clobbers: none"""
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "tcpproxy.py"), "--listen", "127.0.0.3:445",
                          "--target", f"{target}:445"] + extra,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    return p


def run(binary, script, cwd, timeout=120, leaks=False):
    """run - run smbftp against the proxy with a script on stdin
    Inputs : binary path, script = list of lines, cwd, timeout seconds, leaks = detect leaks
    Outputs: (returncode or 'TIMEOUT', stdout, stderr, seconds)
    Clobbers: none"""
    env = dict(os.environ, LANG="C.UTF-8",
               ASAN_OPTIONS=("detect_leaks=1" if leaks else "detect_leaks=0") + ":exitcode=99:symbolize=1")
    t0 = time.time()
    try:
        r = subprocess.run([binary, "-t", "tcp", "127.0.0.3"], input=("\n".join(script) + "\n").encode(),
                           capture_output=True, timeout=timeout, env=env, cwd=cwd)
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), time.time() - t0
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", "", time.time() - t0


def names_in(out):
    """names_in - file names printed by 'ls' (last column of each listing line)
    Inputs : smbftp stdout
    Outputs: list of names
    Clobbers: none"""
    res = []
    for ln in out.splitlines():
        m = re.search(r"(file_\d+\.txt)\s*$", ln)
        if m:
            res.append(m.group(1))
    return res


def record(name, ok, detail=""):
    """record - store and print one result
    Inputs : name, ok, detail
    Outputs: none
    Clobbers: RESULTS"""
    RESULTS.append({"test": name, "ok": bool(ok), "detail": detail})
    print(("[PASS] " if ok else "[FAIL] ") + name + ((" " + detail) if detail else ""), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--share", default="pub")
    ap.add_argument("--share-dir", default=os.path.join(HERE, "share"))
    ap.add_argument("--json", default=None)
    o = ap.parse_args()
    binary = os.path.abspath(o.binary)
    wd = os.path.join(HERE, "work", "faults")
    os.makedirs(wd, exist_ok=True)
    truth = sorted(f for f in os.listdir(os.path.join(o.share_dir, "d_1000")))
    ref = hashlib.md5(open(os.path.join(o.share_dir, "size_65536.bin"), "rb").read()).hexdigest()

    # --- chunked delivery
    for chunk, delay in ((1, 0), (3, 0), (7, 0), (50, 0), (500, 0), (7, 2)):
        px = px_start(o.target, ["--chunk", str(chunk), "--delay", str(delay)])
        try:
            if os.path.exists(os.path.join(wd, "size_65536.bin")):
                os.remove(os.path.join(wd, "size_65536.bin"))
            rc, out, err, secs = run(binary, [f"use {o.share}", "ls d_1000", "get size_65536.bin", "quit"], wd, 300)
            got = names_in(out)
            sz = os.path.join(wd, "size_65536.bin")
            md = hashlib.md5(open(sz, "rb").read()).hexdigest() if os.path.exists(sz) else None
            ok = rc == 0 and sorted(got) == truth and md == ref and "AddressSanitizer" not in err
            record(f"chunk/{chunk}b/delay{delay}ms", ok, f"rc={rc} names={len(got)}/{len(truth)} md5ok={md == ref} {secs:.1f}s")
        finally:
            px.kill(); px.wait()

    # --- connection dropped part-way
    sweep = [500, 2000, 8000, 20000, 40000, 60000, 66000, 70000, 90000, 100000, 110000, 120000, 130000, 134000]
    for n in sweep:
        px = px_start(o.target, ["--drop-after", str(n)])
        try:
            rc, out, err, secs = run(binary, [f"use {o.share}", "ls d_1000", "quit"], wd, 120)
            got = names_in(out)
            bad = [g for g in got if g not in truth]
            dup = len(got) - len(set(got))
            crash = ("AddressSanitizer" in err) or rc in (99,) or (isinstance(rc, int) and rc < 0) or rc == "TIMEOUT"
            incomplete = len(got) < len(truth)
            flagged = ("incomplete" in err.lower()) or ("error" in err.lower()) or ("failed" in err.lower()) or ("not connected" in (out + err).lower())
            ok = (not crash) and not bad and dup == 0 and (not incomplete or flagged)
            record(f"drop@{n}", ok, f"rc={rc} names={len(got)}/{len(truth)} bad={len(bad)} dup={dup} flagged={flagged} {secs:.1f}s")
        finally:
            px.kill(); px.wait()

    # --- a clean run after the drops
    px = px_start(o.target, [])
    try:
        rc, out, err, secs = run(binary, [f"use {o.share}", "ls d_1000", "quit"], wd, 120)
        record("reconnect_after_drop", rc == 0 and sorted(names_in(out)) == truth, f"rc={rc} names={len(names_in(out))}")
    finally:
        px.kill(); px.wait()

    # --- leaks (ASan builds only)
    px = px_start(o.target, [])
    try:
        rc, out, err, secs = run(binary, [f"use {o.share}", "ls d_1000", "ls d_unicode", "get size_4096.bin", "quit"], wd, 120, leaks=True)
        leaks = re.findall(r"(?:Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:\s*\n((?:\s+#\d+ [^\n]*\n){1,4})", err)
        mine = [l for l in leaks if re.search(r"libdsm|smbftp", l[2])]
        record("leak_check", not mine, f"rc={rc} leak_reports={len(leaks)} in_project={len(mine)}")
        if mine:
            open(os.path.join(wd, "leaks.txt"), "w").write(err)
    finally:
        px.kill(); px.wait()

    fails = [r for r in RESULTS if not r["ok"]]
    print(f"SUMMARY: {len(RESULTS)} tests, {len(fails)} failed")
    if o.json:
        json.dump(RESULTS, open(o.json, "w"), indent=1)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
