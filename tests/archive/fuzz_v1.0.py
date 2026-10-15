#!/usr/bin/env python3
"""
fuzz.py - reply-mutation fuzzer for smbftp (test harness only, not part of the project)

Version : 1.0
Usage   : fuzz.py <binary> --target 127.0.0.1 --share pub --seeds 1-300 [--rate 0.3]
          [--outdir DIR] [--script "use pub|ls d_100|ls d_1000|quit"]
Method  : for each seed, start tcpproxy.py in --mutate mode on 127.0.0.3:445 in front of the
          real SMB1 server, run smbftp (ASan build) through it and classify the outcome:
          OK (rc 0), ERR (clean non-zero exit), ASAN (sanitizer report), SIGNAL (killed by signal),
          HANG (timeout).  Unique sanitizer signatures (error kind + top project frame) are tallied.
History : 1.0 first version.
"""
import argparse, os, re, subprocess, sys, time, collections

HERE = os.path.dirname(os.path.abspath(__file__))


def sig_of(err):
    m = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", err)
    kind = m.group(1) if m else None
    if not kind:
        m = re.search(r"runtime error: (.*)", err)
        kind = "UBSAN:" + (m.group(1)[:60] if m else "?")
    frames = re.findall(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+)", err)
    top = "?"
    for fn, loc in frames:
        if "/smbftp_src/" in loc or "smbftp.c" in loc or "libdsm" in loc or "dbgsrc" in loc or "/work/" in loc:
            top = f"{fn} {os.path.basename(loc)}"
            break
    return f"{kind} @ {top}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--share", default="pub")
    ap.add_argument("--seeds", default="1-100")
    ap.add_argument("--rate", type=float, default=0.3)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--outdir", default=os.path.join(HERE, "out", "fuzz"))
    ap.add_argument("--script", default=None)
    o = ap.parse_args()
    a, b = [int(x) for x in o.seeds.split("-")]
    os.makedirs(o.outdir, exist_ok=True)
    script = (o.script or f"use {o.share}|ls|ls d_100|ls d_1000|cd d_50|ls|cd ..|ls d_varlen|ls d_unicode|get size_65536.bin|quit").split("|")
    stat = collections.Counter()
    sigs = collections.defaultdict(list)
    binary = os.path.abspath(o.binary)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:exitcode=99:symbolize=1", LANG="C.UTF-8")
    wd = os.path.join(o.outdir, "wd")
    os.makedirs(wd, exist_ok=True)
    for seed in range(a, b + 1):
        px = subprocess.Popen([sys.executable, os.path.join(HERE, "tcpproxy.py"), "--listen", "127.0.0.3:445",
                               "--target", f"{o.target}:445", "--mutate", str(seed), "--rate", str(o.rate)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.25)
        try:
            p = subprocess.run([binary, "-t", "tcp", "127.0.0.3"], input=("\n".join(script) + "\n").encode(),
                               capture_output=True, timeout=o.timeout, env=env, cwd=wd)
            err = p.stderr.decode("utf-8", "replace")
            if "AddressSanitizer" in err or (p.returncode == 99):
                cls = "ASAN"
            elif p.returncode < 0:
                cls = "SIGNAL"
            elif "runtime error" in err and "left shift" not in err.split("runtime error")[-1][:80]:
                cls = "UBSAN" if re.search(r"runtime error: (?!left shift|null pointer passed as argument 2)", err) else "OK"
            else:
                cls = "OK" if p.returncode == 0 else "ERR"
            if cls in ("ASAN", "UBSAN"):
                s = sig_of(err)
                sigs[s].append(seed)
                open(os.path.join(o.outdir, f"seed{seed}.err"), "w").write(err)
            elif cls == "SIGNAL":
                sigs[f"SIGNAL {-p.returncode}"].append(seed)
                open(os.path.join(o.outdir, f"seed{seed}.err"), "w").write(err)
        except subprocess.TimeoutExpired:
            cls = "HANG"
            sigs["HANG (client blocked, no timeout)"].append(seed)
        finally:
            px.kill(); px.wait()
        stat[cls] += 1
    print("fuzz outcome counts:", dict(stat))
    for s, seeds in sorted(sigs.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(seeds):4d}  {s}   seeds={seeds[:8]}")


if __name__ == "__main__":
    main()
