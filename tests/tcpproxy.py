#!/usr/bin/env python3
"""
tcpproxy.py - logging / fault-injecting TCP proxy for SMB1 traffic (test harness only)

Version : 1.1
Usage   : tcpproxy.py --listen 127.0.0.3:445 --target 127.0.0.1:445 [--log FILE] [--dump]
          [--chunk N] [--delay MS] [--drop-after N] [--mutate SEED] [--rate P]
Options : --dump          decode SMB1 headers/commands (TRANS2 find parameters) into --log
          --chunk N       split every server->client write into N-byte sends
          --delay MS      sleep MS between chunks
          --drop-after N  close both sockets after N server->client bytes
          --mutate SEED   fuzz server->client TRANS2/READ/NT_CREATE replies with a seeded RNG
          --rate P        probability (0..1) that a candidate reply is mutated (default 0.3)
History : 1.1  added --mutate / --rate fuzzing of server replies.
          1.0  first version (logging, chunking, delay, drop).
"""
import argparse, random, socket, struct, sys, threading, time

CMDS = {0x32: "TRANS2", 0x25: "TRANS", 0x72: "NEGOTIATE", 0x73: "SESSION_SETUP", 0x75: "TREE_CONNECT",
        0xa2: "NT_CREATE", 0x2e: "READ", 0x2f: "WRITE", 0x04: "CLOSE", 0x71: "TREE_DISC", 0x74: "LOGOFF",
        0x2b: "ECHO"}
T2 = {0: "OPEN2", 1: "FIND_FIRST2", 2: "FIND_NEXT2", 3: "QUERY_FS", 5: "QUERY_PATH", 7: "QUERY_FILE"}


def decode(buf, d):
    """decode - describe every complete NetBIOS/SMB1 message in buf
    Inputs : buf = bytes seen so far in direction d, d = "C>S" or "S>C"
    Outputs: list of text lines
    Clobbers: none"""
    out = []
    pos = 0
    while pos + 4 <= len(buf):
        ln = ((buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3])
        msg = buf[pos + 4:pos + 4 + ln]
        if len(msg) < ln:
            break
        if msg[:4] == b"\xffSMB" and len(msg) >= 32:
            cmd = msg[4]
            st = struct.unpack_from("<I", msg, 5)[0]
            s = f"{d} len={ln} {CMDS.get(cmd, hex(cmd))} status=0x{st:08x}"
            if cmd == 0x32 and d == "C>S" and len(msg) >= 32 + 1 + 30:
                wct = msg[32]
                w = msg[33:33 + wct * 2]
                if wct >= 14:
                    tpc, tdc, mpc, mdc = struct.unpack_from("<HHHH", w, 0)
                    pc, po, dc, do = struct.unpack_from("<HHHH", w, 20)
                    sub = struct.unpack_from("<H", w, 28)[0] if wct >= 15 else -1
                    s += f" sub={T2.get(sub, sub)} totpar={tpc} totdata={tdc} maxpar={mpc} maxdata={mdc} par={pc}@{po} data={dc}@{do}"
                    pp = msg[po:po + pc]
                    if sub == 1 and len(pp) >= 12:
                        s += f" ff[attr={struct.unpack_from('<H', pp, 0)[0]:#x} cnt={struct.unpack_from('<H', pp, 2)[0]} flags={struct.unpack_from('<H', pp, 4)[0]:#x} lvl={struct.unpack_from('<H', pp, 6)[0]:#x}] pat={pp[12:].decode('utf-16le', 'replace')!r}"
                    if sub == 2 and len(pp) >= 12:
                        s += f" fn[sid={struct.unpack_from('<H', pp, 0)[0]} cnt={struct.unpack_from('<H', pp, 2)[0]} lvl={struct.unpack_from('<H', pp, 4)[0]:#x} resume={struct.unpack_from('<I', pp, 6)[0]:#x} flags={struct.unpack_from('<H', pp, 10)[0]:#x}] name={pp[12:].decode('utf-16le', 'replace')!r}"
            if cmd == 0x32 and d == "S>C" and len(msg) >= 32 + 1 + 20:
                wct = msg[32]
                w = msg[33:33 + wct * 2]
                if wct >= 10:
                    tpc, tdc, _, pc, po, pd, dc, do, dd = struct.unpack_from("<HHHHHHHHH", w, 0)
                    s += f" wct={wct} totpar={tpc} totdata={tdc} par={pc}@{po} pdisp={pd} data={dc}@{do} ddisp={dd}"
                    if pc >= 8 and po + pc <= len(msg):
                        s += " params=" + msg[po:po + pc].hex()
            out.append(s)
        pos += 4 + ln
    return out


def mutate_msg(msg, rng):
    """mutate_msg - return a mutated copy of one SMB message (without the NetBIOS header)
    Inputs : msg = bytes, rng = random.Random
    Outputs: bytes (possibly shorter)
    Clobbers: none"""
    b = bytearray(msg)
    kind = rng.choice(["flip", "flip", "truncate", "status", "field", "zero", "big"])
    if len(b) <= 33:
        return bytes(b)
    if kind == "flip":
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(32, len(b))] = rng.randrange(256)
    elif kind == "truncate":
        cut = rng.randint(1, max(1, len(b) - 33))
        del b[len(b) - cut:]
    elif kind == "status":
        b[5:9] = struct.pack("<I", rng.choice([0xC0000001, 0xC000000F, 0xC0000034, 0xC000003A, 0x80000006,
                                               0xC0000022, 0xC00000CC, 0xFFFFFFFF]))
    elif kind == "field":
        if b[32] >= 10:
            w = rng.randrange(0, 10) * 2
            b[33 + w:35 + w] = struct.pack("<H", rng.choice([0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff]))
        else:
            b[rng.randrange(32, len(b))] = rng.randrange(256)
    elif kind == "zero":
        i = rng.randrange(32, len(b))
        n = rng.randint(1, 64)
        b[i:i + n] = bytes(len(b[i:i + n]))
    elif kind == "big":
        i = rng.randrange(32, len(b) - 3) if len(b) > 36 else 32
        b[i:i + 4] = struct.pack("<I", rng.choice([0xffffffff, 0x80000000, 0x7fffffff, 0x10000, 0xffff]))
    return bytes(b)


def close_pair(src, dst):
    """close_pair - shut down and close both sockets, ignoring errors
    Inputs : src, dst sockets
    Outputs: none
    Clobbers: both sockets"""
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass


def pump_mutate(src, dst, a, rng):
    """pump_mutate - server->client pump that mutates candidate replies
    Inputs : src = server socket, dst = client socket, a = options, rng = random.Random
    Outputs: none (runs until a socket closes)
    Clobbers: sockets"""
    buf = b""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            buf += data
            while len(buf) >= 4:
                ln = (buf[1] << 16) | (buf[2] << 8) | buf[3]
                if len(buf) < 4 + ln:
                    break
                msg = buf[4:4 + ln]
                buf = buf[4 + ln:]
                if len(msg) > 33 and msg[:4] == b"\xffSMB" and msg[4] in (0x32, 0x2e, 0xa2) and rng.random() < a.rate:
                    msg = mutate_msg(msg, rng)
                dst.sendall(bytes([0, (len(msg) >> 16) & 0xff, (len(msg) >> 8) & 0xff, len(msg) & 0xff]) + msg)
    except OSError:
        pass
    finally:
        close_pair(src, dst)


def pump(src, dst, d, a, lock, logf):
    """pump - plain pump with optional decode logging, chunking, delay and drop
    Inputs : src, dst sockets, d = "C>S"/"S>C", a = options, lock/logf = log guard and file
    Outputs: none (runs until a socket closes)
    Clobbers: sockets, logf"""
    buf = b""
    sent = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if a.dump and logf:
                buf += data
                lines = decode(buf, d)
                p = 0
                while p + 4 <= len(buf):
                    ln = ((buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3])
                    if p + 4 + ln > len(buf):
                        break
                    p += 4 + ln
                buf = buf[p:]
                with lock:
                    for l in lines:
                        logf.write(l + "\n")
                    logf.flush()
            if d == "S>C" and a.chunk:
                for i in range(0, len(data), a.chunk):
                    piece = data[i:i + a.chunk]
                    dst.sendall(piece)
                    sent += len(piece)
                    if a.delay:
                        time.sleep(a.delay / 1000.0)
                    if a.drop_after and sent >= a.drop_after:
                        raise OSError("drop")
            else:
                dst.sendall(data)
                sent += len(data)
                if d == "S>C" and a.drop_after and sent >= a.drop_after:
                    raise OSError("drop")
    except OSError:
        pass
    finally:
        close_pair(src, dst)


def main():
    """main - parse options, accept connections, start the two pump threads per connection
    Inputs : command line
    Outputs: none (serves forever)
    Clobbers: log file"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--log")
    ap.add_argument("--chunk", type=int, default=0)
    ap.add_argument("--delay", type=int, default=0)
    ap.add_argument("--mutate", type=int, default=None)
    ap.add_argument("--rate", type=float, default=0.3)
    ap.add_argument("--drop-after", type=int, default=0)
    ap.add_argument("--dump", action="store_true")
    a = ap.parse_args()
    lh, lp = a.listen.rsplit(":", 1)
    th, tp = a.target.rsplit(":", 1)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((lh, int(lp)))
    ls.listen(16)
    logf = open(a.log, "a") if a.log else None
    lock = threading.Lock()
    while True:
        c, _ = ls.accept()
        try:
            t = socket.create_connection((th, int(tp)))
        except OSError:
            c.close()
            continue
        if logf:
            with lock:
                logf.write("=== connection ===\n")
                logf.flush()
        threading.Thread(target=pump, args=(c, t, "C>S", a, lock, logf), daemon=True).start()
        if a.mutate is not None:
            rng = random.Random(a.mutate)
            threading.Thread(target=pump_mutate, args=(t, c, a, rng), daemon=True).start()
        else:
            threading.Thread(target=pump, args=(t, c, "S>C", a, lock, logf), daemon=True).start()


if __name__ == "__main__":
    main()
