#!/bin/bash
# run_all.sh - build smbftp variants and run the whole test matrix (test harness only)
#
# Version : 1.1
# Usage   : run_all.sh <srcdir>      (srcdir = the project tree; libdsm/ is fetched and patched
#                                     by "make fetch" if it is not there yet)
# Needs   : gcc, python3, samba (smbd), impacket (smbserver.py), valgrind (optional)
# Output  : build/ (binaries), out/ (JSON results), console summary lines
# History : 1.1  runs "make fetch" in <srcdir> when libdsm/ has not been fetched.
#           1.0  first version.
T="$(cd "$(dirname "$0")" && pwd)"; SRC="$(cd "$1" && pwd)" || exit 2
[ -f "$SRC/libdsm/.stamp" ] || make -C "$SRC" fetch || exit 1
cd "$T" || exit 1; mkdir -p build out work
[ -d share ] || ./make_share.sh "$T/share" >/dev/null
./start_servers.sh
EXTRA_DEFS="-DNDEBUG" ./build_linux.sh "$SRC" build/asan asan
./build_linux.sh "$SRC" build/plain plain
./build_winutils.sh "$SRC" build/winutils_asan 65001
for spec in "asan 127.0.0.1 pub" "asan 127.0.0.2 PUB" "plain 127.0.0.1 pub" "plain 127.0.0.2 PUB" "winutils_asan 127.0.0.1 pub"; do
  set -- $spec; echo "== harness $1 $2"; python3 harness.py build/$1 --group all --host $2 --share-name $3 --json out/run_$1_$2.json | tail -1
done
echo "== fuzz (Samba, 200 seeds)";  python3 fuzz.py build/asan --target 127.0.0.1 --share pub --seeds 1-200 --timeout 5 --outdir out/fuzz | tail -4
echo "== fuzz (impacket, 100 seeds)"; python3 fuzz.py build/asan --target 127.0.0.2 --share PUB --seeds 701-800 --timeout 5 --outdir out/fuzzi --script "use PUB|ls|ls d_100|ls d_1000|cd d_50|ls|cd ..|ls d_varlen|get size_65536.bin|quit" | tail -4
echo "== faults (Samba)";  python3 faults.py build/asan | tail -1
echo "== faults (impacket)"; python3 faults.py build/asan --target 127.0.0.2 --share PUB | tail -1
