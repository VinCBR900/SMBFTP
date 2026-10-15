#!/bin/bash
# test_applydiff.sh - tests for tools/applydiff.c (the patch tool build.cmd and the Makefile use)
#
# Version : 1.0
# Usage   : tests/test_applydiff.sh [iterations]        (default 400)
#           CC=tcc tests/test_applydiff.sh              (test the TCC build; default is cc)
# Needs   : a C compiler, diff, cmp, python3
# Checks  : 1. random file pairs: "diff -u a b" applied to a must give exactly b (all context
#              sizes 0..5, with and without a final newline, empty files), and a hunk that
#              sits 7 lines away from where the patch says
#           2. refusals: wrong context, truncated hunk, applying twice, /dev/null, path escape,
#              duplicate file, all-or-nothing over several files; a refused patch changes nothing
#           3. accepts a CR LF patch file, honours -p, -d and -n
# History : 1.0  first version.
HERE="$(cd "$(dirname "$0")" && pwd)"
N="${1:-400}"
CC="${CC:-cc}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL: $*"; }

$CC -o "$W/applydiff" "$HERE/../tools/applydiff.c" || { echo "cannot build applydiff with $CC"; exit 2; }
AD="$W/applydiff"

# ---- 1. random pairs --------------------------------------------------------
cat > "$W/gen.py" <<'EOF'
import random, sys
seed, out = int(sys.argv[1]), sys.argv[2]
r = random.Random(seed)
def words(): return ["x%d" % r.randint(0, 40), "", "  indented", "tab\there", "}", "{", "int a;", "\\ backslash", "-dash", "+plus", "@@ -1 +1 @@", "--- fake", "end"]
pool = words()
n = r.choice([0, 1, 2, 3, 10, 50, 200])
a = [r.choice(pool) if r.random() < 0.3 else "line %d" % i for i in range(n)]
b = list(a)
for _ in range(r.choice([0, 1, 2, 5, 20])):
    k = r.random()
    if k < 0.35 and b:   b.pop(r.randrange(len(b)))
    elif k < 0.7:        b.insert(r.randint(0, len(b)), r.choice(pool) + " new%d" % r.randint(0, 9))
    elif b:              b[r.randrange(len(b))] = "changed %d" % r.randint(0, 99)
def dump(lines, nl, path):
    s = "\n".join(lines)
    if lines and nl: s += "\n"
    open(path, "w", newline="").write(s)
dump(a, r.random() < 0.8, out + ".a")
dump(b, r.random() < 0.8, out + ".b")
EOF
for i in $(seq 1 "$N"); do
  python3 "$W/gen.py" "$i" "$W/t" || { bad "generator seed $i"; continue; }
  cmp -s "$W/t.a" "$W/t.b" && continue
  ctx=$((i % 6))
  diff -U$ctx "$W/t.a" "$W/t.b" | sed -e '1s|.*|--- a/f|' -e '2s|.*|+++ b/f|' > "$W/t.diff"
  mkdir -p "$W/d"; cp "$W/t.a" "$W/d/f"
  if ! "$AD" -p1 -d "$W/d" "$W/t.diff" >/dev/null 2>"$W/err"; then bad "seed $i ctx $ctx: refused: $(head -1 "$W/err")"; continue; fi
  if cmp -s "$W/d/f" "$W/t.b"; then ok; else bad "seed $i ctx $ctx: wrong result"; fi
done

# ---- 1b. offset: the same hunk 7 lines further down, with unique lines ------------
mkdir -p "$W/o"
for k in $(seq 1 30); do echo "unique $k"; done > "$W/o/a"
sed -e 's/^unique 15$/CHANGED 15/' "$W/o/a" > "$W/o/b"
diff -U3 "$W/o/a" "$W/o/b" | sed -e '1s|.*|--- a/f|' -e '2s|.*|+++ b/f|' > "$W/o/t.diff"
{ for k in 1 2 3 4 5 6 7; do echo "pad $k"; done; cat "$W/o/a"; } > "$W/o/f"
{ for k in 1 2 3 4 5 6 7; do echo "pad $k"; done; cat "$W/o/b"; } > "$W/o/want"
"$AD" -p1 -d "$W/o" "$W/o/t.diff" 2>&1 | grep -q 'offset 7' && cmp -s "$W/o/f" "$W/o/want" && ok || bad "offset 7 not handled"

# ---- 2. refusals leave everything untouched ------------------------------------
mkdir -p "$W/r"; cd "$W/r" || exit 2
printf 'one\ntwo\nthree\nfour\n' > f1; printf 'a\nb\nc\n' > f2
cp f1 f1.orig; cp f2 f2.orig
good1='--- a/f1
+++ b/f1
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
'
good2='--- a/f2
+++ b/f2
@@ -1,3 +1,3 @@
 a
-b
+B
 c
'
bad2='--- a/f2
+++ b/f2
@@ -1,3 +1,3 @@
 a
-NOT-THERE
+B
 c
'
expect_refused() {   # name exit-code patch-text
  printf '%s' "$3" > p.diff
  "$AD" -p1 p.diff >/dev/null 2>&1; rc=$?
  if [ $rc -ne "$2" ]; then bad "$1: exit $rc, wanted $2"; else ok; fi
  cmp -s f1 f1.orig && cmp -s f2 f2.orig && ok || bad "$1: a file was changed"
}
expect_refused "wrong context"        1 "$bad2"
expect_refused "all-or-nothing"       1 "$good1$bad2"
expect_refused "truncated hunk"       2 "--- a/f1
+++ b/f1
@@ -1,3 +1,3 @@
 one
-two
"
expect_refused "create file"          2 "--- /dev/null
+++ b/new
@@ -0,0 +1 @@
+x
"
expect_refused "path escape"          2 "--- a/../x
+++ b/../x
@@ -1 +1 @@
-a
+b
"
expect_refused "duplicate file"       2 "$good1$good1"
expect_refused "no patch inside"      2 "nothing to see here
"
expect_refused "rename"               2 "rename from a
rename to b
"
# a file without a final newline must not accept a patch that expects one (and vice versa)
printf 'a\nb\nc' > f3; cp f3 f3.orig
printf '%s' "$good2" | sed -e 's|a/f2|a/f3|' -e 's|b/f2|b/f3|' > p.diff
"$AD" -p1 p.diff >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && cmp -s f3 f3.orig && ok || bad "unterminated last line accepted by a patch that expects a newline"
printf 'a\nb\nc\n' > f4
printf '%s' '--- a/f4
+++ b/f4
@@ -1,3 +1,3 @@
 a
-b
+B
 c
\ No newline at end of file
' > p.diff
"$AD" -p1 p.diff >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && ok || bad "file with final newline accepted a patch that says it has none"
printf '%s' "$good1$good2" > p.diff
"$AD" -p1 -n p.diff >/dev/null 2>&1 && cmp -s f1 f1.orig && ok || bad "dry run changed a file or failed"
"$AD" -p1 p.diff >/dev/null 2>&1 && grep -q TWO f1 && grep -q '^B$' f2 && ok || bad "two-file patch not applied"
"$AD" -p1 p.diff >/dev/null 2>&1 && bad "second application was accepted" || ok

# ---- 3. CR LF patch file, -p0, -d, mode of untouched files ------------------------
cp f1.orig f1
printf '%s' "$good1" | sed 's/$/\r/' > p.diff
"$AD" -p1 p.diff >/dev/null 2>&1 && grep -q TWO f1 && ok || bad "CR LF patch file refused"
mkdir -p sub; cp f1.orig sub/f1
printf '%s' "$good1" | sed -e 's|a/f1|f1|' -e 's|b/f1|f1|' > p.diff
"$AD" -p0 -d sub p.diff >/dev/null 2>&1 && grep -q TWO sub/f1 && ok || bad "-p0 -d failed"
# target with CR LF line ends: refused, with the hint
printf 'one\r\ntwo\r\nthree\r\nfour\r\n' > crlf.txt
printf '%s' "$good1" | sed -e 's|a/f1|crlf.txt|' -e 's|b/f1|crlf.txt|' > p.diff
"$AD" -p0 p.diff 2>&1 | grep -q 'CR LF' && ok || bad "CR LF target gave no hint"

echo "applydiff tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
