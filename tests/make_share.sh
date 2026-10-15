#!/bin/bash
# make_share.sh - populate the test share used by harness.py / fuzz.py
#
# Version : 1.1
# Usage   : make_share.sh <sharedir>      (the directory is deleted and re-created)
# Content : directories with 0,1,2,10,50,100,120,150,200,300,500,1000,1365-1367,2000,5000 files;
#           600 files with varying name lengths; 40 files with 240-char names; Unicode names
#           (incl. emoji and CJK); names with spaces and shell/URL special characters; a deep
#           tree; 30 root files; files of 0,1,511..10485760 bytes around transfer-chunk edges.
# History : 1.1  dropped the trailing-dot name ("dot."): Samba mangles it, so no ground truth.
#           1.0  first version.
S="$1"; [ -n "$S" ] || { echo "usage: $0 <sharedir>"; exit 2; }
rm -rf "$S"; mkdir -p "$S"; cd "$S" || exit 1
mkdir d_empty
for n in 1 2 10 50 100 120 150 200 300 500 1000 1365 1366 1367 2000 5000; do
  mkdir d_$n; (cd d_$n && for i in $(seq 1 $n); do : > "file_$(printf %05d $i).txt"; done)
done
mkdir d_varlen; (cd d_varlen && for i in $(seq 1 600); do nm=$(head -c $((i % 200 + 1)) /dev/zero | tr '\0' 'x'); : > "${i}_${nm}"; done)
mkdir d_long255; (cd d_long255 && for i in $(seq 1 40); do nm=$(head -c 250 /dev/zero | tr '\0' 'L'); : > "$(printf %04d $i)_${nm:0:240}.txt"; done)
mkdir d_unicode; (cd d_unicode && : > "café.txt"; : > "über.txt"; : > "日本語.txt"; : > "Привет.txt"; : > "emoji_😀.txt"; : > "naïve file.txt"; : > "ß.txt"; : > "Ωmega.txt"; : > "plain.txt")
mkdir d_unicode_many; (cd d_unicode_many && for i in $(seq 1 300); do : > "ファイル_${i}_é.txt"; done)
mkdir "d_with space"; (cd "d_with space" && for i in 1 2 3; do : > "a b $i.txt"; done)
mkdir d_mixed; (cd d_mixed && for i in $(seq 1 60); do mkdir "sub_$i"; : > "f_$i.dat"; done)
mkdir -p d_deep/a/b/c/d/e/f/g/h; : > d_deep/a/b/c/d/e/f/g/h/leaf.txt
mkdir d_specialnames; (cd d_specialnames && : > ".hidden"; : > "UPPER.TXT"; : > "mixedCase.Txt"; : > "a"; : > "~tilde"; : > 'dollar$sign'; : > "semi;colon"; : > "amp&ersand"; : > "paren(1)"; : > "hash#"; : > "pct%20"; : > ".dotfirst.txt"; : > "two..dots")
head -c 0 /dev/zero > zero.bin
printf 'X' > one.bin
for sz in 511 512 513 4096 4097 32767 32768 32769 60000 65535 65536 65537 131072 1048576 10485760; do head -c $sz /dev/urandom > size_$sz.bin; done
for i in $(seq 1 30); do : > "rootfile_$i.txt"; done
echo done
