#!/bin/sh
# start_servers.sh - start the local SMB1 test servers (test harness only)
#
# Version : 1.2
# Usage   : start_servers.sh            (safe to re-run; starts only what is not running)
#   Samba    127.0.0.1:445  share 'pub'   (SMB1/NT1 only, smb.conf with this directory's path filled in)
#   impacket 127.0.0.2:445  share 'PUB'   (strict SMB1 server)
# Needs   : root (port 445), smbd, impacket's smbserver.py in PATH
# History : 1.2  works from any directory: paths come from this script's location,
#                smb.conf is rewritten into run/smb.conf; smbserver.py found via PATH.
#         1.1  run state under smbftp_test/run.
#         1.0  first version.
T="$(cd "$(dirname "$0")" && pwd)"
R=$T/run
mkdir -p /run/samba /var/run/samba $R/ncalrpc $R/logs $R/lock $R/state $R/cache $R/pid $R/private $R/winbindd $R/ntp
sed "s#/home/claude/smbftp_test#$T#g" "$T/smb.conf" > "$R/smb.conf"
SMBSRV="$(command -v smbserver.py || echo /usr/local/bin/smbserver.py)"
pgrep -x smbd >/dev/null || (cd /tmp && nohup setsid smbd -s $R/smb.conf -F --no-process-group > $R/smbd.out 2>&1 < /dev/null &)
pgrep -f "^python3 $SMBSRV" >/dev/null || (cd /tmp && nohup setsid python3 "$SMBSRV" pub $T/share -ip 127.0.0.2 -port 445 > $R/impacket.out 2>&1 < /dev/null &)
sleep 6
python3 - <<'PY'
import socket
for h in ("127.0.0.1", "127.0.0.2"):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((h, 445)); print(h, "445 open")
    except Exception as e:
        print(h, "closed", e)
    s.close()
PY
