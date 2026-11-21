#!/usr/bin/env bash
# Build the lab client in Linux and run it against a legacy-enabled OpenSSH server.
# Usage: harness/check.sh [repo_dir]   (default: this script's repo)
# Env: CFLAGS_EXTRA="-fsanitize=address -g"  REFERENCE=1 (use stock sftp instead of ./client)
#      SIZE_MB=8 (transfer a random file of that size instead of client.c)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${1:-$HERE/..}" && pwd)"
TAG="$(basename "$REPO" | tr -c 'a-zA-Z0-9\n' '-')"
NET="lab4-net-$TAG"; SRV="lab4-sshd-$TAG"
OUT="$REPO/harness/out"; rm -rf "$OUT"; mkdir -p "$OUT"
PASS=lab4test; TIMEOUT="${TIMEOUT:-60}"

cleanup() { docker rm -f "$SRV" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup
docker image inspect lab4-build >/dev/null 2>&1 || docker build -q -t lab4-build -f "$HERE/Dockerfile.build" "$HERE" >/dev/null
docker image inspect lab4-sshd  >/dev/null 2>&1 || docker build -q -t lab4-sshd  -f "$HERE/Dockerfile.sshd"  "$HERE" >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" --network-alias sshd lab4-sshd >/dev/null

# Build, then run one session: put client.c, delete local copy, get it back.
docker run --rm --network "$NET" --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$REPO":/src -e PASS="$PASS" -e TIMEOUT="$TIMEOUT" -e REFERENCE="${REFERENCE:-0}" \
  -e CFLAGS_EXTRA="${CFLAGS_EXTRA:-}" -e SIZE_MB="${SIZE_MB:-0}" lab4-build bash -c '
set -u; cd /src; O=/src/harness/out
if [ "$REFERENCE" = 1 ]; then echo "reference mode: stock client" > $O/build.log
else
  cmake -S . -B build-linux -DCMAKE_C_FLAGS="-DLINUX -DLOG_LEVEL=DEBUG $CFLAGS_EXTRA" > $O/build.log 2>&1 &&
  cmake --build build-linux -j >> $O/build.log 2>&1 || { echo BUILD_FAILED >> $O/build.log; exit 3; }
fi
tcpdump -i eth0 -U -w $O/session.pcap tcp port 22 2> /dev/null & TD=$!; sleep 1
W=$(mktemp -d); N=client.c
if [ "$SIZE_MB" != 0 ]; then N=big.bin; head -c $((SIZE_MB*1048576)) /dev/urandom > $W/$N; else cp /src/client.c $W/$N; fi
cp $W/$N $O/sent.bin; cd $W
if [ "$REFERENCE" = 1 ]; then
  mkdir dl; printf "put $N\nlcd dl\nget $N\nbye\n" > cmds
  timeout $TIMEOUT sshpass -p "$PASS" sftp -oBatchMode=no -oStrictHostKeyChecking=no -oKexAlgorithms=diffie-hellman-group1-sha1 \
    -oHostKeyAlgorithms=ssh-rsa -oCiphers=aes256-cbc -oMACs=hmac-sha1 -b cmds tester@sshd > $O/client.log 2>&1
else
  # Session 1 uploads; session 2 downloads into an empty dir.
  mkdir dl
  { echo "$PASS"; echo put; echo $N; } > in1
  timeout $TIMEOUT /src/build-linux/client tester@sshd < <(cat in1; sleep 2; echo bye) > $O/client.log 2>&1
  echo "exit=$?" >> $O/client.log
  cd dl
  timeout $TIMEOUT /src/build-linux/client tester@sshd < <(printf "%s\nget\n%s\n" "$PASS" "$N"; sleep 2; echo bye) >> $O/client.log 2>&1
  echo "exit=$?" >> $O/client.log
  cd $W
fi
sleep 1; kill $TD 2>/dev/null; wait $TD 2>/dev/null
cmp -s $O/sent.bin $W/dl/$N && echo DOWNLOAD_MATCH > $O/download.txt || echo DOWNLOAD_MISMATCH > $O/download.txt
chmod -R a+rw $O
'
docker logs "$SRV" > "$OUT/sshd.log" 2>&1
RN=client.c; [ "${SIZE_MB:-0}" != 0 ] && RN=big.bin
docker exec "$SRV" cat /home/tester/$RN > "$OUT/remote.bin" 2>/dev/null
cleanup; trap - EXIT

# Grade.
L="$OUT/sshd.log"; fails=0
ok() { printf '%-4s %s  %s\n' "$1" "$2" "$3"; [ "$2" = PASS ] || fails=$((fails+1)); }
chk() { grep -qE "$2" "$L" && ok "$1" PASS "$3" || ok "$1" FAIL "$3"; }
grep -q BUILD_FAILED "$OUT/build.log" 2>/dev/null && { echo "BUILD FAILED, see harness/out/build.log"; exit 1; }
if grep -qE 'Remote protocol version 2\.0' "$L" && { [ "${REFERENCE:-0}" = 1 ] || grep -q 'SSH-2.0-OpenSSH' "$OUT/client.log"; }; then
  ok CP1 PASS 'version exchange; client shows server id'; else ok CP1 FAIL 'version exchange; client shows server id'; fi
chk CP2 'kex: algorithm: diffie-hellman-group1-sha1'         'kex negotiated'
grep -q 'kex: client->server cipher: aes256-cbc MAC: hmac-sha1' "$L" && grep -q 'kex: server->client cipher: aes256-cbc MAC: hmac-sha1' "$L" \
  && ok CP2b PASS 'aes256-cbc + hmac-sha1 both ways' || ok CP2b FAIL 'aes256-cbc + hmac-sha1 both ways'
chk CP3 'SSH2_MSG_NEWKEYS received'                          'keys switched'
if grep -q 'SSH2_MSG_NEWKEYS received' "$L" && [ -s "$OUT/session.pcap" ] && ! grep -aqE "ssh-userauth|$PASS|ssh-connection" "$OUT/session.pcap"; then
  ok CP3b PASS 'no plaintext after NEWKEYS in pcap'; else ok CP3b FAIL 'no plaintext after NEWKEYS in pcap'; fi
chk CP4 'Accepted password for tester'                       'password auth'
chk CP5 'subsystem request for sftp'                         'session channel + sftp subsystem'
cmp -s "$OUT/sent.bin" "$OUT/remote.bin" && ok CP6a PASS 'upload matches' || ok CP6a FAIL 'upload matches'
grep -q DOWNLOAD_MATCH "$OUT/download.txt" 2>/dev/null && ok CP6b PASS 'download matches' || ok CP6b FAIL 'download matches'
grep -qE 'Corrupted MAC|Bad packet length|rcvd too much data|Disconnecting' "$L" && echo "note: server complaints: $(grep -oE 'Corrupted MAC[^\r]*|Bad packet length[^\r]*|rcvd too much data[^\r]*|Disconnecting[^\r]*' "$L" | sort -u | head -3 | tr '\n' ';')"
echo "logs: $OUT"; [ $fails -eq 0 ] && echo ALL_PASS || { echo "FAILED: $fails"; exit 1; }
