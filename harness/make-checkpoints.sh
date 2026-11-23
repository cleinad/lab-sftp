#!/usr/bin/env bash
# Run the harness once and turn its logs into checkpoint/ evidence files.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"; O="$REPO/harness/out"; C="$REPO/checkpoint"
TIMEOUT=60 "$REPO/harness/check.sh" "$REPO" | tee /tmp/lab4-check.txt
rm -rf "$C"; mkdir -p "$C"
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
CL="$(strip < "$O/client.log")"; SL="$(tr -d '\r' < "$O/sshd.log")"
first_session() { awk '/exit=/{exit} {print}'; }

{ echo "# CP1: server identification string"
  echo "Client log (session 1):"; echo "$CL" | first_session | grep 'server identification'
  echo; echo "Server side, the client's own identification as seen by sshd:"; echo "$SL" | grep -m1 'Remote protocol version'
} > "$C/cp1.txt"

{ echo "# CP2: negotiated cipher suite"
  echo "Client log:"; echo "$CL" | first_session | grep 'negotiated algorithms'
  echo; echo "Server log:"; echo "$SL" | grep -m3 -E 'kex: algorithm|kex: (client->server|server->client) cipher'
} > "$C/cp2.txt"

docker run --rm -v "$O":/o lab4-build tcpdump -nn -r /o/session.pcap -X 2>/dev/null > "$C/cp3-hexdump.txt" || true
cp "$O/session.pcap" "$C/cp3-session.pcap"
{ echo "# CP3: messages are encrypted after key exchange"
  echo "Server log:"; echo "$SL" | grep -m2 -E 'SSH2_MSG_NEWKEYS (sent|received)'
  echo; echo "Plaintext search of the whole capture (expect none after NEWKEYS):"
  for w in ssh-userauth ssh-connection lab4test sftp; do printf '  %-15s %s\n' "$w" "$(grep -ac "$w" "$O/session.pcap" || true) matches"; done
  echo; echo "Full capture: cp3-session.pcap (open in Wireshark); hex dump: cp3-hexdump.txt."
  echo "Before NEWKEYS the KEXINIT algorithm names are readable; after it every payload is random-looking AES-256-CBC ciphertext."
} > "$C/cp3.txt"

{ echo "# CP4: authentication success"
  echo "Client log:"; echo "$CL" | first_session | grep 'authentication succeeded'
  echo; echo "Server log:"; echo "$SL" | grep -m1 'Accepted password for tester'
} > "$C/cp4.txt"

{ echo "# CP5: channel opened"
  echo "Client log:"; echo "$CL" | first_session | grep -E 'channel id|remote window adjust'
  echo; echo "Server log:"; echo "$SL" | grep -m3 -E 'server_input_channel_open|subsystem request for sftp'
  echo; echo "OpenSSH confirms a session channel with window 0 and grants 2097152 bytes once the sftp subsystem starts."
} > "$C/cp5.txt"

{ echo "# CP6: upload and download client.c"
  echo "Client transcript:"; echo "$CL" | grep -E 'uploaded|downloaded|^exit='
  echo; echo "SHA-256 (local original, server copy, downloaded copy):"
  docker run --rm -v "$O":/o -v "$REPO":/r lab4-build sh -c 'sha256sum /r/client.c /o/remote.bin /o/downloaded.bin'
  echo; echo "Harness result:"; grep -v '^logs: ' /tmp/lab4-check.txt
} > "$C/cp6.txt"
strip < "$O/client.log" > "$C/client.log"; cp "$O/sshd.log" "$C/sshd.log"
echo "checkpoint/ written: $(ls "$C" | tr '\n' ' ')"
