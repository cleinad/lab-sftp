# Lab 4 test harness
`harness/check.sh [repo_dir]` builds the client in Ubuntu 24.04 (Docker) and runs it against OpenSSH 9.6 with the lab's legacy algorithms re-enabled (`sshd_lab4.conf`). Session 1 uploads `client.c`; session 2 downloads it into an empty directory. Grades CP1–CP6 from the server's DEBUG3 log, a pcap and file comparisons. Logs land in `harness/out/` (`client.log`, `sshd.log`, `session.pcap`).
- `REFERENCE=1` runs stock `sftp` restricted to the lab algorithms instead of `./client`; it must report ALL_PASS, which proves the harness.
- `CFLAGS_EXTRA="-fsanitize=address -g"` builds with ASan.
- Test account: `tester` / `lab4test` (container only).
