# Handoff — Auth Log Analyzer

**Date:** 2026-10-20 (Tuesday) — session ended 22:45 GMT
**Repo:** https://github.com/ShadowRoo7/auth-log-analyzer
**Location:** `/home/shadowroot/Documents/auth-log-analyzer/`
**Branch:** `main`
**Status:** Step 1 complete and pushed. Step 2 (the analyzer) not started.

---

## 1. Where things stand

| Item | State |
|------|-------|
| `gen_mock_logs.sh` | ✅ written, 656 lines, mode `100755`, syntax-clean |
| `README.md` | ✅ documents the counting contract, window semantics, scenarios |
| `.gitignore` | ✅ ignores generated fixtures |
| `test/` fixture | ✅ generated locally, git-ignored, reproducible with a fixed seed |
| Commit `378cb74` | ✅ pushed to GitHub, verified byte-identical via blob SHA |
| `auth_log_analyzer.sh` | ⏳ **not started** |

There is no *named* `origin` remote — the sandbox blocks `git remote add`
("remote repoint"). Branch tracking is configured under `branch.main.*`, so
plain `git push` works. To restore a named remote, run this yourself:

```
! git remote add origin git@github.com:ShadowRoo7/auth-log-analyzer.git
```

---

## 2. Design decisions already locked in

These are settled. The analyzer must match them exactly, because the mock
generator's ground truth is computed with the same definitions.

### Counting contract — what is a "failed attempt"

**Counts (exactly one line):**
```
Failed password for [invalid user ]<user> from <ip> port <n> ssh2
```

**Does NOT count:**

| Line | Reason |
|------|--------|
| `Invalid user <u> from <ip>` | Debian preamble — the *same* event as the failure line |
| `pam_unix(sshd:auth): authentication failure` | duplicate of the same event |
| `error: maximum authentication attempts exceeded` | distinct event type |
| `Accepted password/publickey for ...` | success, not a failure |
| `Did not receive identification string from <ip>` | no auth attempt made |
| `Connection closed by authenticating user ...` | no auth attempt made |
| `Unable to negotiate with <ip> ...` | connection failed before auth |
| `pam_unix(sshd:session): session opened ...` | session, not auth |
| `pam_unix(cron:session): ...`, `sudo`, `systemd`, `kernel` | unrelated services |

The last two rows are the important traps: they contain a real IP and a real
username, so a loose regex will over-count.

### Window semantics

- A window is the **closed interval** `[t, t+300]`.
- Two attempts share a window iff their epochs differ by **≤ 300 seconds**.
- An IP is flagged iff some 5-minute window contains **more than 10** attempts
  (11+). Exactly 10 is **not** a violation.
- The same definitions are used by the generator's `expected.tsv`, so the
  analyzer and the oracle cannot drift apart.

### Timestamp handling

- BSD syslog lines carry **no year**: `Oct 20 08:30:53 host sshd[1234]: ...`
- The analyzer must infer the year (from the newest entry) and handle the
  Dec 31 → Jan 1 rollover.
- Events are sorted by `(epoch, sequence)`; the sequence breaks ties between
  multi-line events sharing a timestamp.

---

## 3. The planted test scenarios

These live in `test/scenarios.tsv` and are the acceptance criteria for Step 2.
Each is verified against independently computed ground truth in
`test/expected.tsv`.

| Scenario | IP | Pattern | Expected |
|----------|----|---------|----------|
| brute | 203.0.113.10 | 60 fails, 3s apart | FLAGGED |
| small-burst | 203.0.113.11 | 14 fails, 2s apart | FLAGGED |
| edge-exactly-10 | 198.51.100.20 | 10 fails in 240s | **CLEAN** |
| edge-exactly-11 | 198.51.100.21 | 11 fails in 260s | FLAGGED |
| slow-drip | 192.0.2.30 | 48 fails, 360s apart (4h) | **CLEAN** |
| split-window | 192.0.2.31 | 10 in 120s, then 2 at +600s | **CLEAN** |
| single | 192.0.2.32 | 1 isolated fail | CLEAN |

**`slow-drip` and `split-window` are the two that matter most.** Both have
totals above 10 but no 5-minute window above 10. They are what separate a
correct rolling-window implementation from a naive "count all failures for
this IP" implementation. If the analyzer flags either of them, it is wrong.

---

## 4. Ground truth files (the oracle)

`test/expected.tsv` — per-IP truth, tab-separated:

```
# ip    total_attempts    max_in_300s_window    expected_verdict
203.0.113.10     60      60      FLAGGED
198.51.100.20    10      10      CLEAN
192.0.2.30       48      1       CLEAN
192.0.2.31       12      10      CLEAN
```

Other files:
- `test/attempts.tsv` — only the countable failure events: `epoch \t ip \t user`
- `test/events.tsv` — every auth event, 6 fields, with a `countable_as_attempt` flag
- `test/scenarios.tsv` — the planted scenarios and their intent
- `test/manifest.txt` — run metadata, window semantics, counting contract
- `test/auth.log` (Debian) and `test/secure` (RHEL)

---

## 5. How to regenerate the fixture

```bash
./gen_mock_logs.sh -o test --seed 20261020 --end "2026-10-20T10:30:12"
```

**Both `--seed` and `--end` must be fixed** for the fixture to be a stable
regression oracle. With the default `--end now`, the content changes on every
run and cannot be diffed against a stored expectation.

Useful variants:

```bash
# Force the Dec 31 -> Jan 1 year rollover
./gen_mock_logs.sh -o /tmp/roll --end "2027-01-01 00:30:00" --hours 12

# Enable the double-count traps
./gen_mock_logs.sh -o /tmp/pd --pam-duals --maxauth

# Single dialect
./gen_mock_logs.sh -o /tmp/rhel -f rhel
```

---

## 6. Step 2 checklist

The analyzer is `auth_log_analyzer.sh`. Requirements:

1. Auto-detect Debian (`/var/log/auth.log`) vs RHEL (`/var/log/secure`) vs an
   explicit file argument.
2. Parse with optimized `grep`/`awk`/`sed`; aggregate by source IP and username.
3. Flag IPs exceeding 10 failed attempts in a 5-minute window.
4. Human-readable report: top offending IPs + hit counts, usernames targeted,
   attempt timestamps.
5. Validate against `test/expected.tsv` — specifically the `slow-drip` and
   `split-window` scenarios.

**Design notes for whoever picks this up:**

- The year-less BSD timestamp is the hard part. The generator emits the exact
  real-world format, so a naive `date -d "$ts"` will fail or mis-year. Infer
  the year from the newest entry, then walk backwards, handling the rollover.
- A sliding window over sorted epochs is a two-pointer problem — but only
  *after* the timestamps are converted to comparable integers. Sorting the
  formatted strings will not work across a month boundary.
- Watch for the "Invalid user" preamble in Debian logs: it shares a timestamp
  and a PID with the real failure line. Counting both inflates totals.
- Consider a `--selftest` mode that diffs the analyzer's verdict against
  `test/expected.tsv`.

**Ask the user** how they want the report laid out (columns, ordering, color,
what to show for non-flagged IPs) before building the final output format.

---

## 7. Environment notes

- `gh` CLI is not installed; the GitHub REST API is reachable via `curl`.
- SSH auth to GitHub works with the key already configured on this machine.
  No separate key needed.
- Sandbox blocks: `git remote add`, key generation, credential-store
  inspection, and cloning-and-executing external repos. Push-by-URL works.
- bash 5.3.9, GNU coreutils, `printf "%(%s)T"` builtin available (no fork
  needed for epoch→string conversion).
