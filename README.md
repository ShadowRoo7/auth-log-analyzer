# Auth Log Analyzer

Production-grade Bash tooling for detecting SSH brute-force attacks in
`/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS).

## Status

| Step | Component | State |
|------|-----------|-------|
| 1 | `gen_mock_logs.sh` | ✅ complete and verified |
| 2 | `auth_log_analyzer.sh` | ⏳ not started |

## `gen_mock_logs.sh` — mock log generator

Generates deterministic, realistic authentication logs so the analyzer can be
developed and tested without root access or real production logs.

```bash
./gen_mock_logs.sh -o ./mock-logs --seed 42 --hours 12
```

### Why timestamps are stored as epochs

Every event is held internally as an integer UNIX epoch and converted to a
display format only at write time. This matters for testing the 5-minute rule:

- **Exact interval arithmetic.** A planted "10 attempts inside 240s" is
  literally 10 epochs spanning 240 seconds, not a month-length approximation.
- **No year in the output — deliberately.** Real BSD syslog lines read
  `Oct 20 08:30:53 host sshd[1234]: ...`. The generator reproduces that
  exactly, forcing the analyzer to infer the year and handle the Dec 31 → Jan 1
  rollover. The default 12-hour span usually crosses midnight.
- **Sorted by `(epoch, sequence)`.** The sequence breaks ties between
  multi-line events sharing a timestamp, so Debian's `Invalid user X from IP`
  sorts before `Failed password for invalid user X ...`.

### Window semantics

A window is the closed interval `[t, t+300]`. Two attempts share a window iff
their epochs differ by **≤ 300 seconds**. An IP is flagged iff some 5-minute
window contains **more than 10** attempts (11 or more) — exactly 10 is *not* a
violation. These same rules are used to compute the ground truth, so the
generator and the analyzer are held to one definition.

### Counting contract

Only this line counts as a failed attempt:

```
Failed password for [invalid user ]<user> from <ip> port <n> ssh2
```

These deliberately do **not** count:

| Line | Why |
|------|-----|
| `Invalid user <u> from <ip>` | Debian preamble — the *same* event |
| `pam_unix(sshd:auth): authentication failure` | duplicate of the same event |
| `error: maximum authentication attempts exceeded` | distinct event type |

The last two are opt-in (`--pam-duals`, `--maxauth`) to prove the analyzer
does not double-count them.

### Planted test scenarios

Each scenario is verified against independently computed ground truth in
`expected.tsv`.

| Scenario | IP | Pattern | Expected |
|----------|----|---------|----------|
| brute | 203.0.113.10 | 60 fails, 3s apart | FLAGGED |
| small-burst | 203.0.113.11 | 14 fails, 2s apart | FLAGGED |
| edge-exactly-10 | 198.51.100.20 | 10 fails in 240s | **CLEAN** |
| edge-exactly-11 | 198.51.100.21 | 11 fails in 260s | FLAGGED |
| slow-drip | 192.0.2.30 | 48 fails, 360s apart (4h) | **CLEAN** |
| split-window | 192.0.2.31 | 10 in 120s, then 2 at +600s | **CLEAN** |
| single | 192.0.2.32 | 1 isolated fail | CLEAN |

`slow-drip` and `split-window` are the pair that distinguishes a correct
rolling-window implementation from a naive "count all failures for this IP"
one — both have totals above 10 but no 5-minute window above 10.

### Output files

| File | Contents |
|------|----------|
| `auth.log` | Debian/Ubuntu style |
| `secure` | RHEL/CentOS style (Debian-only lines suppressed) |
| `events.tsv` | every SSH auth event: epoch, ISO time, IP, user, kind, countable |
| `attempts.tsv` | only the events that count as failed attempts |
| `expected.tsv` | per-IP truth: total, max in 5-min window, expected verdict |
| `scenarios.tsv` | the planted scenarios and their intent |
| `manifest.txt` | run metadata, window semantics, counting contract |

### Options

```
-o, --output DIR        Output directory (default: ./mock-logs)
-f, --format FMT        debian | rhel | both | rfc5424   (default: both)
-s, --seed N            RNG seed; same seed == identical output
-h, --hours N           Length of the generated log span (default: 12)
-e, --end TIMESTAMP     End time, "YYYY-MM-DD HH:MM:SS" (default: now)
-a, --attackers N       Extra random burst attackers (default: 3)
-n, --noise N           Background failed attempts (default: 150)
    --successes N       Successful logins (default: 40)
    --pam-duals         Also emit paired pam_unix auth-failure lines
    --maxauth           Also emit "maximum authentication attempts exceeded"
    --hostname NAME     Hostname embedded in log lines (default: mockhost)
    --no-irrelevant      Skip cron/sudo/systemd/kernel noise lines
```

### Determinism

The same `--seed` always produces byte-identical output. A hand-rolled LCG is
used rather than `$RANDOM`, which is reseeded in subshells and would make
output depend on how the script is invoked.

Every IP in the fixture is unique — a collision would silently change the
ground truth and make the fixture unreliable as a test oracle.
