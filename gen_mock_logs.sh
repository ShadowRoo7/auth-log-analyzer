#!/usr/bin/env bash
#
# gen_mock_logs.sh — Generate realistic mock authentication logs so that
#                     auth_log_analyzer.sh can be developed and tested without
#                     root access or real production logs.
#
# The generator is fully deterministic: the same --seed always produces a
# byte-identical set of files. That is what makes it usable as a regression
# fixture for the analyzer.
#
# Outputs (in --output DIR):
#   auth.log      Debian/Ubuntu style  (/var/log/auth.log)
#   secure        RHEL/CentOS style    (/var/log/secure)
#   events.tsv    every SSH auth event: epoch, ISO time, IP, user, kind
#   attempts.tsv  only the lines that count as a failed attempt (ground truth)
#   expected.tsv  per-IP expected verdict: total fails, max fails in any
#                 5-minute window, and whether the analyzer should flag it
#   scenarios.tsv human-readable description of the scenario that was planted
#   manifest.txt  run metadata (seed, time span, format, window semantics)
#
# ---------------------------------------------------------------------------
# TIMESTAMP STRUCTURE (the important part for testing the 5-minute rule)
# ---------------------------------------------------------------------------
# The generator keeps every event as an integer UNIX epoch internally and only
# converts to a display format at write time. This is deliberate:
#
#   1. The 5-minute rule is an interval rule, and intervals are trivial to
#      compute in epoch seconds but painful in calendar strings. Keeping the
#      canonical value as an epoch means the planted scenarios are exact:
#      "10 attempts inside 240s" is literally 10 epochs inside a 240s span,
#      not an approximation that depends on the month length.
#
#   2. Real syslog lines carry NO YEAR ("Oct 20 20:18:54"). The analyzer will
#      therefore have to infer the year from the newest entry and handle the
#      Dec 31 -> Jan 1 rollover. To exercise that path the default log span
#      is 12 hours, which usually crosses midnight and therefore produces
#      two different day-of-month values with no year attached.
#
#   3. Events are sorted by (epoch, sequence) before rendering, so the file
#      is in true chronological order even though scenarios are generated
#      scenario-by-scenario. The sequence number breaks ties between the
#      multi-line events that share a timestamp (e.g. Debian's "Invalid user X
#      from 1.2.3.4" must precede "Failed password for invalid user X ...").
#
# Window semantics used throughout (documented in manifest.txt):
#   A window is the closed interval [t, t + 300]. Two attempts are "inside
#   the same 5-minute window" iff their epochs differ by <= 300 seconds.
#   An IP is flagged iff some 5-minute window contains MORE THAN 10
#   attempts (i.e. 11 or more). Exactly 10 is NOT a violation.
#
set -euo pipefail
export LC_ALL=C

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OUT_DIR="./mock-logs"
FORMAT="both"          # debian | rhel | both | rfc5424
SEED=20261020
SPAN_HOURS=12
END_SPEC="now"         # "now" or "YYYY-MM-DD HH:MM:SS"
EXTRA_ATTACKERS=3      # additional randomly-sized burst attackers
NOISE_ATTEMPTS=150     # failed attempts from benign/one-off sources
NOISE_SUCCESSES=40     # successful logins
PAM_DUALS=0            # emit paired pam_unix(sshd:auth) failure lines
MAXAUTH=0              # emit "maximum authentication attempts exceeded" lines
HOSTNAME="mockhost"
EMIT_IRRELEVANT=1      # emit cron/sudo/systemd/kernel lines
WINDOW_SECONDS=300     # window length used for ground truth
THRESHOLD=10           # > this many in a window == violation

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: gen_mock_logs.sh [OPTIONS]

Generate deterministic mock auth logs for testing an auth log analyzer.

Options:
  -o, --output DIR        Output directory (default: ./mock-logs)
  -f, --format FMT        debian | rhel | both | rfc5424   (default: both)
  -s, --seed N            RNG seed; same seed == identical output (default: 20261020)
  -h, --hours N           Length of the generated log span (default: 12)
  -e, --end TIMESTAMP     End time, "YYYY-MM-DD HH:MM:SS" (default: now)
  -a, --attackers N       Extra random burst attackers beyond the fixed set (default: 3)
  -n, --noise N           Background failed attempts from benign IPs (default: 150)
      --successes N       Successful logins (default: 40)
      --pam-duals         Also emit paired "pam_unix(sshd:auth): authentication
                          failure" lines. These are the SAME event as the
                          "Failed password" line, so they are NOT counted in
                          ground truth -- the flag exists to prove the analyzer
                          does not double-count them.
      --maxauth           Also emit "maximum authentication attempts exceeded"
                          lines. Also not counted in ground truth.
      --hostname NAME     Hostname embedded in log lines (default: mockhost)
      --no-irrelevant      Skip cron/sudo/systemd/kernel noise lines
      --help              Show this help

Example:
  ./gen_mock_logs.sh -o /tmp/ml --format both --seed 42 --hours 12
EOF
}

die() { printf 'gen_mock_logs.sh: %s\n' "$*" >&2; exit 1; }

# need_val OPTION VALUE -- echoes VALUE, or dies if VALUE is absent/empty.
# A command substitution would run this in a subshell, so the check is done
# inline in the caller instead.
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)     [ -n "${2-}" ] || die "option '$1' requires a value"; OUT_DIR="$2"; shift 2 ;;
        -f|--format)     [ -n "${2-}" ] || die "option '$1' requires a value"; FORMAT="$2"; shift 2 ;;
        -s|--seed)       [ -n "${2-}" ] || die "option '$1' requires a value"; SEED="$2"; shift 2 ;;
        -h|--hours)      [ -n "${2-}" ] || die "option '$1' requires a value"; SPAN_HOURS="$2"; shift 2 ;;
        -e|--end)        [ -n "${2-}" ] || die "option '$1' requires a value"; END_SPEC="$2"; shift 2 ;;
        -a|--attackers)  [ -n "${2-}" ] || die "option '$1' requires a value"; EXTRA_ATTACKERS="$2"; shift 2 ;;
        -n|--noise)      [ -n "${2-}" ] || die "option '$1' requires a value"; NOISE_ATTEMPTS="$2"; shift 2 ;;
        --successes)     [ -n "${2-}" ] || die "option '$1' requires a value"; NOISE_SUCCESSES="$2"; shift 2 ;;
        --pam-duals)     PAM_DUALS=1; shift ;;
        --maxauth)       MAXAUTH=1; shift ;;
        --hostname)      [ -n "${2-}" ] || die "option '$1' requires a value"; HOSTNAME="$2"; shift 2 ;;
        --no-irrelevant)  EMIT_IRRELEVANT=0; shift ;;
        --help)          usage; exit 0 ;;
        *)               die "unknown option: $1 (try --help)" ;;
    esac
done

case "$FORMAT" in
    debian|rhel|both|rfc5424) ;;
    *) die "invalid --format '$FORMAT' (want debian|rhel|both|rfc5424)" ;;
esac

# ---------------------------------------------------------------------------
# Deterministic RNG
# ---------------------------------------------------------------------------
# A hand-rolled LCG is used instead of $RANDOM because $RANDOM is reseeded in
# subshells, which would make output depend on how the script is invoked.
# This LCG is pure bash arithmetic: no forks, fully reproducible.
LCG_STATE=$(( SEED & 0x7fffffff ))
lcg() {
    LCG_STATE=$(( (LCG_STATE * 1103515245 + 12345) & 0x7fffffff ))
}
# rnd_range LO HI -> result in $REPLY (high bits only, avoids LCG low-bit bias)
rnd_range() {
    lcg
    REPLY=$(( $1 + ((LCG_STATE >> 8) % ($2 - $1 + 1)) ))
}
# pick ARRAY_NAME -> result in $REPLY
pick() {
    local -n _arr="$1"
    rnd_range 0 $((${#_arr[@]} - 1))
    REPLY="${_arr[$REPLY]}"
}

# ---------------------------------------------------------------------------
# Time base
# ---------------------------------------------------------------------------
if [ "$END_SPEC" = "now" ]; then
    END_EPOCH=$(printf "%(%s)T" -1)
else
    END_EPOCH=$(date -d "$END_SPEC" +%s 2>/dev/null) \
        || die "could not parse --end '$END_SPEC'"
fi
START_EPOCH=$(( END_EPOCH - SPAN_HOURS * 3600 ))

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
KNOWN_USERS=(root admin ubuntu oracle postgres git pi deploy user ftp \
             jenkins mysql www-data ec2-user centos apache tomcat)
TARGET_USERS=(root admin test oracle postgres git pi ftp jenkins mysql \
              hadoop weblogic tomcat nobody service backup deploy sysadmin \
              operator user www ubuntu centos ec2-user db database zabbix)
DOC_IP_BLOCKS=("203.0.113" "198.51.100" "192.0.2")
INTERNAL_IP_BLOCKS=("10.0.0" "192.168.1" "172.16.0")

# ---------------------------------------------------------------------------
# Event store
#
# Parallel arrays; events are appended in generation order and sorted by
# (epoch, seq) before rendering.
# ---------------------------------------------------------------------------
declare -a EV_EPOCH EV_SEQ EV_PROG EV_PID EV_BODY EV_KIND EV_IP EV_USER EV_COUNTABLE

EV_EPOCH=(); EV_SEQ=(); EV_PROG=(); EV_PID=(); EV_BODY=()
EV_KIND=(); EV_IP=(); EV_USER=(); EV_COUNTABLE=()
SEQ=0

# add_event EPOCH KIND PROG PID BODY IP USER COUNTABLE
add_event() {
    SEQ=$((SEQ + 1))
    EV_EPOCH+=("$1"); EV_KIND+=("$2"); EV_PROG+=("$3"); EV_PID+=("$4")
    EV_BODY+=("$5"); EV_IP+=("$6"); EV_USER+=("$7"); EV_COUNTABLE+=("$8")
    EV_SEQ+=("$SEQ")
}

# ---------------------------------------------------------------------------
# IP allocation
#
# Every IP used in the fixture is unique. If a random IP collided with an
# existing one, ground truth (expected.tsv) could silently change, which
# would make the fixture unreliable as a test oracle.
# ---------------------------------------------------------------------------
declare -A USED_IPS
alloc_ip() {
    local ip
    while :; do
        lcg
        local blk="${DOC_IP_BLOCKS[$(( (LCG_STATE >> 8) % ${#DOC_IP_BLOCKS[@]} ))]}"
        lcg
        ip="$blk.$(( (LCG_STATE >> 8) % 254 + 1 ))"
        if [ ! -v "USED_IPS[$ip]" ]; then
            USED_IPS[$ip]=1
            printf '%s' "$ip"
            return 0
        fi
    done
}

# ---------------------------------------------------------------------------
# Line builders (OpenSSH wording; dialect differences are applied at render
# time, so one event set can be written as either Debian or RHEL)
# ---------------------------------------------------------------------------
sshd_pid()  { rnd_range 1000 32000; }
sshd_port() { rnd_range 30000 65000; }

# emit_failure EPOCH IP USER
#
# The "Failed password" line is the ONLY event counted as an attempt.
# Debian additionally emits an "Invalid user X from IP" preamble for
# unknown usernames (same pid, same timestamp) -- this is a parser trap
# because a naive analyzer may count it as a second failure.
emit_failure() {
    local epoch=$1 ip=$2 user=$3
    local pid port
    sshd_pid;  pid=$REPLY
    sshd_port; port=$REPLY
    local known=0 u
    for u in "${KNOWN_USERS[@]}"; do
        [ "$u" = "$user" ] && { known=1; break; }
    done

    # Debian-style "Invalid user" preamble. Stored as its own event so that
    # the renderer can suppress it for RHEL output; counted as 0 attempts.
    # Added FIRST so that it sorts before the "Failed password" line that
    # shares its timestamp -- that is the real syslog ordering.
    if [ "$known" -eq 0 ]; then
        add_event "$epoch" INVALID_USER "sshd[$pid]" "$pid" \
            "Invalid user $user from $ip" "$ip" "$user" 0
    fi

    local text
    if [ "$known" -eq 1 ]; then
        text="Failed password for $user from $ip port $port ssh2"
    else
        text="Failed password for invalid user $user from $ip port $port ssh2"
    fi
    add_event "$epoch" FAIL_PASSWORD "sshd[$pid]" "$pid" "$text" "$ip" "$user" 1

    if [ "$MAXAUTH" -eq 1 ]; then
        sshd_pid;  pid=$REPLY
        sshd_port; port=$REPLY
        add_event "$epoch" MAXAUTH "sshd[$pid]" "$pid" \
            "error: maximum authentication attempts exceeded for $user from $ip port $port ssh2 [preauth]" \
            "$ip" "$user" 0
    fi

    if [ "$PAM_DUALS" -eq 1 ]; then
        sshd_pid; pid=$REPLY
        add_event "$epoch" PAM_FAIL "sshd[$pid]" "$pid" \
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=$ip user=$user" \
            "$ip" "$user" 0
    fi
}

# emit_success EPOCH IP USER METHOD
emit_success() {
    local epoch=$1 ip=$2 user=$3 method=$4
    local pid port
    sshd_pid;  pid=$REPLY
    sshd_port; port=$REPLY
    if [ "$method" = "password" ]; then
        add_event "$epoch" ACCEPT_PASSWORD "sshd[$pid]" "$pid" \
            "Accepted password for $user from $ip port $port ssh2" "$ip" "$user" 0
    else
        add_event "$epoch" ACCEPT_PUBLICKEY "sshd[$pid]" "$pid" \
            "Accepted publickey for $user from $ip port $port ssh2: RSA SHA256:AAAAFakeKeyMaterial000000000000000000" \
            "$ip" "$user" 0
    fi
    # Debian-style session-open line; suppressed at render time for RHEL.
    sshd_pid; pid=$REPLY
    add_event "$epoch" SESSION_OPENED "sshd[$pid]" "$pid" \
        "pam_unix(sshd:session): session opened for user $user by (uid=0)" "$ip" "$user" 0
}

# emit_noise_line EPOCH -- carries an IP but is NOT an auth failure
emit_noise_line() {
    local epoch=$1
    local ip port pid
    lcg;     ip="$(alloc_ip)"
    sshd_port; port=$REPLY
    sshd_pid;  pid=$REPLY
    lcg; local pick_num=$(( LCG_STATE % 7 ))
    case "$pick_num" in
        0) add_event "$epoch" DISCONNECT "sshd[$pid]" "$pid" \
               "Connection closed by authenticating user root $ip port $port [preauth]" "$ip" "root" 0 ;;
        1) add_event "$epoch" NOID "sshd[$pid]" "$pid" \
               "Did not receive identification string from $ip" "$ip" "" 0 ;;
        2) add_event "$epoch" NEGOTIATE "sshd[$pid]" "$pid" \
               "Unable to negotiate with $ip port $port: no matching key exchange found. Their offer: diffie-hellman-group1-sha1" \
               "$ip" "" 0 ;;
        3) add_event "$epoch" INPUT_INVALID "sshd[$pid]" "$pid" \
               "input_userauth_request: invalid user test" "$ip" "test" 0 ;;
        4) add_event "$epoch" BANNED "sshd[$pid]" "$pid" \
               "not allowed because user $ip is banned" "$ip" "" 0 ;;
        5) add_event "$epoch" REVERSE_LOOKUP "sshd[$pid]" "$pid" \
               "reverse mapping checking getaddrinfo for $ip [FAILED]: possible address spoofing" "$ip" "" 0 ;;
        6) add_event "$epoch" UNKNOWN_OPT "sshd[$pid]" "$pid" \
               "Unknown option: -o ForceCommand" "$ip" "" 0 ;;
    esac
}

# emit_irrelevant EPOCH -- no IP, no auth semantics
emit_irrelevant() {
    local epoch=$1
    local pid
    sshd_pid; pid=$REPLY
    lcg; local pick_num=$(( LCG_STATE % 5 ))
    case "$pick_num" in
        0) add_event "$epoch" IRRELEVANT_CRON "CRON[$pid]" "$pid" \
               "pam_unix(cron:session): session opened for user root by (uid=0)" "" "" 0 ;;
        1) add_event "$epoch" IRRELEVANT_SUDO "sudo" "0" \
               "pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1001 euid=0 tty=/dev/pts/0 ruser= rhost= user=alice" \
               "" "alice" 0 ;;
        2) add_event "$epoch" IRRELEVANT_SYSTEMD "systemd[1]" "1" \
               "Started OpenBSD Secure Shell server." "" "" 0 ;;
        3) add_event "$epoch" IRRELEVANT_KERNEL "kernel" "0" \
               "[12345.678901] TCP: request_sock_TCP: Possible SYN flooding on port 22." "" "" 0 ;;
        4) add_event "$epoch" IRRELEVANT_SU "su[$pid]" "$pid" \
               "pam_unix(su:session): session closed for user root" "" "root" 0 ;;
    esac
}

# ---------------------------------------------------------------------------
# Scenario table
#
# Each scenario plants a precise, purposeful failure pattern so the analyzer's
# 5-minute rule can be verified against known ground truth.
# ---------------------------------------------------------------------------
declare -a SCEN_NAME SCEN_IP SCEN_MODE SCEN_COUNT SCEN_VERDICT SCEN_NOTE

record_scenario() {
    SCEN_NAME+=("$1"); SCEN_IP+=("$2"); SCEN_MODE+=("$3")
    SCEN_COUNT+=("$4"); SCEN_VERDICT+=("$5"); SCEN_NOTE+=("$6")
}

# plant_burst START COUNT STEP IP
#   Plants COUNT failures spaced STEP seconds apart. The epoch of the LAST
#   attempt is returned in $PLANT_LAST (a global, NOT stdout -- printing
#   would force a subshell and discard the event arrays).
plant_burst() {
    local start=$1 count=$2 step=$3 ip=$4
    local e=$start i
    for (( i = 0; i < count; i++ )); do
        pick TARGET_USERS
        emit_failure "$e" "$ip" "$REPLY"
        e=$(( e + step ))
    done
    PLANT_LAST=$(( e - step ))
}

# --- fixed scenario IPs (documentation ranges, deterministic) ---------------
IP_BRUTE="203.0.113.10"     # hard brute force
IP_SMALL="203.0.113.11"     # small burst, still over threshold
IP_EDGE10="198.51.100.20"   # exactly 10 in window -> NOT flagged
IP_EDGE11="198.51.100.21"   # exactly 11 in window -> FLAGGED
IP_DRIP="192.0.2.30"        # slow drip, high total, no window over 10 -> NOT flagged
IP_SPLIT="192.0.2.31"       # 10 inside window + 2 far away -> NOT flagged
IP_SINGLE="192.0.2.32"      # one lone failure -> NOT flagged

for ip in "$IP_BRUTE" "$IP_SMALL" "$IP_EDGE10" "$IP_EDGE11" \
          "$IP_DRIP" "$IP_SPLIT" "$IP_SINGLE"; do
    USED_IPS[$ip]=1
done

# --- scenario 1: hard brute force -----------------------------------------
plant_burst $(( START_EPOCH + 1800 )) 60 3 "$IP_BRUTE"
record_scenario "brute" "$IP_BRUTE" "burst" 60 "FLAGGED" \
    "60 failures spaced 3s apart (~3 min span); max 5-min window far above threshold"

# --- scenario 2: small burst ------------------------------------------------
plant_burst $(( START_EPOCH + 3600 )) 14 2 "$IP_SMALL"
record_scenario "small-burst" "$IP_SMALL" "burst" 14 "FLAGGED" \
    "14 failures spaced 2s apart; just over threshold, tests the >10 boundary"

# --- scenario 3: exactly 10 in window (must NOT be flagged) -----------------
plant_burst $(( START_EPOCH + 5400 )) 10 26 "$IP_EDGE10"
record_scenario "edge-exactly-10" "$IP_EDGE10" "boundary" 10 "CLEAN" \
    "10 failures inside 240s; hits the threshold but never EXCEEDS it -> must NOT be flagged"

# --- scenario 4: exactly 11 in window (must be flagged) --------------------
plant_burst $(( START_EPOCH + 7200 )) 11 26 "$IP_EDGE11"
record_scenario "edge-exactly-11" "$IP_EDGE11" "boundary" 11 "FLAGGED" \
    "11 failures inside 260s; one over the threshold -> must be flagged"

# --- scenario 5: slow drip --------------------------------------------------
# 48 failures every 360s over 4 hours: a high total count, but never more
# than one attempt inside any 5-minute window. This is the scenario that
# separates a correct rolling-window implementation from a naive
# "count all failures for this IP" implementation.
plant_burst $(( START_EPOCH + 900 )) 48 360 "$IP_DRIP"
record_scenario "slow-drip" "$IP_DRIP" "drip" 48 "CLEAN" \
    "48 failures spaced 360s apart; total is high but no 5-min window exceeds 10"

# --- scenario 6: split window ----------------------------------------------
# 10 failures packed into 120s, then 2 more 600s later. Total = 12 (a naive
# implementation would flag it), but the densest 5-minute window holds 10.
plant_burst $(( START_EPOCH + 1200 )) 10 13 "$IP_SPLIT"
plant_burst $(( PLANT_LAST + 600 )) 2 5 "$IP_SPLIT"
record_scenario "split-window" "$IP_SPLIT" "split" 12 "CLEAN" \
    "10 failures in 120s then 2 six minutes later; total 12 but max 5-min window = 10"

# --- scenario 7: lone failure ----------------------------------------------
plant_burst $(( START_EPOCH + 2400 )) 1 0 "$IP_SINGLE"
record_scenario "single" "$IP_SINGLE" "single" 1 "CLEAN" \
    "one isolated failure; normal background noise, must NOT be flagged"

# --- extra random burst attackers ------------------------------------------
for (( a = 0; a < EXTRA_ATTACKERS; a++ )); do
    ip="$(alloc_ip)"
    rnd_range 15 45; count=$REPLY
    rnd_range 1 4;   step=$REPLY
    plant_burst $(( START_EPOCH + (a + 1) * 900 )) "$count" "$step" "$ip"
    record_scenario "random-burst-$(( a + 1 ))" "$ip" "burst" "$count" "FLAGGED" \
        "randomly sized burst of $count failures spaced ${step}s apart"
done

# ---------------------------------------------------------------------------
# Background noise
# ---------------------------------------------------------------------------
# One-off failures from unrelated hosts. Each gets a distinct IP so that no
# IP accidentally accumulates a window violation.
for (( n = 0; n < NOISE_ATTEMPTS; n++ )); do
    ip="$(alloc_ip)"
    lcg
    offset=$(( START_EPOCH + ((LCG_STATE >> 8) % (SPAN_HOURS * 3600)) ))
    pick TARGET_USERS
    emit_failure "$offset" "$ip" "$REPLY"
done

# Successful logins from internal hosts.
for (( n = 0; n < NOISE_SUCCESSES; n++ )); do
    pick INTERNAL_IP_BLOCKS
    blk=$REPLY
    lcg
    ip="$blk.$(( (LCG_STATE >> 8) % 254 + 1 ))"
    lcg
    offset=$(( START_EPOCH + ((LCG_STATE >> 8) % (SPAN_HOURS * 3600)) ))
    pick KNOWN_USERS
    user=$REPLY
    lcg
    if [ $(( LCG_STATE % 2 )) -eq 0 ]; then
        emit_success "$offset" "$ip" "$user" "password"
    else
        emit_success "$offset" "$ip" "$user" "publickey"
    fi
done

# IP-bearing but non-auth lines, and totally irrelevant lines.
for (( n = 0; n < NOISE_ATTEMPTS; n++ )); do
    lcg
    offset=$(( START_EPOCH + ((LCG_STATE >> 8) % (SPAN_HOURS * 3600)) ))
    emit_noise_line "$offset"
    if [ "$EMIT_IRRELEVANT" -eq 1 ]; then
        emit_irrelevant "$offset"
    fi
done

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

# Sort indices by (epoch, seq).
IDX_FILE=$(mktemp)
for (( i = 0; i < SEQ; i++ )); do
    printf '%s\t%09d\t%s\n' "${EV_EPOCH[$i]}" "${EV_SEQ[$i]}" "$i" >> "$IDX_FILE"
done
mapfile -t SORTED_IDX < <(sort -k1,1n -k2,2n "$IDX_FILE" | cut -f3)
rm -f "$IDX_FILE"

# render_line IDX DIALECT -> prints one log line
render_line() {
    local i=$1 dialect=$2
    local epoch=${EV_EPOCH[$i]} prog=${EV_PROG[$i]} pid=${EV_PID[$i]} body=${EV_BODY[$i]}
    if [ "$FORMAT" = "rfc5424" ]; then
        printf '%s.%06d+00:00 %s %s %s - %s\n' \
            "$(printf "%(%Y-%m-%dT%H:%M:%S)T" "$epoch")" \
            "$(( (EV_SEQ[$i] * 37) % 1000000 ))" \
            "$HOSTNAME" "${prog%%[*}" "$pid" "$body"
    else
        # Classic BSD syslog line: "Mon DD HH:MM:SS host prog[pid]: body"
        # Note there is no year in this format, exactly like the real thing.
        printf '%s %s %s: %s\n' \
            "$(printf "%(%b %e %H:%M:%S)T" "$epoch")" \
            "$HOSTNAME" "$prog" "$body"
    fi
}

# write_log FILE DIALECT
write_log() {
    local file=$1 dialect=$2
    : > "$file"
    local i
    for i in "${SORTED_IDX[@]}"; do
        # Debian-only lines are suppressed from the RHEL rendering.
        case "${EV_KIND[$i]}" in
            INVALID_USER|SESSION_OPENED)
                [ "$dialect" = "debian" ] || continue
                ;;
        esac
        render_line "$i" "$dialect" >> "$file"
    done
}

if [ "$FORMAT" = "debian" ] || [ "$FORMAT" = "both" ]; then
    write_log "$OUT_DIR/auth.log" debian
fi
if [ "$FORMAT" = "rhel" ] || [ "$FORMAT" = "both" ]; then
    write_log "$OUT_DIR/secure" rhel
fi
if [ "$FORMAT" = "rfc5424" ]; then
    write_log "$OUT_DIR/auth.log" rhel
fi

# ---------------------------------------------------------------------------
# Ground truth files
# ---------------------------------------------------------------------------
# events.tsv: every SSH auth event in chronological order.
{
    printf '# epoch\tiso_time\tip\tuser\tkind\tcountable_as_attempt\n'
    for i in "${SORTED_IDX[@]}"; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${EV_EPOCH[$i]}" \
            "$(printf "%(%Y-%m-%dT%H:%M:%S)T" "${EV_EPOCH[$i]}")" \
            "${EV_IP[$i]}" "${EV_USER[$i]}" "${EV_KIND[$i]}" "${EV_COUNTABLE[$i]}"
    done
} > "$OUT_DIR/events.tsv"

# attempts.tsv: only the events that count as a failed attempt.
# Counting rule (this is the contract the analyzer must match):
#   a line matching  "Failed password for [invalid user ]<user> from <ip>"
# ONLY the "Failed password" line counts. The Debian "Invalid user" preamble,
# the "pam_unix(sshd:auth): authentication failure" duplicate, and the
# "maximum authentication attempts exceeded" line are all NOT counted.
: > "$OUT_DIR/attempts.tsv"
for i in "${SORTED_IDX[@]}"; do
    if [ "${EV_COUNTABLE[$i]}" = "1" ]; then
        printf '%s\t%s\t%s\n' "${EV_EPOCH[$i]}" "${EV_IP[$i]}" "${EV_USER[$i]}" \
            >> "$OUT_DIR/attempts.tsv"
    fi
done

# expected.tsv: per-IP truth computed with a real sliding window over the
# generated epochs. This is the file the analyzer's output should be diffed
# against.
awk -v win="$WINDOW_SECONDS" -v thr="$THRESHOLD" '
{
    ip = $2
    n[ip]++
    ts[ip, n[ip]] = $1
    tot[ip] = n[ip]
}
END {
    printf "# ip\ttotal_attempts\tmax_in_%ds_window\texpected_verdict\n", win
    for (ip in tot) {
        m = n[ip]
        left = 1
        max = 0
        for (right = 1; right <= m; right++) {
            while (ts[ip, right] - ts[ip, left] > win) left++
            c = right - left + 1
            if (c > max) max = c
        }
        verdict = (max > thr) ? "FLAGGED" : "CLEAN"
        printf "%s\t%d\t%d\t%s\n", ip, tot[ip], max, verdict
    }
}
' "$OUT_DIR/attempts.tsv" | sort > "$OUT_DIR/expected.tsv.tmp"
# Keep the header on top, sort only the data rows.
{
    head -1 "$OUT_DIR/expected.tsv.tmp"
    tail -n +2 "$OUT_DIR/expected.tsv.tmp" | sort -t"$(printf '\t')" -k1,1
} > "$OUT_DIR/expected.tsv"
rm -f "$OUT_DIR/expected.tsv.tmp"

# scenarios.tsv: intent vs. computed truth.
{
    printf '# scenario\tip\tmode\tplanted_attempts\texpected_verdict\tnote\n'
    for (( s = 0; s < ${#SCEN_NAME[@]}; s++ )); do
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${SCEN_NAME[$s]}" "${SCEN_IP[$s]}" "${SCEN_MODE[$s]}" \
            "${SCEN_COUNT[$s]}" "${SCEN_VERDICT[$s]}" "${SCEN_NOTE[$s]}"
    done
} > "$OUT_DIR/scenarios.tsv"

# manifest.txt: everything needed to reproduce and interpret the run.
{
    printf 'Auth log mock fixture\n'
    printf '======================\n\n'
    printf 'seed             : %s\n' "$SEED"
    printf 'format           : %s\n' "$FORMAT"
    printf 'hostname         : %s\n' "$HOSTNAME"
    printf 'span_hours       : %s\n' "$SPAN_HOURS"
    printf 'start_epoch      : %s (%s)\n' "$START_EPOCH" \
        "$(printf "%(%Y-%m-%dT%H:%M:%S)T" "$START_EPOCH")"
    printf 'end_epoch        : %s (%s)\n' "$END_EPOCH" \
        "$(printf "%(%Y-%m-%dT%H:%M:%S)T" "$END_EPOCH")"
    printf 'window_seconds   : %s\n' "$WINDOW_SECONDS"
    printf 'threshold        : more than %s attempts in any %ss window\n' \
        "$THRESHOLD" "$WINDOW_SECONDS"
    printf 'window_semantics : closed interval [t, t+%s]; two attempts share a\n' "$WINDOW_SECONDS"
    printf '                   window iff their epochs differ by <= %s seconds\n' "$WINDOW_SECONDS"
    printf 'pam_duals        : %s\n' "$PAM_DUALS"
    printf 'maxauth          : %s\n' "$MAXAUTH"
    printf 'total_events     : %s\n' "$SEQ"
    printf 'total_attempts   : %s\n' "$(wc -l < "$OUT_DIR/attempts.tsv" | tr -d ' ')"
    printf 'flagged_ips      : %s\n' \
        "$(awk -F'\t' '!/^#/ && $4=="FLAGGED"' "$OUT_DIR/expected.tsv" | wc -l | tr -d ' ')"
    printf '\nCounting rule (the contract the analyzer must match)\n'
    printf -- '-----------------------------------------------------------\n'
    printf 'A failed attempt is a line matching:\n'
    printf '  "Failed password for [invalid user ]<user> from <ip> port <n> ssh2"\n'
    printf 'Only that line counts. NOT counted:\n'
    printf '  - "Invalid user <u> from <ip>"            (Debian preamble, same event)\n'
    printf '  - "pam_unix(sshd:auth): authentication failure" (duplicate of same event)\n'
    printf '  - "error: maximum authentication attempts exceeded" (distinct event type)\n'
    printf '\nTimestamp notes\n'
    printf -- '----------------\n'
    printf 'BSD-style lines (debian/rhel) carry NO YEAR. The analyzer must infer\n'
    printf 'the year from the newest entry and handle a Dec->Jan rollover. This\n'
    printf 'span is %s hours, so it usually crosses midnight and emits two\n' "$SPAN_HOURS"
    printf 'different day-of-month values with no year attached.\n'
    printf '\nTo exercise the year rollover explicitly:\n'
    printf '  ./gen_mock_logs.sh -o /tmp/ml --end "2027-01-01 00:30:00" --hours 12\n'
    printf '  (start lands on 2026-12-31, end on 2027-01-01)\n'
} > "$OUT_DIR/manifest.txt"

printf 'Wrote mock auth logs to %s\n' "$OUT_DIR"
printf '  events=%s attempts=%s flagged_ips=%s\n' \
    "$SEQ" \
    "$(wc -l < "$OUT_DIR/attempts.tsv" | tr -d ' ')" \
    "$(awk -F'\t' '!/^#/ && $4=="FLAGGED"' "$OUT_DIR/expected.tsv" | wc -l | tr -d ' ')"
