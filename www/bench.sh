#!/bin/sh
# openblox benchmark — https://openblox.sh/bench.sh
#
# Measures a running openbloxd on this machine, through its own socket, the
# way a caller uses it. Run it as root on the host, after setup.sh:
#
#   curl -fsSL https://openblox.sh/bench.sh | sudo sh
#   curl -fsSL https://openblox.sh/bench.sh | sudo sh -s -- --mode stress
#
# Two modes:
#   latency (default)  one sandbox at a time: create, exec, a Python job, delete,
#                      with the same Python run on the host for comparison.
#   stress             concurrency steps up level by level, every sandbox running
#                      a CPU and memory job at once, until throughput stops
#                      growing, jobs fail, or the host runs low on memory.
#
# Options:
#   --mode latency|stress
#   --rounds N       latency: rounds (default 10); stress: jobs per sandbox (default 3)
#   --levels "1 2 4" stress: concurrency levels (default "1 2 4 8 16")
#   --job-mb N       memory each job fills (default 64)
#   --cpu N          size of each job's CPU loop (default 3000000)
#   --floor-mb N     stress stops before host free memory drops below this (default 512)
#   --profile NAME   profile to create sandboxes under (default code-exec)
#
# Stress mode never goes past the profile's max_sandboxes. To find the
# hardware's limit rather than the config's, raise max_sandboxes for the run,
# then put it back.
#
# Every sandbox it creates is named bench-<pid>-… and removed before it exits.

set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

SOCKET=${OPENBLOX_SOCKET:-/run/openbloxd/openbloxd.sock}
MODE=latency
ROUNDS=
LEVELS="1 2 4 8 16"
JOB_MB=64
CPU=3000000
FLOOR_MB=512
PROFILE=code-exec
SAMPLER='' t=''

say() { printf '%s\n' "$*"; }
fatal() { printf 'bench: %s\n' "$*" >&2; exit 1; }

parse_args() {
  while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || fatal "$1 needs a value"
    case $1 in
      --mode) MODE=$2 ;;
      --rounds) ROUNDS=$2 ;;
      --levels) LEVELS=$2 ;;
      --job-mb) JOB_MB=$2 ;;
      --cpu) CPU=$2 ;;
      --floor-mb) FLOOR_MB=$2 ;;
      --profile) PROFILE=$2 ;;
      *) fatal "unknown option $1 (see the header of this script)" ;;
    esac
    shift 2
  done
  case $MODE in latency) ROUNDS=${ROUNDS:-10} ;; stress) ROUNDS=${ROUNDS:-3} ;; *) fatal "--mode is latency or stress" ;; esac
  for v in "$ROUNDS" "$JOB_MB" "$CPU" "$FLOOR_MB" $LEVELS; do
    case $v in '' | *[!0-9]*) fatal "'$v' is not a whole number" ;; esac
  done
  case $PROFILE in '' | *[!A-Za-z0-9._-]*) fatal "invalid profile name '$PROFILE'" ;; esac
}

preflight() {
  [ "$(id -u)" = 0 ] || fatal "run as root (the daemon's socket is root-only): sudo sh bench.sh"
  [ -S "$SOCKET" ] || fatal "no openbloxd socket at $SOCKET; is the daemon running? (systemctl status openbloxd)"
  command -v curl >/dev/null || fatal "needs curl"
  api GET /profiles | grep -q "\"name\":\"$PROFILE\"" || fatal "openbloxd has no profile '$PROFILE'"
  RUN=bench-$$
  trap cleanup EXIT
  trap 'exit 130' INT TERM
}

api() { # method, path[, body]
  if [ $# -ge 3 ]; then
    curl -sS --unix-socket "$SOCKET" -H 'Content-Type: application/json' -X "$1" "http://openbloxd$2" -d "$3"
  else
    curl -sS --unix-socket "$SOCKET" -X "$1" "http://openbloxd$2"
  fi
}

now() { date +%s%N; }
ms() { echo $((($2 - $1) / 1000000)); }
mem_free() { awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo; }
cpu_ticks() { awk '/^cpu / {print $2+$3+$4+$6+$7+$8, $5}' /proc/stat; } # busy idle

create() { # name → 0 ok, 2 at capacity, 1 other failure
  out=$(api POST /sandboxes "{\"name\":\"$1\",\"profile\":\"$PROFILE\"}") || return 1
  case $out in *'"id"'*) return 0 ;; *at_capacity*) return 2 ;; *) say "create $1: $out" >&2; return 1 ;; esac
}

destroy() { # an HTTP error must not pass as a deleted sandbox
  curl -fsS --unix-socket "$SOCKET" -X DELETE "http://openbloxd/sandboxes/$1" >/dev/null || { say "could not delete $1" >&2; return 1; }
}

run() { # name, argv-json
  out=$(api POST "/sandboxes/$1/exec" "{\"argv\":$2,\"timeout\":\"120s\"}") || return 1
  case $out in *'"exit_code":0'*) return 0 ;; *) return 1 ;; esac
}

cleanup() {
  [ -z "$SAMPLER" ] || kill "$SAMPLER" 2>/dev/null
  [ -z "$t" ] || rm -rf "$t"
  names=$(api GET /sandboxes 2>/dev/null | grep -o "\"name\":\"$RUN-[^\"]*\"" | cut -d'"' -f4) || true
  for n in $names; do destroy "$n" || true; done
}

job_code() { printf "b=b'x'*(%s<<20); print(len(b)>>20, sum(i*i for i in range(%s)))" "$JOB_MB" "$CPU"; }
job_argv() { printf '["python3","-c","%s"]' "$(job_code)"; }

stats() { # label, file → min median max
  sort -n "$2" | awk -v l="$1" '{a[NR]=$1} END {if (NR) printf "  %-24s %7d %7d %7d ms\n", l, a[1], a[int((NR+1)/2)], a[NR]}'
}

latency() {
  t=$(mktemp -d)
  say "latency: $ROUNDS rounds, profile $PROFILE, job = fill ${JOB_MB} MiB + a ${CPU}-step loop"
  i=0
  while [ $i -lt "$ROUNDS" ]; do
    i=$((i + 1)); n=$RUN-$i
    a=$(now); create "$n" || fatal "could not create a sandbox (is the profile at its max_sandboxes?)"
    b=$(now); ms "$a" "$b" >>"$t/create"
    a=$(now); run "$n" '["true"]' || fatal "exec failed"; b=$(now); ms "$a" "$b" >>"$t/exec"
    a=$(now); run "$n" '["python3","-c","pass"]' || fatal "python3 failed"; b=$(now); ms "$a" "$b" >>"$t/py"
    a=$(now); run "$n" "$(job_argv)" || fatal "the job failed; lower --job-mb below the profile's memory_mb"
    b=$(now); ms "$a" "$b" >>"$t/job"
    a=$(now); destroy "$n" || fatal "could not delete a sandbox"; b=$(now); ms "$a" "$b" >>"$t/delete"
    if command -v python3 >/dev/null; then
      a=$(now); python3 -c pass; b=$(now); ms "$a" "$b" >>"$t/hpy"
      a=$(now); python3 -c "$(job_code)" >/dev/null; b=$(now); ms "$a" "$b" >>"$t/hjob"
    fi
  done
  printf '  %-24s %7s %7s %7s\n' "" min median max
  stats "create sandbox" "$t/create"
  stats "exec: true" "$t/exec"
  stats "exec: python3 startup" "$t/py"
  stats "exec: job" "$t/job"
  stats "delete sandbox" "$t/delete"
  if [ -s "$t/hpy" ]; then
    say "  on the host, no sandbox:"
    stats "python3 startup" "$t/hpy"
    stats "job" "$t/hjob"
  fi
  rm -rf "$t"
}

stress() {
  say "stress: levels $LEVELS, $ROUNDS jobs per sandbox, job = fill ${JOB_MB} MiB + a ${CPU}-step loop"
  say "        stops before host free memory drops under ${FLOOR_MB} MiB"
  printf '  %6s %9s %9s %9s %8s %6s %10s %6s\n' sandboxes create_ms job_p50 job_max jobs/s cpu% free_MiB failed
  best=0 best_c=0 best_cpu=0 peak=0 peak_c=0 last_c=0 stop=
  for c in $LEVELS; do
    t=$(mktemp -d)
    free=$(mem_free)
    if [ $((free - c * JOB_MB * 14 / 10)) -lt "$FLOOR_MB" ]; then
      stop="level $c would take the host under ${FLOOR_MB} MiB free (${free} MiB now)"; rm -rf "$t"; break
    fi

    a=$(now); j=0
    while [ $j -lt "$c" ]; do j=$((j + 1)); (if create "$RUN-$c-$j"; then echo 0; else echo $?; fi >"$t/c$j") & done
    wait; b=$(now); create_ms=$(ms "$a" "$b")
    if grep -qx 2 "$t"/c*; then
      stop="level $c is over the profile's max_sandboxes; raise it to go further"
      j=0; while [ $j -lt "$c" ]; do j=$((j + 1)); destroy "$RUN-$c-$j" & done; wait; rm -rf "$t"; break
    fi

    # below the floor, stop starting jobs; the ones in flight finish
    (while :; do f=$(mem_free); echo "$f" >>"$t/mem"; [ "$f" -ge "$FLOOR_MB" ] || : >"$t/stop"; sleep 0.2; done) & SAMPLER=$!
    x=$(cpu_ticks); busy0=${x% *} idle0=${x#* }
    a=$(now); j=0 pids=
    while [ $j -lt "$c" ]; do
      j=$((j + 1))
      (
        grep -qx 0 "$t/c$j" || { echo fail >>"$t/fail"; exit; }
        r=0
        while [ $r -lt "$ROUNDS" ] && [ ! -e "$t/stop" ]; do
          r=$((r + 1)); s=$(now)
          if run "$RUN-$c-$j" "$(job_argv)"; then ms "$s" "$(now)" >>"$t/job.$j"; else echo fail >>"$t/fail.$j"; : >"$t/stop"; fi
        done
      ) &
      pids="$pids $!"
    done
    # shellcheck disable=SC2086 # a list of PIDs
    wait $pids; b=$(now)
    kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null || true; SAMPLER=
    x=$(cpu_ticks); busy=$((${x% *} - busy0)) idle=$((${x#* } - idle0))

    cat "$t"/job.* 2>/dev/null | sort -n >"$t/jobs" || true
    done_n=$(wc -l <"$t/jobs")
    failed=$(cat "$t"/fail* 2>/dev/null | wc -l)
    wall=$(ms "$a" "$b")
    tput=$(awk -v n="$done_n" -v w="$wall" 'BEGIN {printf "%.2f", w ? n * 1000 / w : 0}')
    p50=$(awk '{a[NR]=$1} END {print NR ? a[int((NR+1)/2)] : "-"}' "$t/jobs")
    pmax=$(awk 'END {print NR ? $1 : "-"}' "$t/jobs")
    cpu=$(awk -v b="$busy" -v i="$idle" 'BEGIN {printf "%d", (b + i) ? b * 100 / (b + i) : 0}')
    minfree=$(sort -n "$t/mem" | head -1)
    printf '  %6s %9s %9s %9s %8s %6s %10s %6s\n' "$c" "$create_ms" "$p50" "$pmax" "$tput" "$cpu" "${minfree:-?}" "$failed"

    j=0; while [ $j -lt "$c" ]; do j=$((j + 1)); destroy "$RUN-$c-$j" & done; wait
    rm -rf "$t"
    last_c=$c
    if awk -v x="$tput" -v y="$peak" 'BEGIN {exit !(x > y)}'; then peak=$tput peak_c=$c; fi
    if awk -v x="$tput" -v y="$best" 'BEGIN {exit !(x > y * 1.1)}'; then best=$tput best_c=$c best_cpu=$cpu; fi
    [ "$failed" = 0 ] || { stop="jobs failed at $c sandboxes (out of memory, or the daemon refused them)"; break; }
    [ "${minfree:-0}" -ge "$FLOOR_MB" ] || { stop="host free memory fell under ${FLOOR_MB} MiB at $c sandboxes"; break; }
  done
  say ""
  if [ "$best_c" != 0 ] && [ "$best_c" = "$last_c" ]; then
    say "throughput was still growing at $best_c concurrent sandboxes ($best jobs/s)."
  elif [ "$best_c" != 0 ]; then
    why="more sandboxes add little throughput"
    [ "$best_cpu" -lt 90 ] || why="$why: the CPU is saturated, so jobs queue for it"
    say "throughput levels off at $best_c concurrent sandboxes ($best jobs/s); past that, $why."
    [ "$peak_c" = "$best_c" ] || say "the highest rate measured was $peak jobs/s, at $peak_c."
  fi
  [ -z "$stop" ] || say "stopped: $stop."
}

main() {
  parse_args "$@"
  preflight
  say "openblox bench on $(hostname): $(nproc) CPUs, $(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo) MiB RAM, $(openbloxd --version 2>/dev/null | head -1)"
  case $MODE in latency) latency ;; stress) stress ;; esac
}

main "$@"
