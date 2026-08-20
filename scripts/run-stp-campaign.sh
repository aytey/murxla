#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-stp-campaign.sh [BUILD_DIR] [RESULTS_PREFIX]

Run the STP fuzzing campaign until interrupted, as four lanes over 24 workers.

Every lane fuzzes every registered STP option on every run (--fuzz-opts-all)
and forces incremental mode, so the lanes differ only in what they check
against and how generation is steered.

  stp-diff  10  STP vs STP, options fuzzed against a pinned reference
  bzla       8  STP vs Bitwuzla, generation steered towards UF
  uf-gated   4  STP vs Bitwuzla, every solve carries a UF application
  narrow     2  STP vs STP at --bw-max 8

Why this shape:

* stp-diff is the widest net. Cross-checking STP against itself makes
  d_same_solver true, which is what re-enables get-value, get-unsat-core and
  get-unsat-assumptions -- ShadowSolver disables all three whenever the two
  solvers differ, so a Bitwuzla-referenced campaign never reads a model value
  at all. It also compares a fuzzed option vector against a fixed one, so an
  option that changes a verdict shows up as a divergence rather than having to
  crash to be noticed.

* --prefer-uf steers generation towards uninterpreted functions without also
  gating check-sat on one. Measured over 4000 runs against --require-uf: 2.62
  solves per run rather than 0.38, at 91% of the UF density. Solves per solver
  instance is what the state-reuse defects on this branch need -- they are
  second entries into a pipeline over what the last solve left behind -- so
  the gate was buying UF density by destroying the thing that finds them.

* uf-gated keeps a smaller share on --require-uf, where every solve is
  guaranteed to carry a UF application (4.2 per solve against 0.55).

* narrow is a hypothesis, not a measurement: narrow bit-vectors should make UF
  arguments collide, which is when injectivity and congruence lemmas fire. It
  showed no effect on solve rate or sat/unsat mix, so it gets two workers.

Defaults:
  BUILD_DIR       ./build-ufupdated
  RESULTS_PREFIX  /home/avj/clones/stp/campaign-results/stp-YYYYmmdd-HHMMSS

Each lane writes to RESULTS_PREFIX-<lane>. Press Ctrl-C to stop all of them.
EOF
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  usage
  exit 0
fi

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${1:-"$repo_dir/build-ufupdated"}
results_prefix=${2:-"/home/avj/clones/stp/campaign-results/stp-$(date +%Y%m%d-%H%M%S)"}
murxla="$build_dir/bin/murxla"
asan_runtime=/usr/lib64/clang/21/lib/linux/libclang_rt.asan-x86_64.so

# The reference vector for the STP-vs-STP lanes: abstractions off, no
# injectivity, no Ackermannisation. Every one of these is meant to preserve the
# verdict, so a divergence against the fuzzed side is a soundness bug.
reference_opts=uf-inject-args=0,bv-eq-abstraction=0,bv-term-abstraction=0,uf-ackermann=off

if [[ ! -x $murxla ]]; then
  echo "error: Murxla executable not found: $murxla" >&2
  exit 1
fi

if [[ ! -f $asan_runtime ]]; then
  echo "error: ASan runtime not found: $asan_runtime" >&2
  exit 1
fi

# STP is a shared library, so a rebuilt libstp.so is picked up without
# relinking -- but a build that added C API symbols or ifaceflag_t enumerators
# needs Murxla reconfigured, or the new options stay invisible to option
# fuzzing.
libstp=$(ldd "$murxla" 2>/dev/null | awk '/libstp\.so/ {print $3}')
if [[ -n ${libstp:-} && -f $libstp && $libstp -nt $murxla ]]; then
  echo "warning: $libstp is newer than $murxla" >&2
  echo "         reconfigure and rebuild Murxla if STP's C API changed" >&2
fi

# lane name, worker count, lane-specific flags
lanes=(
  "stp-diff 10 -c stp --cross-check-opts $reference_opts --prefer-uf"
  "bzla      8 -c bitwuzla -C bitwuzla --prefer-uf"
  "uf-gated  4 -c bitwuzla -C bitwuzla --require-uf"
  "narrow    2 -c stp --cross-check-opts $reference_opts --prefer-uf --bw-max 8"
)

output_dirs=()
for lane in "${lanes[@]}"; do
  read -r name _ <<<"$lane"
  output_dirs+=("${results_prefix}-${name}")
done

for output_dir in "${output_dirs[@]}"; do
  if [[ -e $output_dir ]]; then
    echo "error: refusing to reuse existing output directory: $output_dir" >&2
    exit 1
  fi
done

pids=()
stop_lanes() {
  trap - INT TERM EXIT
  if ((${#pids[@]})); then
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi
}
trap stop_lanes INT TERM EXIT

for lane in "${lanes[@]}"; do
  read -r name jobs flags <<<"$lane"
  output_dir="${results_prefix}-${name}"
  mkdir -p "$output_dir"

  echo "Starting lane $name ($jobs workers): $flags"
  # shellcheck disable=SC2086  # flags is a deliberate word list
  env LD_PRELOAD="$asan_runtime" \
    "$murxla" \
      --stp $flags \
      --fuzz-opts-all --force-incremental \
      -j "$jobs" -t 20 \
      -e "$output_dir/errors.json" \
      -O "$output_dir" \
    >"$output_dir/run.log" 2>&1 &
  pids+=("$!")
  echo "  log: $output_dir/run.log"
done

echo "Running until all lanes finish or you press Ctrl-C."

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=$?
done
pids=()
exit "$status"
