#!/usr/bin/env bash
#
# Build piqaso_sdk for each binding language (python, java, javascript), run
# the 1000-sample benchmark suite (native C + the wrapper for that build),
# and save the parsed min/max/mean/std summary to JSON.
#
# Outputs (under benchmarks/results/ by default):
#
#   native.json              -- C bench_* binaries only (no wrapper)
#   python.json              -- C + Python wrapper
#   node.json                -- C + Node wrapper
#   java.json                -- C + Java wrapper
#   raw/<lang>.log           -- full stdout of each run
#
# Usage:
#   test/run_all_benchmarks.sh                    # all targets, 1000 reps
#   test/run_all_benchmarks.sh -n 200             # fewer reps
#   test/run_all_benchmarks.sh --only mlkem aes   # subset of algorithms
#   test/run_all_benchmarks.sh --langs python     # one wrapper only
#   test/run_all_benchmarks.sh --skip-xmss        # drop slow XMSS
#
# Each binding language requires its own build directory because only one
# SWIG language can be configured per CMake build. We use:
#
#   build-native/   -- native C only (no bindings)
#   build-py/       -- BUILD_BINDINGS=ON BINDINGS_LANGUAGE=python
#   build-java/     -- BUILD_BINDINGS=ON BINDINGS_LANGUAGE=java
#   build-js/       -- BUILD_BINDINGS=ON BINDINGS_LANGUAGE=javascript

set -euo pipefail

# ---------------------------------------------------------------- options ---
REPEATS=1000
LANGS=(python node java)
ONLY=()
SKIP_XMSS=0
OUT_DIR=""
JOBS="$(nproc 2>/dev/null || echo 4)"

usage() {
    sed -n '2,30p' "$0"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--repeats)   REPEATS="$2"; shift 2 ;;
        --langs)        shift; LANGS=(); while [[ $# -gt 0 && "$1" != --* ]]; do LANGS+=("$1"); shift; done ;;
        --only)         shift; ONLY=();  while [[ $# -gt 0 && "$1" != --* ]]; do ONLY+=("$1");  shift; done ;;
        --skip-xmss)    SKIP_XMSS=1; shift ;;
        --out-dir)      OUT_DIR="$2"; shift 2 ;;
        -j|--jobs)      JOBS="$2"; shift 2 ;;
        -h|--help)      usage 0 ;;
        *)              echo "unknown arg: $1" >&2; usage 1 ;;
    esac
done

# ---------------------------------------------------------------- paths ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

[[ -z "$OUT_DIR" ]] && OUT_DIR="$ROOT_DIR/benchmarks/results"
mkdir -p "$OUT_DIR/raw"

if [[ ${#ONLY[@]} -eq 0 ]]; then
    ONLY=(mlkem mldsa aes lms xmss)
fi
if [[ "$SKIP_XMSS" -eq 1 ]]; then
    ONLY=("${ONLY[@]/xmss}")
fi
# Collapse blanks introduced by the substitution above.
TMP=(); for x in "${ONLY[@]}"; do [[ -n "$x" ]] && TMP+=("$x"); done
ONLY=("${TMP[@]}")

echo "================================================================"
echo " piqaso_sdk benchmark sweep"
echo "   repeats : $REPEATS"
echo "   only    : ${ONLY[*]}"
echo "   langs   : ${LANGS[*]}"
echo "   out-dir : $OUT_DIR"
echo "   jobs    : $JOBS"
echo "================================================================"

# ---------------------------------------------------------------- helpers --
configure_build() {
    # $1 = build dir, remaining args = extra cmake -D flags
    local build_dir="$1"; shift
    if [[ ! -f "$build_dir/CMakeCache.txt" ]]; then
        echo ">> cmake configure $build_dir ($*)"
        cmake -S . -B "$build_dir" "$@" >/dev/null
    fi
    echo ">> cmake build $build_dir"
    cmake --build "$build_dir" -j "$JOBS" >/dev/null

    # Sanity check: if bench binaries aren't there, force a clean reconfigure.
    if [[ ! -x "$build_dir/bench_mlkem" ]]; then
        echo ">> bench binaries missing in $build_dir — wiping and reconfiguring"
        rm -rf "$build_dir"
        cmake -S . -B "$build_dir" "$@" >/dev/null
        cmake --build "$build_dir" -j "$JOBS" >/dev/null
    fi
}

run_suite() {
    # $1 = label (filename stem), $2 = build dir, $3 = wrapper lang ("" for none)
    local label="$1" build="$2" wrapper="$3"
    local json="$OUT_DIR/${label}.json"
    local log="$OUT_DIR/raw/${label}.log"

    local args=(--build-dir "$build" -n "$REPEATS" --json "$json" --only "${ONLY[@]}")
    if [[ -n "$wrapper" ]]; then
        args+=(--wrappers "$wrapper")
    fi

    echo
    echo "================================================================"
    echo " run: $label   (build=$build, wrapper=${wrapper:-none})"
    echo "================================================================"
    python3 test/run_benchmarks.py "${args[@]}" 2>&1 | tee "$log"
}

# ---------------------------------------------------------------- 1. native
configure_build "build-native"
run_suite "native" "build-native" ""

# ---------------------------------------------------------------- 2. wrappers
for lang in "${LANGS[@]}"; do
    case "$lang" in
        python)
            configure_build "build-py" \
                -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=python
            run_suite "python" "build-py" "python"
            ;;
        java)
            configure_build "build-java" \
                -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=java
            run_suite "java" "build-java" "java"
            ;;
        node|javascript|js)
            # node-addon-api must be installed in bindings/js/ first.
            if [[ ! -f bindings/js/node_modules/node-addon-api/napi.h ]]; then
                echo ">> installing node-addon-api in bindings/js/"
                ( cd bindings/js && npm install --silent )
            fi
            configure_build "build-js" \
                -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=javascript
            run_suite "node" "build-js" "node"
            ;;
        *)
            echo "unknown language: $lang" >&2
            exit 1
            ;;
    esac
done

echo
echo "================================================================"
echo " done.  results in $OUT_DIR"
ls -1 "$OUT_DIR"/*.json 2>/dev/null || true
echo "================================================================"
