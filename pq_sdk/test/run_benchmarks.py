#!/usr/bin/env python3
"""
Run piqaso_sdk micro-benchmarks and report min / max / mean / std.

Each bench_<algo> binary prints lines of the form:

    BENCH <label> <ns>

This script invokes every benchmark binary REPEAT times (default 1000),
parses every BENCH line emitted across all runs, groups samples by
<label>, and prints a summary table.

Build first (host build, with tests enabled):

    cmake -S . -B build
    cmake --build build -j

Then:

    python3 test/run_benchmarks.py             # 1000 runs of each bench
    python3 test/run_benchmarks.py -n 100      # fewer runs (faster)
    python3 test/run_benchmarks.py --iters 10  # 10 inner iterations / run
    python3 test/run_benchmarks.py --only mlkem mldsa aes
    python3 test/run_benchmarks.py --json results.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

DEFAULT_BENCHES = ["mlkem", "mldsa", "aes", "lms", "xmss"]
WRAPPER_LANGS  = ["python", "node", "java"]
BENCH_LINE_RE  = re.compile(r"^BENCH\s+(\S+)\s+(\d+)\s*$")


def find_build_dir(explicit: str | None) -> Path:
    here = Path(__file__).resolve().parent
    root = here.parent
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates += [root / "build", root / "build-js", root / "build-debug"]
    for c in candidates:
        if c.is_dir() and any((c / f"bench_{b}").exists() for b in DEFAULT_BENCHES):
            return c
    raise SystemExit(
        "Could not locate built bench_* binaries. Build with:\n"
        "  cmake -S . -B build && cmake --build build -j\n"
        "or pass --build-dir <path>."
    )


def run_one(binary: Path, iters: int) -> list[tuple[str, int]]:
    """Run binary once; return list of (label, ns) parsed from stdout."""
    proc = subprocess.run(
        [str(binary), str(iters)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"\n{binary.name} failed (rc={proc.returncode})\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
        )
        raise SystemExit(1)
    samples: list[tuple[str, int]] = []
    for line in proc.stdout.splitlines():
        m = BENCH_LINE_RE.match(line)
        if m:
            samples.append((m.group(1), int(m.group(2))))
    return samples


def run_cmd(cmd: list[str], cwd: Path | None = None,
            env: dict | None = None) -> list[tuple[str, int]]:
    """Run an arbitrary command; parse BENCH lines from its stdout."""
    proc = subprocess.run(cmd, cwd=cwd, env=env,
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(
            f"\n{' '.join(cmd)} failed (rc={proc.returncode})\n"
            f"--- stdout (tail) ---\n{proc.stdout[-2000:]}\n"
            f"--- stderr (tail) ---\n{proc.stderr[-2000:]}\n"
        )
        raise SystemExit(1)
    samples: list[tuple[str, int]] = []
    for line in proc.stdout.splitlines():
        m = BENCH_LINE_RE.match(line)
        if m:
            samples.append((m.group(1), int(m.group(2))))
    return samples


def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:8.1f} ns"
    if ns < 1_000_000:
        return f"{ns/1_000:8.2f} us"
    if ns < 1_000_000_000:
        return f"{ns/1_000_000:8.2f} ms"
    return f"{ns/1_000_000_000:8.3f} s "


def summarize(samples: list[int]) -> dict:
    n = len(samples)
    mn = min(samples)
    mx = max(samples)
    mean = statistics.fmean(samples)
    std = statistics.pstdev(samples) if n > 1 else 0.0
    return {"n": n, "min": mn, "max": mx, "mean": mean, "std": std}


def progress(prefix: str, done: int, total: int) -> None:
    width = 30
    filled = int(width * done / max(total, 1))
    bar = "#" * filled + "-" * (width - filled)
    sys.stderr.write(f"\r  {prefix:<14} [{bar}] {done}/{total}")
    sys.stderr.flush()


def run_wrappers(langs: list[str], benches: list[str], iters: int,
                 build_dir: Path, samples: dict) -> None:
    """Drive the SWIG wrapper benchmarks. Each wrapper is invoked once with
    iters=N (process/JVM startup is too expensive to repeat)."""
    here = Path(__file__).resolve().parent
    root = build_dir.parent

    for lang in langs:
        sys.stderr.write(f"  wrapper {lang:<6} ... ")
        sys.stderr.flush()
        t0 = time.monotonic()

        if lang == "python":
            script = here / "bench_bindings.py"
            env = os.environ.copy()
            extra = f"{build_dir}{os.pathsep}{build_dir / 'python'}"
            env["PYTHONPATH"] = extra + (os.pathsep + env["PYTHONPATH"]
                                         if env.get("PYTHONPATH") else "")
            cmd = [sys.executable, str(script), str(iters), *benches]
            new = run_cmd(cmd, env=env)

        elif lang == "node":
            script = here / "bench_bindings.js"
            node = os.environ.get("NODE", "node")
            cmd = [node, str(script), str(iters), *benches]
            new = run_cmd(cmd)

        elif lang == "java":
            jar         = build_dir / "piqaso.jar"
            classes_dir = build_dir / "bench_classes"
            src         = here / "BenchPiqaso.java"
            if not jar.exists():
                sys.stderr.write(
                    f"skip (no {jar}; build with -DBUILD_BINDINGS=ON "
                    "-DBINDINGS_LANGUAGE=java)\n")
                continue
            classes_dir.mkdir(parents=True, exist_ok=True)
            # Compile if needed.
            class_file = classes_dir / "BenchPiqaso.class"
            if (not class_file.exists()
                    or class_file.stat().st_mtime < src.stat().st_mtime):
                javac = os.environ.get("JAVAC", "javac")
                subprocess.run(
                    [javac, "-cp", str(jar), "-d", str(classes_dir), str(src)],
                    check=True)
            java_bin = os.environ.get("JAVA", "java")
            cp = f"{jar}{os.pathsep}{classes_dir}"
            cmd = [java_bin, "-cp", cp,
                   f"-Djava.library.path={build_dir}",
                   "BenchPiqaso", str(iters), *benches]
            new = run_cmd(cmd)
        else:
            continue

        for label, ns in new:
            samples[label].append(ns)
        sys.stderr.write(f"({time.monotonic() - t0:.1f}s, {len(new)} samples)\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--repeats", type=int, default=1000,
                    help="how many times to invoke each bench binary (default: 1000)")
    ap.add_argument("--iters", type=int, default=1,
                    help="inner iterations per binary invocation (default: 1)")
    ap.add_argument("--only", nargs="+", choices=DEFAULT_BENCHES,
                    help="run only the named benchmarks")
    ap.add_argument("--wrappers", nargs="+", choices=WRAPPER_LANGS,
                    metavar="LANG",
                    help=f"also run wrapper benchmarks for: {WRAPPER_LANGS}. "
                         "Wrappers are invoked once with iters=repeats since "
                         "process/JVM startup dominates.")
    ap.add_argument("--no-c", action="store_true",
                    help="skip the native C bench binaries (only run wrappers)")
    ap.add_argument("--build-dir", help="path to CMake build directory")
    ap.add_argument("--json", help="write raw summary to this JSON file")
    args = ap.parse_args()

    build_dir = find_build_dir(args.build_dir)
    benches = args.only or DEFAULT_BENCHES

    print(f"build dir : {build_dir}")
    print(f"repeats   : {args.repeats}  (inner iters: {args.iters})")
    print(f"benches   : {', '.join(benches)}\n")

    # label -> list[ns]
    samples: dict[str, list[int]] = defaultdict(list)

    overall_t0 = time.monotonic()
    if not args.no_c:
        for name in benches:
            binary = build_dir / f"bench_{name}"
            if not binary.exists():
                sys.stderr.write(f"skip: {binary} not found\n")
                continue
            t0 = time.monotonic()
            for i in range(args.repeats):
                for label, ns in run_one(binary, args.iters):
                    samples[label].append(ns)
                if (i + 1) % max(args.repeats // 50, 1) == 0 or (i + 1) == args.repeats:
                    progress(name, i + 1, args.repeats)
            elapsed = time.monotonic() - t0
            sys.stderr.write(f"   ({elapsed:.1f}s)\n")

    if args.wrappers:
        run_wrappers(args.wrappers, benches, args.repeats, build_dir, samples)
    total_elapsed = time.monotonic() - overall_t0

    # ----------------------------- report -----------------------------
    summary = {label: summarize(v) for label, v in samples.items()}

    print()
    print(f"{'operation':<32} {'n':>7}  {'min':>11}  {'mean':>11}  "
          f"{'max':>11}  {'std':>11}")
    print("-" * 92)
    for label in sorted(summary):
        s = summary[label]
        print(f"{label:<32} {s['n']:>7}  "
              f"{fmt_ns(s['min'])}  {fmt_ns(s['mean'])}  "
              f"{fmt_ns(s['max'])}  {fmt_ns(s['std'])}")
    print("-" * 92)
    print(f"total wall time: {total_elapsed:.1f}s")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"raw summary written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
