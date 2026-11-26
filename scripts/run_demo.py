#!/usr/bin/env python3
"""Run actual independent protocol parties; verify using a separate clear oracle."""
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_input(path):
    with Path(path).open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE))
    result = {}
    for row in rows:
        if row["id"] in result:
            raise ValueError("duplicate input identifier")
        result[row["id"]] = (int(row["weight"]), row["features"])
    return result


def generate(path, parties, small, large, overlap, threshold, maximum, seed):
    rng = random.Random(seed)
    if not 0 <= overlap <= min(small, large):
        raise ValueError("overlap must fit all sets")
    common = [f"common_{j:06d}" for j in range(overlap)]
    joint_targets = [0, threshold - 1, threshold, threshold + 1, parties * maximum]
    shared = []
    for j in range(overlap):
        target = joint_targets[j] if j < len(joint_targets) else rng.randrange(parties * maximum + 1)
        target = max(0, min(parties * maximum, target))
        weights = [target // parties + int(k < target % parties) for k in range(parties)]
        rng.shuffle(weights)
        shared.append(weights)
    files = []
    for k in range(parties):
        size = small if k == 0 else large
        rows = [(name, shared[j][k]) for j, name in enumerate(common)]
        # High-weight partial overlaps catch accidentally implementing only
        # pairwise PSI, or thresholding before the full intersection.
        if parties >= 3 and size >= overlap + 2:
            rows += [("partial_01" if k in (0, 1) else f"private_partial01_{k}", maximum),
                     ("partial_02" if k in (0, 2) else f"private_partial02_{k}", maximum)]
        rows += [(f"private_{k}_{j:08d}", rng.randrange(maximum + 1)) for j in range(size-len(rows))]
        rng.shuffle(rows)
        fpath = path / f"party{k}.tsv"
        with fpath.open("w", encoding="utf-8", newline="") as stream:
            stream.write("id\tweight\tfeatures\n")
            for j, (name, weight) in enumerate(rows):
                feature = json.dumps({"party": k, "local_row": j, "value": rng.randrange(1000000)}, separators=(",", ":"))
                stream.write(f"{name}\t{weight}\t{feature}\n")
        files.append(fpath)
    return files


def stop(processes):
    for proc in processes:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
    deadline = time.monotonic() + 3
    for proc in processes:
        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()


def execute(args):
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d_%H%M%S")
    run = ROOT / "results" / f"run_{stamp}_{uuid.uuid4().hex[:6]}"
    run.mkdir(parents=True)
    binary = ROOT / "build" / "mpwsi_party"
    if not binary.is_file():
        raise RuntimeError("Build first: bash scripts/build.sh")
    env = os.environ.copy()
    prefix = Path(env.get("DEPENDENCY_PREFIX", ROOT.parent / "MinBucket-MPSI/.runtime/prefix"))
    env["LD_LIBRARY_PATH"] = ":".join([str(prefix / "usr/lib/x86_64-linux-gnu"), str(prefix / "lib"), str(prefix / "lib64"), env.get("LD_LIBRARY_PATH", "")])
    env["OMP_NUM_THREADS"] = "1"
    paper = ROOT / "IEEE.tex"
    manifest = {"status": "running", "mode": "real encrypted multi-process protocol", "purpose": "correctness, not publication benchmark", "config": vars(args), "binary_sha256": digest(binary), "paper_sha256": digest(paper) if paper.is_file() else None, "commands": []}
    manifest["source_sha256"] = {str(p.relative_to(ROOT)): digest(p) for d in ("src", "include", "scripts", "tests") for p in sorted((ROOT / d).rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
    manifest["source_sha256"]["CMakeLists.txt"] = digest(ROOT / "CMakeLists.txt")
    files = []
    if not args.esc_test:
        if args.inputs:
            files = [Path(p).resolve() for p in args.inputs]
            if len(files) != args.parties:
                raise ValueError("provide exactly --parties input files")
        else:
            files = generate(run, args.parties, args.small, args.large, args.overlap, args.threshold, args.max_weight, args.seed)
        # Only this validation harness reads every input. Party processes each
        # receive ONE --input path and never receive the expected result.
        maps = [read_input(p) for p in files]
        common = set.intersection(*(set(m) for m in maps))
        sums = {i: sum(m[i][0] for m in maps) for i in common}
        expected = sorted(i for i in common if sums[i] >= args.threshold)
        (run / "oracle.json").write_text(json.dumps({"intersection_count": len(common), "joint_weights": sums, "expected_ids": expected}, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["inputs"] = [{"path": str(p), "sha256": digest(p), "rows": len(m)} for p, m in zip(files, maps)]
    processes, logs = [], []
    start = time.monotonic()
    print(f"RESULT_DIR={run}", flush=True)
    try:
        for k in range(args.parties):
            command = [str(binary), "--party", str(k), "--parties", str(args.parties), "--threshold", str(args.threshold), "--max-weight", str(args.max_weight), "--bins", str(args.bins), "--capacity", str(args.capacity), "--plain-bits", str(args.plain_bits), "--poly-degree", str(args.poly_degree), "--base-port", str(args.base_port), "--timeout", str(args.timeout), "--report", str(run / f"party{k}.json")]
            if args.esc_test:
                command += ["--esc-test"]
            else:
                command += ["--input", str(files[k]), "--output", str(run / f"aligned{k}.tsv")]
            manifest["commands"].append(command)
            log = (run / f"party{k}.log").open("w", encoding="utf-8")
            logs.append(log)
            processes.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True))
        while True:
            codes = [proc.poll() for proc in processes]
            if any(code is not None and code != 0 for code in codes):
                raise RuntimeError(f"party failed, exit codes {codes}; inspect party*.log")
            if all(code == 0 for code in codes):
                break
            if time.monotonic() - start > args.timeout + 5:
                raise TimeoutError("protocol timed out")
            time.sleep(0.1)
        reports = [json.loads((run / f"party{k}.json").read_text()) for k in range(args.parties)]
        if args.esc_test:
            if not all(r["status"] == "passed" and r["cases"] == 16 for r in reports):
                raise AssertionError("ESC tests failed")
            manifest["verified_esc_cases"] = 16
        else:
            checks = []
            for k in range(args.parties):
                with (run / f"aligned{k}.tsv").open(encoding="utf-8", newline="") as stream:
                    rows = list(csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE))
                actual = [row["id"] for row in rows]
                exact = actual == expected
                features = all(row["id"] in maps[k] and row["features"] == maps[k][row["id"]][1] for row in rows)
                checks.append({"party": k, "exact_sorted_ids": exact, "local_features_exact": features, "count": len(rows)})
                if not exact or not features:
                    raise AssertionError(f"party {k} disagrees with independent clear oracle")
            manifest["verification"] = checks
            manifest["intersection_count"] = len(common)
            manifest["selected_count"] = len(expected)
            manifest["transport_bytes_once"] = sum(r["sent_bytes"] for r in reports) + sum(r["sci_sent_plus_received_bytes"] for r in reports) // 2
            p = reports[0]["plain_modulus"]
            manifest["conservative_bmwg_false_match_bound"] = min(1.0, (args.parties-1) * reports[0]["bins"] * args.capacity / p)
        manifest["party_reports"] = reports
        manifest["status"] = "passed"
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        stop(processes)
        for log in logs:
            log.close()
        manifest["wall_seconds"] = time.monotonic() - start
        (run / "result.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "selected_count": manifest.get("selected_count"), "result": str(run / "result.json")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--small", type=int, default=16)
    parser.add_argument("--large", type=int, default=64)
    parser.add_argument("--overlap", type=int, default=8)
    parser.add_argument("--threshold", type=int, default=150)
    parser.add_argument("--max-weight", type=int, default=100)
    parser.add_argument("--bins", type=int, default=64)
    parser.add_argument("--capacity", type=int, default=16)
    parser.add_argument("--plain-bits", type=int, default=50)
    parser.add_argument("--poly-degree", type=int, default=16384)
    parser.add_argument("--base-port", type=int, default=23400)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20261014)
    parser.add_argument("--inputs", nargs="+")
    parser.add_argument("--esc-test", action="store_true")
    args = parser.parse_args()
    if args.esc_test:
        args.parties = 2
    if not (2 <= args.parties <= 16 and 0 <= args.max_weight <= 100000000 // args.parties and 0 <= args.threshold < 2**64):
        parser.error("invalid party count, max-weight or threshold")
    execute(args)


if __name__ == "__main__":
    main()
