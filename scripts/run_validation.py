#!/usr/bin/env python3
"""Sequential end-to-end regression cases; all use real protocol processes."""
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("esc_wrap_boundaries", ["--esc-test"]),
    ("three_party_threshold_boundary", []),
    ("four_party", ["--parties", "4", "--threshold", "200"]),
    ("threshold_zero_includes_zero_weight", ["--threshold", "0"]),
    ("threshold_above_maximum", ["--threshold", "301"]),
    ("disjoint", ["--overlap", "0"]),
    ("empty_sender", ["--large", "0", "--overlap", "0"]),
    ("all_coordinator_records_shared", ["--overlap", "16"]),
]


def main():
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y%m%d_%H%M%S")
    path = ROOT / "results" / f"validation_{stamp}_{uuid.uuid4().hex[:6]}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "cases": []}
    try:
        for j, (name, options) in enumerate(CASES):
            print(f"CASE {name}", flush=True)
            command = [sys.executable, str(ROOT / "scripts/run_demo.py"), "--base-port", str(23400 + j * 1000), *options]
            proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(proc.stdout, end="", flush=True)
            dirs = [line.split("=", 1)[1] for line in proc.stdout.splitlines() if line.startswith("RESULT_DIR=")]
            entry = {"name": name, "exit_code": proc.returncode, "command": command}
            if dirs:
                result_path = Path(dirs[-1]) / "result.json"
                entry["report"] = str(result_path)
                if result_path.exists():
                    run = json.loads(result_path.read_text())
                    entry.update(status=run["status"], selected_count=run.get("selected_count"), wall_seconds=run["wall_seconds"])
            report["cases"].append(entry)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            if proc.returncode or entry.get("status") != "passed":
                raise RuntimeError(f"validation failed: {name}")
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"VALIDATION_REPORT={path}", flush=True)


if __name__ == "__main__":
    main()
