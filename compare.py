#!/usr/bin/env python3
"""
compare.py — Compare scan results from multiple scanners and identify whitelisted IPs

Input:  folder containing multiple results-*.json files
Output: report + lists of universal whitelist IPs and operator-blocked IPs

Usage:
    python3 compare.py reports/
    python3 compare.py reports/ --baseline starlink
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_reports(folder: Path) -> list[dict]:
    """Load all results-*.json files from the folder."""
    reports = []
    for f in folder.glob("results-*.json"):
        try:
            with f.open() as fp:
                report = json.load(fp)
                report["_filename"] = f.name
                reports.append(report)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[WARN] Skipping {f.name}: {e}", file=sys.stderr)
    return reports


def build_index(reports: list[dict]) -> dict[str, dict[str, dict]]:
    """
    Build a lookup index for fast cross-scanner comparison:
    {
        "116.202.1.3": {
            "starlink":    {"tls_ok": True,  "latency_ms": 113},
            "ali-irancell":{"tls_ok": False, "latency_ms": 0},
            ...
        },
        ...
    }
    """
    index: dict[str, dict[str, dict]] = defaultdict(dict)
    for report in reports:
        scanner_id = report["scanner_id"]
        for r in report["results"]:
            index[r["ip"]][scanner_id] = {
                "tcp_open": r["tcp_open"],
                "tls_ok": r["tls_ok"],
                "latency_ms": r["latency_ms"],
            }
    return index


def analyze(index, scanners: list[str], baseline: str | None):
    """
    Returns two lists:
    1. universal_whitelist: IPs that are TLS-OK from ALL scanners
    2. baseline_only:       IPs that work from baseline but fail on others (= filtered)
    """
    universal_whitelist = []
    baseline_only = []

    for ip, by_scanner in index.items():
        # Skip IPs that weren't tested by all scanners (incomplete data)
        if not all(s in by_scanner for s in scanners):
            continue

        all_tls_ok = all(by_scanner[s]["tls_ok"] for s in scanners)
        if all_tls_ok:
            universal_whitelist.append(ip)
            continue

        if baseline and by_scanner.get(baseline, {}).get("tls_ok"):
            other_scanners = [s for s in scanners if s != baseline]
            if any(not by_scanner[s]["tls_ok"] for s in other_scanners):
                baseline_only.append(ip)

    return universal_whitelist, baseline_only


def write_targets_file(ips: list[str], path: Path, header: str):
    """Write IPs in the targets.txt format the scanner understands."""
    with path.open("w") as f:
        f.write(f"# {header}\n")
        f.write(f"# Count: {len(ips)}\n\n")
        for ip in sorted(ips):
            f.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(description="Compare scan results across operators")
    parser.add_argument("folder", help="Folder containing results-*.json")
    parser.add_argument(
        "-b", "--baseline", default=None,
        help="Baseline scanner name (default: first scanner found)"
    )
    parser.add_argument(
        "-o", "--output-dir", default=".",
        help="Output directory for generated lists"
    )
    args = parser.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"[ERROR] Folder not found: {folder}", file=sys.stderr)
        sys.exit(1)

    reports = load_reports(folder)
    if not reports:
        print(f"[ERROR] No results-*.json files found in {folder}", file=sys.stderr)
        sys.exit(1)

    scanners = [r["scanner_id"] for r in reports]
    baseline = args.baseline or scanners[0]

    print(f"[*] Folder:    {folder}")
    print(f"[*] Scanners:  {len(reports)}")
    print(f"            {', '.join(scanners)}")
    print(f"[*] Baseline:  {baseline}")
    print()

    # Per-scanner summary
    print("-" * 60)
    print(f"{'Scanner':<30} {'Public IP':<18} {'TLS OK':>8}")
    print("-" * 60)
    for r in reports:
        print(f"{r['scanner_id']:<30} {r['public_ip']:<18} {r['tls_ok_count']:>8}")
    print("-" * 60)
    print()

    index = build_index(reports)
    universal, baseline_only = analyze(index, scanners, baseline)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(exist_ok=True)

    universal_file = out_dir / "whitelist-universal.txt"
    write_targets_file(
        universal, universal_file,
        "IPs that are TLS-OK from ALL scanners (true whitelist)"
    )

    blocked_file = out_dir / "blocked-by-iran.txt"
    write_targets_file(
        baseline_only, blocked_file,
        f"IPs that only work from {baseline} (likely filtered by Iranian operators)"
    )

    print(f"[OK] Universal whitelist: {len(universal)} IPs")
    print(f"     -> {universal_file}")
    print()
    print(f"[!]  Blocked by Iranian operators: {len(baseline_only)} IPs")
    print(f"     -> {blocked_file}")

    # Per-operator pass-through rate vs baseline
    if baseline in scanners:
        baseline_tls = next(r["tls_ok_count"] for r in reports if r["scanner_id"] == baseline)
        print()
        print("[*] Pass-through rate vs baseline:")
        for r in reports:
            if r["scanner_id"] == baseline:
                continue
            ratio = r["tls_ok_count"] / baseline_tls * 100 if baseline_tls else 0
            print(f"    {r['scanner_id']:<30} {ratio:>5.1f}%  ({r['tls_ok_count']}/{baseline_tls})")


if __name__ == "__main__":
    main()
