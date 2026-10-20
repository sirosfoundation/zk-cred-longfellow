#!/usr/bin/env python3
"""Per-file line coverage of src/nymauth (non-test sources) from an lcov file.

Prints a table (also appended to $GITHUB_STEP_SUMMARY when set) and exits 1 if the module's
line coverage is below the threshold. Only src/nymauth is gated; other code is reported nowhere.

usage: nymauth_coverage.py LCOV_FILE THRESHOLD_PERCENT
"""
import os
import sys

lcov, threshold = sys.argv[1], float(sys.argv[2])
files, cur = {}, None
for line in open(lcov):
    line = line.strip()
    if line.startswith("SF:"):
        cur = line[3:]
        files[cur] = {}
    elif line.startswith("DA:") and cur is not None:
        n, hits = line[3:].split(",")[:2]
        files[cur][int(n)] = int(hits)

rows, total, covered = [], 0, 0
for f, lines in sorted(files.items()):
    marker = "/src/nymauth/"
    if marker not in f:
        continue
    rel = f.split(marker, 1)[1]
    # tests are not gated: the measure is of the code they exercise
    if rel.startswith("tests/") or rel == "tests.rs":
        continue
    miss = sorted(n for n, h in lines.items() if h == 0)
    rows.append((rel, len(lines), len(lines) - len(miss), miss))
    total += len(lines)
    covered += len(lines) - len(miss)

if not rows:
    print("no src/nymauth files in the coverage data")
    sys.exit(1)

pct = 100.0 * covered / total
out = ["| file | lines | covered | % | uncovered lines |", "|---|---:|---:|---:|---|"]
for rel, t, c, miss in rows:
    out.append(f"| {rel} | {t} | {c} | {100.0 * c / t:.1f} | {', '.join(map(str, miss))} |")
out.append(f"| **src/nymauth total** | {total} | {covered} | **{pct:.1f}** | threshold {threshold:.0f} |")
text = "\n".join(out)
print(text)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as fh:
        fh.write("### nymauth line coverage\n\n" + text + "\n")
if pct < threshold:
    print(f"coverage {pct:.1f}% is below the {threshold:.0f}% threshold")
    sys.exit(1)
