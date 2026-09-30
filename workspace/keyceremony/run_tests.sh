#!/usr/bin/env bash
# Run every test: unit scenarios, edge cases, in-process smoke.
set -euo pipefail
cd "$(dirname "$0")"
echo "=== RFC 8032 / primitive correctness is exercised inside the suites ==="
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge tests.test_authz tests.test_drills
echo "=== HTTP e2e (login gates + four-eyes tickets + concurrent approve) ==="
python3 tests/http_e2e.py "${1:-8301}"
echo "=== cross-region DR drill HTTP e2e (scan/blueprint/resume/mirror/lease/evidence) ==="
python3 tests/drill_http_e2e.py "${2:-8302}"
echo "ALL TESTS PASSED"
