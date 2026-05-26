#!/usr/bin/env bash
set -euo pipefail
python -m fuzzer.cli evaluate --result-dir "${1:-results/run_001}"
