#!/usr/bin/env bash
set -euo pipefail
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode fsm-ga
