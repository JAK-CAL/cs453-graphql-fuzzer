#!/usr/bin/env bash
set -euo pipefail
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-graphql
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-sequence
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode auth-only
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode query-shape-only
