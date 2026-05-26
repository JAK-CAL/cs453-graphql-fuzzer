# FSM-guided GraphQL Security Fuzzing

This project is a Python 3.11+ GraphQL security fuzzer for local labs and authorized test systems. It discovers a GraphQL schema, builds an operation pool, generates FSM-style request sequences, scores them with a genetic algorithm, and compares the FSM+GA approach against simpler baseline fuzzers.

## Safety Notice

Use this tool only against local vulnerable GraphQL labs, team-owned test servers, or endpoints where you have explicit written authorization. The fuzzer can generate authentication probes, injection strings, aliases, nested queries, and batches. Defaults are conservative, but you are responsible for setting safe limits.

## Architecture

```text
GraphQL Endpoint
      |
      v
Schema Discovery / Probing
      |
      v
Operation Pool Builder
      |
      v
FSM Transition Mapper + Shared Storage
      |
      v
Initial Population of Chromosomes
      |
      v
Sequence Executor
      |
      +--> GraphQL Query Builder
      +--> Auth/Header Builder
      +--> HTTP Client
      |
      v
Security Oracles
      |
      v
Fitness Evaluation
      |
      v
Selection / Crossover / Mutation / Repair
      |
      v
Next Generation

Outputs:
  findings.json
  coverage.json
  latency_log.csv
  generation_summary.csv
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Target Setup

The default endpoint is `http://localhost:3000/graphql`, intended for the vulnerable lab at:

```text
https://github.com/JAK-CAL/vulnerable-graphql-api
```

The endpoint is configurable in YAML, so DVGA or another authorized GraphQL server can be used.

## Configuration

Use `configs/default.yaml` as the base. Important limits:

- `execution.timeout_seconds`
- `execution.request_delay_ms`
- `limits.max_sequence_length`
- `limits.max_query_depth`
- `limits.max_alias_count`
- `limits.max_batch_size`
- `ga.population_size`
- `ga.generations`

For quick GA experiments, reduce `ga.population_size`, `ga.generations`, and `baselines.iterations`.

## Commands

Run schema discovery:

```bash
python -m fuzzer.cli discover --config configs/vulnerable_graphql_api.yaml
```

Run FSM-guided GA:

```bash
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode fsm-ga
```

Run baselines:

```bash
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-graphql
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-sequence
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode auth-only
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode query-shape-only
```

Evaluate results:

```bash
python -m fuzzer.cli evaluate --result-dir results/run_001
```

## Output Files

Each run creates the configured result directory with:

- `config.resolved.yaml`: resolved config.
- `schema.json`: introspection schema or probing fallback.
- `operation_pool.json`: discovered query/mutation operations.
- `generation_summary.csv`: GA generation metrics.
- `findings.json`: oracle findings in a shared record format.
- `coverage.json`: state, transition, and operation coverage.
- `latency_log.csv`: request timing header, ready for request-level logging extension.
- `sequences.json`: executed chromosomes and metadata.
- `metrics.json`: created by `evaluate`.

Example finding:

```json
{
  "finding_type": "AUTH_BYPASS_CANDIDATE",
  "severity": "high",
  "sequence_id": "seq_0012",
  "generation": 5,
  "operation": "privatePost",
  "transition": "query_other_resource",
  "auth_mode": "low_privilege",
  "status_code": 200,
  "latency_ms": 132.4,
  "response_size": 2048,
  "evidence": {
    "reason": "low privilege actor received private resource data",
    "sensitive_fields": ["email", "role"],
    "response_snippet": "{...}"
  }
}
```

## Core Concepts

- FSM state: coarse execution phase such as schema known, request executed, or response classified.
- Transition: attacker-style action such as public query, protected query without token, injection query, or batch query.
- Guard: checks whether a transition can run with current storage and operation metadata.
- Operation pool: schema-derived query and mutation root fields.
- Shared storage: tokens, resource IDs, actors, deleted resources, and previous responses.
- Gene/chromosome: one transition, and a sequence of transitions for GA search.
- Mutation: sequence, auth mode, payload, and query-shape changes.
- Oracle: response classifier for auth bypass, leakage, injection, and cost anomalies.
- Fitness: coverage plus security findings, with findings weighted more heavily.

## Supported Oracles

- Auth bypass candidate.
- Error leakage.
- Injection signal.
- DoS/cost anomaly.
- Differential auth comparison module for metamorphic extensions.

## Research Questions

- RQ1: Does FSM+GA find more security findings than random fuzzing?
- RQ2: Does GA improve coverage?
- RQ3: Are negative transitions useful?
- RQ4: Does query-shape mutation help detect DoS/cost anomalies?

## Testing

```bash
pytest
```

The tests cover query generation, operation-pool construction, oracles, mutation, and repair behavior.

## Development Notes

FSM support is intentionally modular. The current executor is an MVP that can run GA experiments now; deeper resource lifecycle modeling can be added in `fuzzer/fsm/executor.py`, `guards.py`, and `transition_mapper.py` without rewriting the GA or baselines.

Limitations:

- Introspection-disabled targets only receive a small probing fallback.
- Token acquisition is heuristic unless the target exposes a recognizable login operation.
- Request-level response archiving is scaffolded but not wired into every runner yet.
- Metamorphic differential comparison is implemented as a reusable oracle module, not a full sequence scheduler.
