# CODEX IMPLEMENTATION INSTRUCTIONS

## Project Title

**FSM-guided GraphQL Security Fuzzing**

This document is a complete implementation brief for Codex. Codex should use it to generate the project file structure, Python source code, tests, example configuration files, and a complete `README.md`.

---

## 0. High-Level Goal

Build a Python-based **FSM-guided, stateful GraphQL security fuzzer**.

The fuzzer targets a GraphQL API and automatically generates request sequences that model attacker behavior as FSM transitions. It executes those sequences, classifies responses with security oracles, scores each sequence using a GA-style fitness function, mutates/crosses over sequences, and compares the proposed FSM-guided GA against simple baselines.

The project must support:

1. Schema discovery through GraphQL introspection.
2. Operation pool construction from schema.
3. FSM state and transition modeling.
4. Shared FSM storage for tokens, actors, resources, and IDs.
5. Schema-aware and storage-aware input generation.
6. Positive, negative, setup, and metamorphic transitions.
7. Security-oriented response oracles.
8. GA-based sequence optimization.
9. Baseline fuzzers.
10. JSON/CSV result logging.
11. README with install, run, config, and evaluation instructions.

---

## 1. Primary Target Server

Use the following target by default:

```text
https://github.com/JAK-CAL/vulnerable-graphql-api
```

The fuzzer repository is expected to be:

```text
https://github.com/JAK-CAL/cs453-graphql-fuzzer
```

The target endpoint must be configurable. Do not hard-code one endpoint.

Default local endpoint:

```text
http://localhost:3000/graphql
```

DVGA can remain a secondary/legacy target, but the implementation should be general enough to work against any local GraphQL endpoint.

---

## 2. Security and Scope Constraints

This tool is intended only for:

- Local vulnerable GraphQL labs.
- Team-owned test servers.
- Explicitly authorized GraphQL endpoints.

Add this warning prominently in `README.md`.

The fuzzer must include safety limits:

- Request timeout.
- Maximum sequence length.
- Maximum query depth.
- Maximum alias count.
- Maximum batch size.
- Optional delay between requests.
- Maximum generations and population size.

Default values must be conservative.

---

## 3. Required Repository Structure

Generate the following project structure.

```text
cs453-graphql-fuzzer/
  README.md
  requirements.txt
  pyproject.toml
  .gitignore

  configs/
    default.yaml
    vulnerable_graphql_api.yaml
    dvga.yaml

  fuzzer/
    __init__.py
    cli.py
    config.py

    graphql/
      __init__.py
      client.py
      introspection.py
      schema_types.py
      operation_pool.py
      query_builder.py
      payloads.py

    fsm/
      __init__.py
      states.py
      transitions.py
      storage.py
      guards.py
      transition_mapper.py
      executor.py

    ga/
      __init__.py
      chromosome.py
      population.py
      selection.py
      crossover.py
      mutation.py
      repair.py
      fitness.py

    oracle/
      __init__.py
      base.py
      auth.py
      error_leakage.py
      injection.py
      dos.py
      differential.py

    runners/
      __init__.py
      fsm_ga.py
      random_graphql.py
      random_sequence.py
      auth_mutation_only.py
      query_shape_only.py

    storage/
      __init__.py
      json_logger.py
      coverage.py
      findings.py
      response_archive.py

    evaluation/
      __init__.py
      metrics.py
      report.py

  scripts/
    run_fsm_ga.sh
    run_baselines.sh
    evaluate_results.sh

  tests/
    test_query_builder.py
    test_operation_pool.py
    test_oracles.py
    test_mutation.py
    test_repair.py

  results/
    .gitkeep
```

---

## 4. Dependencies

Use Python 3.11+.

`requirements.txt` should include:

```text
requests>=2.31.0
PyYAML>=6.0.0
pytest>=8.0.0
```

Optional but acceptable:

```text
rich>=13.0.0
```

Use optional dependencies only if they improve CLI output without complicating the project.

---

## 5. Configuration Format

Use YAML config files.

Example `configs/default.yaml`:

```yaml
target:
  name: vulnerable-graphql-api
  endpoint: "http://localhost:3000/graphql"

execution:
  timeout_seconds: 5
  request_delay_ms: 50
  max_response_archive_bytes: 4096

limits:
  max_sequence_length: 8
  max_query_depth: 4
  max_alias_count: 10
  max_duplicate_fields: 5
  max_batch_size: 3

ga:
  population_size: 30
  generations: 20
  mutation_rate: 0.35
  crossover_rate: 0.50
  elitism_count: 2
  tournament_size: 3

mutations:
  sequence: true
  auth: true
  payload: true
  query_shape: true

oracles:
  auth_bypass: true
  error_leakage: true
  injection: true
  dos: true

baselines:
  iterations: 200

output:
  result_dir: "results/run_001"
```

---

## 6. Core Data Models

### 6.1 GraphQL Operation Model

Implement in:

```text
fuzzer/graphql/schema_types.py
```

Required classes:

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Argument:
    name: str
    type_name: str
    required: bool = False
    raw_type: dict[str, Any] | None = None


@dataclass
class Operation:
    name: str
    operation_type: str  # "query" or "mutation"
    args: list[Argument] = field(default_factory=list)
    return_type: str | None = None
    selectable_fields: list[str] = field(default_factory=list)
    nested_fields: dict[str, str] = field(default_factory=dict)
    auth_required_guess: bool = False
    sensitive_field_guess: bool = False
```

Attribute meanings:

- `name`: GraphQL root field name, e.g. `login`, `posts`, `user`.
- `operation_type`: either `query` or `mutation`.
- `args`: argument metadata.
- `return_type`: unwrapped GraphQL return type name.
- `selectable_fields`: scalar fields that can be used in selection sets.
- `nested_fields`: object/list fields that can be used for depth-based query-shape mutation.
- `auth_required_guess`: heuristic guess based on operation/field names.
- `sensitive_field_guess`: true when return fields include sensitive names.

Sensitive keywords:

```python
SENSITIVE_KEYWORDS = [
    "admin",
    "user",
    "private",
    "secret",
    "token",
    "password",
    "permission",
    "role",
    "email",
    "profile",
    "owner",
]
```

---

### 6.2 Query Shape Model

Implement in:

```text
fuzzer/ga/chromosome.py
```

```python
from dataclasses import dataclass


@dataclass
class QueryShape:
    depth: int = 1
    alias_count: int = 0
    batch: bool = False
    batch_size: int = 1
    duplicate_fields: int = 0
```

Attribute meanings:

- `depth`: intended nesting depth.
- `alias_count`: number of aliases for the same operation.
- `batch`: whether to send a batch request.
- `batch_size`: number of operations in a batch request.
- `duplicate_fields`: number of duplicated fields in the selection set.

---

### 6.3 Gene and Chromosome

Implement in:

```text
fuzzer/ga/chromosome.py
```

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Gene:
    transition: str
    operation_name: str | None
    auth_mode: str
    payload: dict[str, Any] = field(default_factory=dict)
    query_shape: QueryShape = field(default_factory=QueryShape)
    expected_negative: bool = False


@dataclass
class Chromosome:
    genes: list[Gene]
    fitness: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    visited_states: set[str] = field(default_factory=set)
    visited_transitions: set[str] = field(default_factory=set)
    valid_request_count: int = 0
    total_request_count: int = 0
    unique_error_patterns: set[str] = field(default_factory=set)
```

Attribute meanings:

- `Gene.transition`: abstract FSM transition.
- `Gene.operation_name`: operation selected from the operation pool.
- `Gene.auth_mode`: `no_token`, `valid_token`, `bad_token`, `empty_token`, `wrong_prefix`, `low_privilege`.
- `Gene.payload`: argument values.
- `Gene.query_shape`: query-structure mutation metadata.
- `Gene.expected_negative`: true for intentionally invalid/forbidden actions.
- `Chromosome.genes`: a transition sequence.
- `Chromosome.fitness`: GA score.
- `Chromosome.findings`: security findings from execution.
- `Chromosome.visited_states`: FSM state coverage.
- `Chromosome.visited_transitions`: transition coverage.
- `Chromosome.valid_request_count`: number of GraphQL-valid responses.
- `Chromosome.total_request_count`: number of executed requests.
- `Chromosome.unique_error_patterns`: normalized error signatures.

---

## 7. FSM Design

### 7.1 FSM States

Implement in:

```text
fuzzer/fsm/states.py
```

Use string enums.

```python
from enum import Enum


class FSMState(str, Enum):
    S0_START = "S0_START"
    S1_SCHEMA_KNOWN = "S1_SCHEMA_KNOWN"
    S2_SURFACE_MAPPED = "S2_SURFACE_MAPPED"
    S3_AUTH_CONTEXT_AVAILABLE = "S3_AUTH_CONTEXT_AVAILABLE"
    S4_OPERATION_SELECTED = "S4_OPERATION_SELECTED"
    S5_INPUT_SPACE_PREPARED = "S5_INPUT_SPACE_PREPARED"
    S6_REQUEST_EXECUTED = "S6_REQUEST_EXECUTED"
    S7_RESPONSE_CLASSIFIED = "S7_RESPONSE_CLASSIFIED"
    S8_INTERESTING_BEHAVIOR_FOUND = "S8_INTERESTING_BEHAVIOR_FOUND"
    S9_REPRODUCIBLE_FINDING = "S9_REPRODUCIBLE_FINDING"
    S10_MUTATION_PLANNED = "S10_MUTATION_PLANNED"
    S11_RESET = "S11_RESET"
```

These states represent:

- Authentication state.
- Resource lifecycle state.
- Response classification state.
- Mutation planning state.

---

### 7.2 Transition Types

Implement in:

```text
fuzzer/fsm/transitions.py
```

Required abstract transitions:

```python
from enum import Enum


class TransitionName(str, Enum):
    INTROSPECT_SCHEMA = "introspect_schema"
    PROBE_PUBLIC_SURFACE = "probe_public_surface"

    LOGIN_OR_GET_TOKEN = "login_or_get_token"
    PUBLIC_QUERY = "public_query"

    SETUP_CREATE_RESOURCE = "setup_create_resource"
    QUERY_OWN_RESOURCE = "query_own_resource"
    QUERY_OTHER_RESOURCE = "query_other_resource"
    UPDATE_OWN_RESOURCE = "update_own_resource"
    UPDATE_OTHER_RESOURCE = "update_other_resource"
    DELETE_OWN_RESOURCE = "delete_own_resource"
    DELETE_OTHER_RESOURCE = "delete_other_resource"
    QUERY_DELETED_RESOURCE = "query_deleted_resource"

    PROTECTED_QUERY_WITHOUT_TOKEN = "protected_query_without_token"
    PROTECTED_QUERY_WITH_VALID_TOKEN = "protected_query_with_valid_token"
    PROTECTED_QUERY_WITH_BAD_TOKEN = "protected_query_with_bad_token"
    PROTECTED_QUERY_WITH_LOW_PRIVILEGE = "protected_query_with_low_privilege"

    INJECTION_PAYLOAD_QUERY = "injection_payload_query"
    ALIAS_AMPLIFIED_QUERY = "alias_amplified_query"
    DEEPLY_NESTED_QUERY = "deeply_nested_query"
    BATCH_QUERY = "batch_query"

    METAMORPHIC_COMPARE_AUTH_MODES = "metamorphic_compare_auth_modes"
```

Transition categories:

1. **Setup Transition**
   - login
   - resource create

2. **Positive Lifecycle Transition**
   - query own resource
   - update own resource
   - delete own resource

3. **Negative Lifecycle Transition**
   - query other user's resource
   - update other user's resource
   - delete other user's resource
   - protected query without token
   - protected query with bad token

4. **Metamorphic Transition**
   - compare valid/no/bad/low-privilege responses for same operation/resource.

---

## 8. Shared FSM Storage

Implement in:

```text
fuzzer/fsm/storage.py
```

Required classes:

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Actor:
    name: str
    username: str | None = None
    password: str | None = None
    token: str | None = None
    role: str = "user"


@dataclass
class ResourceRef:
    resource_type: str
    id: str
    owner_actor: str | None = None
    state: str = "active"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class FSMStorage:
    actors: dict[str, Actor] = field(default_factory=dict)
    active_actor: str | None = None
    resources: dict[str, list[ResourceRef]] = field(default_factory=dict)
    previous_responses: list[dict[str, Any]] = field(default_factory=list)
    known_ids: set[str] = field(default_factory=set)
    valid_tokens: list[str] = field(default_factory=list)
    invalid_tokens: list[str] = field(default_factory=list)

    def add_token(self, actor_name: str, token: str) -> None:
        ...

    def get_token(self, actor_name: str | None = None) -> str | None:
        ...

    def add_resource(self, resource: ResourceRef) -> None:
        ...

    def get_resource(
        self,
        resource_type: str | None = None,
        owner_actor: str | None = None,
        state: str | None = "active",
    ) -> ResourceRef | None:
        ...

    def extract_ids_from_response(self, response_body: Any) -> None:
        ...
```

Purpose:

- Store login results.
- Store created resource IDs.
- Reuse IDs in later transitions.
- Support ownership tests.
- Support deleted resource tests.
- Support storage-aware payload generation.

---

## 9. Guard Design

Implement in:

```text
fuzzer/fsm/guards.py
```

Guards decide whether a transition can execute in the current context.

Examples:

- `valid_token` required → check token exists.
- `update/delete` transition → check active resource exists.
- `query_deleted_resource` → check deleted resource ID exists.
- `injection_payload_query` → prefer operations with arguments.
- `query_other_resource` → require at least two actors or at least one resource owned by another actor.

Required API:

```python
def can_execute_transition(
    transition: str,
    gene: Gene,
    storage: FSMStorage,
    operation_pool: list[Operation],
) -> bool:
    ...
```

---

## 10. GraphQL Client

Implement in:

```text
fuzzer/graphql/client.py
```

Required:

```python
from dataclasses import dataclass
from typing import Any


@dataclass
class GraphQLResponse:
    status_code: int
    body: Any
    text: str
    latency_ms: float
    response_size: int
    timeout: bool
    request_query: str | None = None
    request_variables: dict[str, Any] | None = None
    auth_mode: str | None = None
```

Client features:

- POST request to GraphQL endpoint.
- Support JSON body.
- Support batch JSON body if `QueryShape.batch=True`.
- Header generation by auth mode:
  - no token
  - valid token
  - bad token
  - empty token
  - wrong prefix
  - low privilege token, if available
- Timeout handling.
- Latency measurement.
- Response size measurement.

---

## 11. Schema Discovery

Implement in:

```text
fuzzer/graphql/introspection.py
```

Required features:

- Send introspection query.
- Save raw schema JSON.
- Return `None` if introspection is disabled.
- Provide minimal schema probing fallback placeholder.

The fallback can be simple in MVP:

- Try common query/mutation names from a small dictionary.
- Parse GraphQL error suggestions if present.
- Store partial findings.

Do not over-engineer probing.

---

## 12. Operation Pool Builder

Implement in:

```text
fuzzer/graphql/operation_pool.py
```

Required functions:

```python
def unwrap_type(type_obj: dict | None) -> tuple[str | None, bool]:
    """
    Return unwrapped type name and whether it was NON_NULL.
    """


def build_type_map(schema: dict) -> dict[str, dict]:
    ...


def selectable_fields_for_type(
    type_map: dict[str, dict],
    type_name: str | None,
) -> tuple[list[str], dict[str, str]]:
    """
    Return scalar selectable fields and nested object/list fields.
    """


def guess_auth_required(operation: Operation) -> bool:
    ...


def build_operation_pool(schema: dict) -> list[Operation]:
    ...
```

Rules:

- Include root `Query` fields.
- Include root `Mutation` fields.
- Store argument names/types.
- Store scalar fields as `selectable_fields`.
- Store object/list fields as `nested_fields`.
- Use sensitive keywords to set `auth_required_guess` and `sensitive_field_guess`.

---

## 13. Query Builder

Implement in:

```text
fuzzer/graphql/query_builder.py
```

Required features:

1. Build variable definitions.
2. Build argument call syntax.
3. Build selection set.
4. Support duplicate fields.
5. Support aliases.
6. Support shallow nested selection using `nested_fields`.
7. Support batch request creation.
8. Return both query and variables.

Required API:

```python
def build_graphql_document(
    operation: Operation,
    payload: dict[str, Any],
    query_shape: QueryShape,
    operation_map: dict[str, Operation] | None = None,
) -> tuple[str | list[dict[str, Any]], dict[str, Any]]:
    ...
```

Behavior:

- If `batch=False`, return `(query_string, variables)`.
- If `batch=True`, return `(list_of_request_objects, {})`.
- Use GraphQL variables rather than interpolating payload values directly.
- Do not create syntactically invalid query strings intentionally unless a specific negative mutation requests wrong type/null values through variables.

---

## 14. Payload Generation

Implement in:

```text
fuzzer/graphql/payloads.py
```

Required payload strategies:

### 14.1 Schema-aware defaults

```python
def default_value_for_type(type_name: str, required: bool = False) -> Any:
    ...
```

Defaults:

| GraphQL Type | Value |
|---|---|
| ID | `"1"` |
| String | `"test"` |
| Int | `1` |
| Float | `1.0` |
| Boolean | `True` |

### 14.2 Storage-aware values

Use `FSMStorage` to reuse:

- valid IDs
- created resource IDs
- deleted resource IDs
- actor credentials
- previous response object IDs

### 14.3 Security payloads

Include:

```python
SQL_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "'; SELECT 1; --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
]

COMMAND_PAYLOADS = [
    "$(id)",
    "`id`",
]

STRESS_PAYLOADS = [
    "A" * 2048,
]
```

---

## 15. Response Oracles

Implement in:

```text
fuzzer/oracle/
```

All findings must use a common record format.

### 15.1 Finding Record Format

```python
{
  "finding_type": "AUTH_BYPASS_CANDIDATE",
  "severity": "high",
  "sequence_id": "seq_0001",
  "generation": 3,
  "operation": "someOperation",
  "transition": "protected_query_without_token",
  "auth_mode": "no_token",
  "status_code": 200,
  "latency_ms": 120.5,
  "response_size": 2048,
  "evidence": {
    "reason": "...",
    "matched_keywords": [],
    "response_snippet": "..."
  }
}
```

### 15.2 Auth Bypass Oracle

Implement in:

```text
fuzzer/oracle/auth.py
```

Detect:

- no token returns protected data.
- bad token returns sensitive data.
- low privilege token returns admin data.
- no/bad token response resembles valid-token response for sensitive fields.
- expected negative transition unexpectedly succeeds.

Sensitive fields:

```python
SENSITIVE_FIELDS = [
    "email",
    "role",
    "permission",
    "token",
    "password",
    "admin",
    "secret",
    "private",
    "owner",
]
```

### 15.3 Error Leakage Oracle

Implement in:

```text
fuzzer/oracle/error_leakage.py
```

Detect keywords:

```python
ERROR_LEAK_KEYWORDS = [
    "Traceback",
    "Exception",
    "SQL syntax",
    "SQLite",
    "PostgreSQL",
    "MySQL",
    "MongoError",
    "TypeError",
    "ReferenceError",
    "Resolver",
    "Internal Server Error",
    "stack trace",
]
```

Normalize case when matching.

### 15.4 Injection Oracle

Implement in:

```text
fuzzer/oracle/injection.py
```

Detect:

- SQL/DB error.
- payload reflection.
- boolean-based response difference.
- unexpected internal exception.
- time-based latency spike, if baseline is available.

### 15.5 DoS / Cost Oracle

Implement in:

```text
fuzzer/oracle/dos.py
```

Inputs:

- response latency.
- response size.
- timeout.
- status code.
- query depth.
- alias count.
- batch size.

Default detection:

```text
timeout == true
OR latency_ms > max(1000, baseline_latency_ms * 5)
OR response_size > max(50000, baseline_response_size * 10)
OR status_code >= 500
```

### 15.6 Differential Oracle

Implement in:

```text
fuzzer/oracle/differential.py
```

Compare responses for the same operation/resource under:

- valid token
- no token
- bad token
- low privilege token

Use this especially for metamorphic transitions.

---

## 16. FSM Executor

Implement in:

```text
fuzzer/fsm/executor.py
```

Responsibilities:

1. Execute one chromosome.
2. For each gene:
   - select operation.
   - check guard.
   - repair or skip with penalty.
   - generate payload.
   - build GraphQL query.
   - execute request.
   - update storage from response.
   - classify with oracles.
   - update coverage.
3. Return executed chromosome with fitness-relevant metadata.

Required API:

```python
def execute_chromosome(
    chromosome: Chromosome,
    client: GraphQLClient,
    operation_pool: list[Operation],
    storage: FSMStorage,
    config: AppConfig,
    generation: int = 0,
    sequence_id: str = "seq_0000",
) -> Chromosome:
    ...
```

---

## 17. GA Implementation

### 17.1 Population

Implement in:

```text
fuzzer/ga/population.py
```

Create initial population using operation pool and transition categories.

Initial population should include:

- public query genes.
- login/token genes if login-like mutations exist.
- protected query with no token.
- protected query with bad token.
- injection genes for operations with args.
- alias/depth genes.

### 17.2 Selection

Implement tournament selection.

```python
def select_parent(population: list[Chromosome], tournament_size: int) -> Chromosome:
    ...
```

### 17.3 Crossover

Implement sequence crossover.

```python
def crossover(parent_a: Chromosome, parent_b: Chromosome, max_len: int) -> Chromosome:
    ...
```

Run repair after crossover.

### 17.4 Mutation

Implement in:

```text
fuzzer/ga/mutation.py
```

Mutation types:

1. Sequence mutation
   - insert gene
   - delete gene
   - replace gene
   - duplicate gene
   - reorder local subsequence

2. Auth mutation
   - no token
   - valid token
   - bad token
   - empty token
   - wrong prefix
   - low privilege

3. Payload mutation
   - SQL-like
   - XSS-like
   - path traversal
   - command-like
   - long string
   - null
   - wrong type

4. Query-shape mutation
   - alias count increase
   - duplicate field increase
   - depth increase
   - batch enable/increase

### 17.5 Repair

Implement in:

```text
fuzzer/ga/repair.py
```

Important rule:

**Do not repair by simply downgrading `valid_token` to `no_token`.**

Instead:

1. Insert required setup transition if possible.
2. Insert login transition before valid-token transitions.
3. Insert resource-create transition before resource-dependent transitions.
4. Preserve negative intent.
5. If repair fails, keep the gene but mark penalty or skip at execution.

Required API:

```python
def repair_chromosome(
    chromosome: Chromosome,
    operation_pool: list[Operation],
    max_sequence_length: int,
) -> Chromosome:
    ...
```

### 17.6 Fitness

Implement in:

```text
fuzzer/ga/fitness.py
```

Formula:

```text
fitness =
  1.0 * new_state_count
+ 1.0 * new_transition_count
+ 0.5 * valid_request_ratio
+ 3.0 * unique_error_count
+ 8.0 * auth_anomaly_count
+ 6.0 * injection_signal_count
+ 6.0 * cost_anomaly_count
+ 10.0 * security_finding_count
- 2.0 * skipped_transition_count
- 3.0 * unrepaired_invalid_sequence_count
```

Security findings must dominate simple coverage.

---

## 18. Runners

### 18.1 FSM-guided GA Runner

Implement in:

```text
fuzzer/runners/fsm_ga.py
```

Flow:

```text
load config
create result directory
create client
introspect schema
build operation pool
save schema and operation pool
create initial population
for each generation:
    execute all chromosomes
    log coverage/findings/latency
    calculate fitness
    selection/crossover/mutation/repair
save final summary
```

### 18.2 Baseline Runners

Implement:

```text
fuzzer/runners/random_graphql.py
fuzzer/runners/random_sequence.py
fuzzer/runners/auth_mutation_only.py
fuzzer/runners/query_shape_only.py
```

Baselines:

1. `Random GraphQL Fuzzer`
   - Single random operation per iteration.
   - Random auth mode.
   - Random payload.

2. `Random Sequence Fuzzer`
   - Random operation sequence.
   - No FSM guards.
   - Same oracle.

3. `Auth Mutation Only`
   - Same operation tested under valid/no/bad/empty/wrong-prefix token modes.

4. `Query Shape Only`
   - Alias/depth/batch/duplicate mutation only.

All baselines must reuse the same oracles and result format.

---

## 19. CLI

Implement in:

```text
fuzzer/cli.py
```

Use `argparse`.

Required commands:

```bash
python -m fuzzer.cli discover --config configs/vulnerable_graphql_api.yaml
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode fsm-ga
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-graphql
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-sequence
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode auth-only
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode query-shape-only
python -m fuzzer.cli evaluate --result-dir results/run_001
```

---

## 20. Logging and Output Files

For every run, generate:

```text
results/run_001/
  config.resolved.yaml
  schema.json
  operation_pool.json
  generation_summary.csv
  findings.json
  coverage.json
  latency_log.csv
  sequences.json
  responses/
    response_000001.json
```

### 20.1 findings.json

Array of finding records.

### 20.2 coverage.json

```json
{
  "state_coverage": 8,
  "transition_coverage": 12,
  "visited_states": [],
  "visited_transitions": [],
  "operation_coverage": 15
}
```

### 20.3 generation_summary.csv

Columns:

```text
generation,best_fitness,avg_fitness,total_findings,auth_findings,injection_findings,dos_findings,error_leakage_findings,state_coverage,transition_coverage
```

### 20.4 latency_log.csv

Columns:

```text
timestamp,sequence_id,generation,operation,transition,auth_mode,status_code,latency_ms,response_size,timeout
```

---

## 21. Evaluation Metrics

Implement in:

```text
fuzzer/evaluation/metrics.py
```

Required metrics:

- state coverage
- transition coverage
- operation coverage
- valid request ratio
- unique error count
- total findings
- unique findings
- auth anomaly count
- injection signal count
- cost anomaly count
- error leakage count
- time-to-first-finding
- max latency
- average latency
- max response size
- reproducible finding count, optional placeholder

Research Questions:

| RQ | Question |
|---|---|
| RQ1 | Does FSM+GA find more security findings than random fuzzing? |
| RQ2 | Does GA improve coverage? |
| RQ3 | Are negative transitions useful? |
| RQ4 | Does query-shape mutation help detect DoS/cost anomalies? |

---

## 22. Tests

Write minimal pytest tests.

### 22.1 test_query_builder.py

Test:

- basic query generation.
- mutation generation.
- alias generation.
- duplicate fields.
- batch generation.

### 22.2 test_operation_pool.py

Test:

- unwrap type.
- build operation from synthetic introspection schema.
- sensitive keyword detection.

### 22.3 test_oracles.py

Test:

- auth bypass detection.
- error leakage keyword detection.
- injection reflection.
- DoS timeout detection.

### 22.4 test_mutation.py

Test:

- sequence mutation changes chromosome.
- auth mutation changes auth mode.
- payload mutation inserts payload.
- query-shape mutation increases alias/depth/batch.

### 22.5 test_repair.py

Test:

- valid-token gene gets login setup inserted.
- resource-dependent gene gets setup-create inserted when possible.
- negative intent is not removed.

---

## 23. README.md Requirements

Generate a complete `README.md`.

The README must include:

1. Project title and one-paragraph overview.
2. Safety notice.
3. Architecture diagram in text form.
4. Installation instructions.
5. Target server setup section.
6. Configuration section.
7. How to run schema discovery.
8. How to run FSM-guided GA fuzzer.
9. How to run baselines.
10. How to evaluate results.
11. Output directory explanation.
12. Core concepts:
    - FSM state
    - transition
    - guard
    - operation pool
    - shared storage
    - gene/chromosome
    - mutation
    - oracle
    - fitness
13. Supported mutation types.
14. Supported oracles.
15. Metrics and research questions.
16. Troubleshooting.
17. Development guide.
18. Limitations.

README command examples:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
python -m fuzzer.cli discover --config configs/vulnerable_graphql_api.yaml
```

```bash
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode fsm-ga
```

```bash
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-graphql
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode random-sequence
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode auth-only
python -m fuzzer.cli fuzz --config configs/vulnerable_graphql_api.yaml --mode query-shape-only
```

```bash
python -m fuzzer.cli evaluate --result-dir results/run_001
```

---

## 24. Implementation Priority

Codex should implement in this order.

### Phase 1: MVP Core

1. Config loader.
2. GraphQL client.
3. Introspection.
4. Operation pool builder.
5. Query builder.
6. Basic oracle framework.
7. JSON logger.

### Phase 2: FSM and Storage

1. FSM states/transitions.
2. FSMStorage.
3. Guards.
4. Transition mapper.
5. Executor.

### Phase 3: GA

1. Gene/Chromosome.
2. Initial population.
3. Fitness.
4. Selection.
5. Crossover.
6. Mutation.
7. Repair.

### Phase 4: Baselines and Evaluation

1. Random GraphQL fuzzer.
2. Random sequence fuzzer.
3. Auth-only runner.
4. Query-shape-only runner.
5. Evaluation report generator.

### Phase 5: README and Tests

1. README.md.
2. Unit tests.
3. Example configs.
4. Shell scripts.

---

## 25. Minimum Acceptance Criteria

The generated project is acceptable if:

1. `pip install -r requirements.txt` succeeds.
2. `pytest` runs.
3. `python -m fuzzer.cli discover --config configs/default.yaml` runs against a local endpoint or fails gracefully with a clear error.
4. `python -m fuzzer.cli fuzz --config configs/default.yaml --mode fsm-ga` runs and creates a result directory.
5. `findings.json`, `coverage.json`, and `generation_summary.csv` are created.
6. Baseline modes run through the same CLI.
7. README explains target setup, commands, configs, outputs, and limitations.
8. Code uses the shared finding format.
9. Query execution never runs without timeout.
10. Query-shape mutation respects configured limits.

---

## 26. Coding Style

- Keep modules small and readable.
- Use dataclasses for data models.
- Use type hints.
- Avoid global mutable state.
- Use explicit config objects rather than magic constants.
- Fail gracefully with helpful messages.
- Write JSON with `ensure_ascii=False` and `indent=2`.
- Avoid unnecessary external dependencies.

---

## 27. Important Design Notes

1. The main novelty is **FSM-guided stateful sequence generation**, not just random GraphQL fuzzing.
2. Security findings should come from oracles, not from HTTP status alone.
3. GraphQL responses may return HTTP 200 even when `errors` exist; always inspect `data` and `errors`.
4. The same oracle implementation must be reused by the proposed method and all baselines.
5. Negative transitions are first-class citizens. They represent requests that should fail but may reveal vulnerabilities if they succeed.
6. Repair should preserve the original testing intent.
7. Stateful resource tracking is important for ownership and lifecycle bugs.
8. Query-shape mutation is important for GraphQL-specific DoS/cost anomaly testing.
9. Result logs must be reproducible and suitable for tables in the final report.
10. The README should be written so a new teammate can clone, install, run, and understand the project without reading source code first.

---

## 28. Suggested README Architecture Diagram

Include this text diagram in `README.md`:

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

---

## 29. Example Finding

Use this example in README:

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

---

## 30. Deliverables Codex Must Produce

Codex should generate:

1. Full repository file structure.
2. Python source files.
3. YAML configs.
4. Shell scripts.
5. Unit tests.
6. Complete README.md.
7. `.gitignore`.
8. `requirements.txt`.
9. `pyproject.toml`.

The generated code does not need to be a perfect research artifact immediately, but it must be runnable, modular, and aligned with the FSM-guided GraphQL security fuzzing design.
