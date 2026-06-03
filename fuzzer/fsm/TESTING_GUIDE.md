# Attacker FSM 테스트 가이드

이 문서는 Attacker FSM 퍼저를 **기존 타깃 서버**로 돌리는 방법과 **다른 GraphQL 서버**로 옮겨 테스트할 때 무엇을 바꿔야 하는지를 설명한다.

---

## 1. 빠른 시작 (기존 타깃: vulnerable-graphql-api)

타깃은 로컬 `~/vulnerable-graphql-api`를 Docker로 띄워서만 쓴다(상용 서버는 rate-limit/밴 위험).

### 1) 서버 띄우기

```bash
cd ~/vulnerable-graphql-api
docker build -t vgql .
docker run -d --rm --name vgql-run -p 3000:3000 vgql
# 준비 확인 (200 이면 OK)
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3000/graphql \
  -H 'Content-Type: application/json' -d '{"query":"{ __schema { queryType { name } } }"}'
```

엔드포인트: `http://localhost:3000/graphql` · GraphiQL 동일 URL · introspection 켜져 있음.

### 2) 퍼저 실행

```bash
# 의존성 (requests, pyyaml). 가상환경 권장.
python -m venv .venv && .venv/bin/pip install requests pyyaml

# 메인: FSM-guided GA 모드
.venv/bin/python -m fuzzer.cli fuzz \
  --config configs/vulnerable_graphql_api_budget.yaml --mode fsm-ga
```

출력 예: `fuzz complete: findings=5 states=10 transitions=11`

### 3) 결과 확인

`results/<output.result_dir>/` 아래에 생성된다:

| 파일 | 내용 |
|---|---|
| `server_model.json` | **관찰한 서버 지식** — responsive_operations, observed_auth_required, nonproductive_ops, 수확한 id, rate_limited |
| `findings.json` | 탐지된 취약 후보(AUTH_BYPASS / INJECTION / DOS / ERROR_LEAKAGE) |
| `coverage.json` | 방문한 state/transition/operation |
| `sequences.json` | 최종 population의 공격 시퀀스 |
| `generation_summary.csv` | 세대별 fitness·findings·coverage |
| `schema.json`, `operation_pool.json` | introspection 결과·연산 풀 |

### 4) 정리 / 리셋

```bash
docker rm -f vgql-run        # 종료
# 시드 상태로 되돌리려면 컨테이너를 다시 run (이 타깃엔 resetServer mutation이 없음)
```

### 다른 실행 모드

`--mode` 로 baseline 들을 돌릴 수 있다(비교/보고서용):

```
fsm-ga            # 메인 — FSM + GA + 능동 관찰 + budget
random-graphql    # 단일 무작위 연산
random-sequence   # 무작위 시퀀스
auth-only         # auth_mode 스윕
query-shape-only  # alias/nested/batch 스윕
```

스키마만 확인하려면: `python -m fuzzer.cli discover --config <config>`

---

## 2. 설정(config) 핵심 필드

config는 YAML이며 `configs/` 안에 예시가 있다. FSM/예산 관련 중요한 키:

```yaml
target:
  endpoint: "http://localhost:3000/graphql"   # 공격 대상

execution:
  request_delay_ms: 650          # 요청 간 간격 (rate limit 대응 페이싱)
  reset_between_chromosomes: false  # GraphQL reset_query 호출 여부 (타깃에 reset op 있을 때만 true)

ga:
  request_budget: 90             # ★ run 전체 총 요청 상한 (null=무제한)
  surface_probe_enabled: true    # ★ 시작 시 능동 탐사 on/off
  surface_probe_max_requests: 8  # ★ 탐사에 쓸 최대 요청 수
  population_size: 12
  generations: 6
  fitness_function: "default"    # default | coverage_only | state_weight_average
```

- **`request_budget`**: 부트스트랩 탐사 + 모든 chromosome 실행 + prerequisite 충족 + replay 까지 **모든 요청을 합산**해 제한한다. 예산 소진 시 이후 실행을 멈춘다.
- **`request_delay_ms`**: rate limit이 있는 서버에서 429를 피하려고 페이싱한다. (타깃은 100 req/분 → 약 650ms 권장.)
- 총 요청량 대략치(예산 없을 때) ≈ `surface_probe` + `generations × population × 평균 시퀀스 길이`.

---

## 3. 다른 GraphQL 서버로 테스트하기

### 3-1. 최소 절차

1. 그 서버를 로컬에 띄운다(또는 접근 가능한 엔드포인트 확보). **테스트 권한이 있는 서버만** 대상으로 한다.
2. config를 복제해 `target.endpoint`를 바꾼다:
   ```bash
   cp configs/vulnerable_graphql_api_budget.yaml configs/my_target.yaml
   # endpoint, output.result_dir, request_budget, request_delay_ms 수정
   ```
3. introspection이 되는지 먼저 확인: `python -m fuzzer.cli discover --config configs/my_target.yaml`
   - `operation_pool.json` 에 연산이 채워지면 OK.
   - introspection이 막혀 있으면 `operation_pool`이 비고 퍼저가 할 일이 없다(§3-4 참고).
4. `fuzz --mode fsm-ga` 실행.

### 3-2. 자동으로 적응되는 부분 (보통 손 안 대도 됨)

ServerModel이 **응답을 보고 학습**하므로 서버마다 아래는 자동 조정된다:
- 어떤 연산이 실제로 data를 주는지(`responsive_operations`).
- 인증이 필요한지(`observed_auth_required`) — cookie 없이 에러나면 auth 필요로 추정.
- 항상 실패하는 연산(`nonproductive_ops`) — 이후 선택에서 자동 제외.
- 실재 id 수확 → capability 충족에 재사용.

즉 "서버 내부를 모르는 상태에서 요청→관찰→상태 갱신→다음 행동 선택"은 코드 변경 없이 동작한다.

### 3-3. 서버 성격에 따라 점검/수정할 부분

현재 capability·auth 모델은 **세션 쿠키 인증**(요청 한 번으로 신원이 생기는 타입)을 가정한다. 다른 서버라면 다음을 점검한다:

| 서버 특성 | 확인/수정 위치 |
|---|---|
| **Bearer 토큰 로그인이 실제로 동작** | 현재 planner는 "세션 확립=public query"로 인증을 만든다. 토큰 로그인이 필요한 서버면 `planner.py`의 producer(`_resolve_capability`의 SESSION 경로)를 login→토큰 흐름으로 바꾸고, `storage.add_token`/`get_token`을 활용. `capabilities.derive_capabilities`의 SESSION 판정도 토큰 보유로 확장. |
| **인증이 헤더 토큰 기반** | `client.headers_for_auth`(Authorization 헤더)는 이미 토큰이 있으면 붙인다. 토큰 획득 경로만 맞추면 됨. |
| **리소스 owner 개념이 다름** | OWN/OTHER 리소스는 "서로 다른 actor(쿠키 jar/세션) = 다른 소유자" 가정. 멀티테넌시 방식이 다르면 `planner._other_owner` 와 `storage.get_other_resource` 점검. |
| **상태 초기화 방법** | 타깃에 reset mutation이 있으면 `execution.reset_query` 를 그 쿼리로, `reset_between_chromosomes: true`. 없으면 false 유지하고 서버 재시작으로 리셋. |
| **rate limit 존재** | `request_budget` 와 `request_delay_ms` 를 한도 아래로. `server_model.json`의 `rate_limited`가 true면 너무 빠른 것. |
| **introspection 비활성** | §3-4 |

### 3-4. introspection이 막힌 서버

- `introspect_schema`가 실패하면 `probe_schema_placeholder`(흔한 필드 이름 추정)로 폴백하지만 연산 풀이 부실하다.
- 대안: 스키마를 별도로 구해서 `target.schema_path`에 introspection JSON 경로를 지정하면 그걸 사용한다(`runners/common.prepare_run` 참고).

### 3-5. 부트스트랩 탐사 커스터마이즈

`surface_probe.bootstrap_surface`는 기본적으로 ① 서로 다른 두 세션으로 public query ② login 시도(망가졌는지 학습) ③ create 1회로 소유 리소스 시드 를 보낸다. 타깃에 맞춰 프로빙 시나리오를 바꾸려면 이 함수를 수정한다. 끄려면 `surface_probe_enabled: false`.

---

## 4. 동작 개요 (한눈에)

```
introspect → operation_pool / dependency graph
  → bootstrap_surface (능동 탐사, ServerModel 시드)        [budget 차감]
  → GA: 세대 반복
       repair → execute_chromosome
                 ├ guard 막힘? → planner가 전제 transition 합성·실행 후 재시도
                 ├ 매 응답 server_model.observe (학습)
                 └ budget 소진 시 중단                      [budget 차감]
       fitness 평가 → 선택/교배/변이
  → server_model.json / findings.json / coverage.json 덤프
```

핵심 모듈:
- `executor.py` — 시퀀스 실행, guard·전제 충족, 관찰·예산 배선
- `capabilities.py` / `planner.py` — capability 도출 + 막히면 positive transition 합성
- `guards.py` — transition 실행 가능 판정(capability + operation-surface)
- `server_model.py` — run 전체 관찰 지식(학습)
- `surface_probe.py` — 시작 시 능동 탐사
- `transition_mapper.py` / `dependency.py` — transition↔operation 매핑·점수
- `../ga/budget.py` — RequestBudget

---

## 5. 단위 테스트

```bash
pip install pytest requests pyyaml
pytest -q          # 전체
pytest -q tests/test_server_model.py tests/test_surface_probe.py tests/test_budget.py
```

FakeClient 기반이라 서버 없이도 FSM·관찰·예산 로직을 검증한다. 새 서버용으로 planner/capability를 바꿨다면 `tests/test_capabilities.py`, `tests/test_planner.py`, `tests/test_attacker_fsm_integration.py` 를 함께 갱신할 것.

> 주의: `latency_log.csv` 는 현재 헤더만 쓰고 행 적재는 연결돼 있지 않다(기존 한계). 총 요청량은 `server_model.json`/실행 로그로 가늠한다.
