# Remediation Verification Model

## Lifecycle & Status Transitions

```
[ Scanner Finding ]
        |
        v
    PROPOSED  <--- (Gemma AI generates patch proposal)
        |
        +---> REJECTED (Developer rejects proposal)
        |
        v
    APPROVED  <--- (Developer approves patch proposal)
        |
        v
    APPLIED   <--- (Patch applied to isolated temporary workspace)
        |
        v
   VERIFYING  <--- (Dual-baseline verification harness executing)
        |
        +---> VERIFIED    (Regression tests pass & vulnerability cleared)
        +---> FAILED      (Regression tests fail or new findings introduced)
        +---> INCONCLUSIVE (Verification checks produced mixed or incomplete results)
```

## Pluggable Verification Checks

1. **Original Baseline Test**: Evaluates existing project tests against original source code.
2. **Security Regression Test**: Verifies that the targeted vulnerability is reproduced in original code and resolved in patched code.
3. **AST & Scanner Rescan**: Runs static analysis rules against the patched workspace to confirm finding removal without introducing new findings.
4. **Syntax & AST Validation**: Validates modified files for syntax errors using language parsers (e.g. Python `ast.parse`).

## Evidence Schema

Every verification run records explicit evidence:
- Baseline test status & output log
- Patched test status & output log
- Finding count change (previous vs. current)
- AST syntax validation status
- Exact timestamp and workspace hash
