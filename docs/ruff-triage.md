# Ruff finding triage

The baseline scan on 2026-07-22 reported 114 findings. Ruff's safe autofix
removed 79 lint-only findings (mostly unused imports and dead local variables).
The remaining 34 findings are explicitly scoped in `pyproject.toml`:

- 18 are legacy import-order, ORM boolean-expression, ambiguous-short-name, or
  re-export cases where changing code would add unrelated churn.
- 10 are optional-dependency/type-annotation findings (`AsyncEngine`,
  `SentenceTransformer`, and the runtime config logger) that require a typing
  or optional-import design decision, not a silent lint suppression.
- 6 are intentionally unused compatibility variables/imports in the search,
  enrichment, and CLI compatibility paths.

These exceptions are file- and rule-specific rather than global, so new Ruff
findings continue to fail the normal scan. None of the deferred items was
changed because doing so would be a behavior change outside this hygiene pass;
they should be handled in focused follow-up changes with tests.
