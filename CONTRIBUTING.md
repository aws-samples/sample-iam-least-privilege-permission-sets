# Contributing to LP2PS

Thank you for contributing. Because this project is a security tool that produces IAM policies, a few
invariants must always be upheld.

## Invariants you must uphold

1. **Read-only.** Code that runs against analyzed accounts calls only allowlisted describe/list APIs.
   Adding a write API makes `test_awsguard` fail.
2. **Deterministic core.** Analysis and synthesis logic produces the same output for the same input. Do not
   use `datetime.now()` or `random` in the core.
3. **AI is purely additive.** AI results are isolated under the `ai_suggested` namespace, and the
   deterministic core never imports `lp2ps.ai`.
4. **Customer-agnostic.** Account IDs, ARNs, persona names, and thresholds live only in
   `config/<customer>.yaml`. Do not hardcode them in code or tests.

## Development workflow

**Install the engine before the backend.** The backend reuses the engine's contract
(`models.py`) and storage layer, so it needs the `lp2ps` package importable. That dependency is
deliberately not declared in `backend/pyproject.toml`: `lp2ps` is a local sibling package with no
public PyPI release, and declaring it by name would let pip resolve the name against the public
index instead. Install engine first — into the same virtualenv, or with the backend venv able to
see it.

```bash
# Engine (install this first)
cd engine && pip install -e '.[dev]'
pytest                     # all tests (especially test_awsguard, test_determinism)
bandit -r lp2ps            # SAST
pip-audit                  # dependency vulnerabilities

# Backend API (requires the engine above; otherwise ModuleNotFoundError: lp2ps)
cd backend && pip install -e '.[dev]'
pytest

# Frontend
cd frontend && npm install
npm run typecheck && npm run build

# Infra (CDK)
cd infra && npm install
npm test                   # assertion tests
npx cdk synth --all -c config=../config/example.yaml
```

## Security scanners (pre-commit)

`.pre-commit-config.yaml` defines shift-left gates such as detect-secrets, bandit, and private-key checks.

```bash
pip install pre-commit
pre-commit run --all-files      # full scan (recommended before committing)
pre-commit run                  # staged files only
```

> **Note on automatic git hook installation:** In managed environments, `core.hooksPath` may be set to a
> security tool (e.g., a corporate security hook), which can cause `pre-commit install` to be rejected. In
> that case run `pre-commit run` **manually / in CI** as shown above — do not disable the system hook. CI
> (`.github/workflows/ci.yml`) enforces the same scanners, so regressions are blocked in the PR.

## PR checklist

- [ ] `pytest` passes (including read-only and determinism tests)
- [ ] No hardcoded secrets or credentials (detect-secrets)
- [ ] New dependencies are not copyleft-licensed (GPL/LGPL/AGPL/SSPL)
- [ ] For UI changes, verified actual render (passing transpile alone is not sufficient)
- [ ] `frontend/src/api/types.ts` and `engine/lp2ps/models.py` contracts stay in sync

## Commits

Use clear commit messages and split work into single logical changes.
