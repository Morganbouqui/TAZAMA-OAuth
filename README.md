# TAZAMA-OAuth

Independent OAuth/OIDC assessment application. Phase 1 provides packaging, CLI, workspace, strict scope/callback policy, controlled HTTP, evidence/redaction, safety foundations, and tests. OAuth discovery/testing is intentionally deferred.

## Development

```bash
python -m venv .venv
# activate the environment
python -m pip install -e '.[dev]'
tazama-oauth --version
tazama-oauth --help
pytest
```

TAZAMA-OAuth is independent of TAZAMA and neither imports nor modifies it.
