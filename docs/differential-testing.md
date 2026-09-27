# Phase 3 controlled differential testing

Phase 3 adds ACTIVE, explicitly gated differential testing for state binding, redirect URI validation and PKCE behavior. TARGET never grants scope: every network command loads explicit project scope from `.tazama_oauth/scope.json`. Callback receive authorization remains separate from assessment-target authorization.

Without `--active`, test commands create/display plans but transmit no mutated requests. With `--active --dry-run`, mutations are still not transmitted. With `--active`, the central engine applies scope/callback checks and uses only `ControlledTransport`.

Baselines store normalized/redacted request characteristics and response hashes rather than raw secrets. Mutations are structured `TestMutation` records. Comparisons are deterministic: status, Location, redirect chain, body hash/length, OAuth errors, code/token-like response indicators. Ordinary differences do not establish a vulnerability.

Confidence transitions remain OBSERVED/POTENTIAL/LIKELY/CONFIRMED/NOT_REPRODUCED. Phase 3 only promotes to CONFIRMED when a caller supplies evidence of a reproduced concrete security consequence; pattern matching alone cannot do so.
