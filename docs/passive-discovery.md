# Phase 2 passive OAuth/OIDC intelligence

Phase 2 is reconnaissance and protocol mapping, not exploitation. `discover` inspects an authorized resource for OAuth/OIDC references and observed authorization requests. `oidc discover` retrieves only the standard in-scope OpenID Provider metadata location; endpoints named by metadata are classified before any possible request and out-of-scope endpoints remain `NOT_REQUESTED`. `map` distinguishes observed flows from provider-supported flows. `analyze` summarizes observations without converting missing state, missing PKCE, or a flow type into vulnerability claims.

Authorization parsing preserves repeated and unknown parameters. Endpoint inventory and relationship objects are JSON-serializable and use the existing filesystem/JSON architecture. Discovery evidence reuses the Phase 1 evidence store and deliberately omits raw HTML response bodies from persisted discovery evidence, preventing authorization-page state/nonce values from being persisted accidentally.

All Phase 2 network access uses `ControlledTransport`; no Phase 2 module imports a separate networking client.
