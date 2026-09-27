# Token, JWT and OIDC validation intelligence

Decoding is not verification. Signature verification is not claim validation. Local token construction is not server acceptance. TAZAMA-OAuth keeps these states separate.

`token inspect` and `token compare` are local-only and generate no network traffic. Prefer `--file` or stdin for sensitive tokens to avoid shell history. Raw tokens, Bearer headers, authorization codes and session secrets must not be persisted; fingerprints are used for correlation.

JWT inspection classifies opaque/JWT/JWS/JWE-like/unknown structures, decodes JOSE headers and claims without trusting them, analyzes exp/iat/nbf/auth_time, and reports JOSE observations such as alg=none, symmetric algorithms, kid/jku/jwk/x5u/crit. These are observations, not vulnerabilities.

Verification supports HMAC only with an explicitly supplied secret and RSA verification with explicit/JWKS public material. There is no secret brute forcing. JWKS selection uses kid/alg/kty/use and reports ambiguity rather than choosing arbitrarily. JWKS network retrieval must use ControlledTransport and explicit project scope.

OIDC ID-token validation exposes signature, issuer, audience, azp, expiration, iat, nbf and nonce separately. Expected issuer/audience/nonce/client ID must come from explicit trusted input/configuration or authorized metadata, never from the token's own untrusted claims.

Phase 4 does not automatically spray token variants at discovered endpoints. Any future server-acceptance test remains ACTIVE, explicitly scoped, tester-controlled and evidence-backed.
