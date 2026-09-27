# Phase 1 Architecture

All network access by assessment modules is mediated by `ControlledTransport`. Scope is deny-by-default and checked before each request and redirect hop. Callback authorization is a separate capability and never grants general host assessment scope. Evidence is redacted before atomic JSON persistence. ACTIVE operations require explicit authorization through `SafetyPolicy`.
