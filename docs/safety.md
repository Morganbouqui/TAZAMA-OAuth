# Safety

Phase 1 contains no OAuth vulnerability testing. Network requests require explicit scope. Redirects are manually evaluated before following. ACTIVE operations require `--active`; HIGH_IMPACT requires a separate confirmation mechanism. Raw secrets are not persisted by the evidence store.
