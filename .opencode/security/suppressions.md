# Suppressed false positives — reason + evidence hash required

Never re-flag a pattern listed here without NEW evidence. Check this file
before writing any finding.

| Pattern | Reason | Evidence hash / ref | Date |
|---|---|---|---|
| _(example)_ react-router `http://localhost` fallback base | framework default, not an internal URL | signature-filtered | _ |
| _(example)_ Algolia search-only key | public by design, abusable endpoint at most | key prefix `...` | _ |
