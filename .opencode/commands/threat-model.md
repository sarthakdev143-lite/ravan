---
description: Build a threat model for a target. Assets, trust boundaries, STRIDE per boundary, attack trees for crown-jewel goals, kill-chain mapping.
agent: ravan
---

Threat-model `$TARGET` (context: `$CONTEXT` — stack, data, boundaries if known).

1. If architecture is unknown, establish it first (static SPA / SSR / API / CMS + data flows). No findings before the model.
2. Produce: assets ranked by value, trust boundaries enumerated, STRIDE per boundary, 1–2 attack trees for the top goals (AND/OR paths), kill-chain mapping showing where current posture breaks the chain.
3. Map relevant OWASP (2021 + 2025 delta, API, LLM as applicable) categories and MITRE ATT&CK tactic/technique IDs onto each path.
4. Save to `.opencode/security/threat-model-$TARGET.md` and state the top-3 paths a defender should kill first, with effort tags.
