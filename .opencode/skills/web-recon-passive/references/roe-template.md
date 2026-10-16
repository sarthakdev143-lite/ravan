# Rules of Engagement template

Requires explicit user sign-off. Nothing outside the RoE without fresh approval.

## 1. Parties & authority

Owner/operator authorizing, tester/agent role, authorization proof attached.

## 2. Targets IN / OUT

In-scope hosts, paths, accounts, test windows. Explicit exclusions
(hosting, CDN, third-party services, production data). Third parties out
by default.

## 3. Authorization tiers

- **Tier 0 passive:** public-info review only. Always allowed once scoped.
- **Tier 1 active-safe:** banner/version reads, header checks with written OK.
- **Tier 2 intrusive:** fuzzing, injection, brute-force, exploitation —
  written permission + window + contacts required. Never assumed.

## 4. Forbidden techniques

DoS, social engineering, physical, credential replay, live transactions,
lateral movement, third-party probing. No exceptions inside this RoE.

## 5. Windows, data handling, contacts, stop conditions

Test windows, PII/secrets handling (redact, rotate on exposure), emergency
contacts, stop-on-detection conditions, rollback expectations.

## Sign-off

Owner signature + date. Agent proceeds only after sign-off is recorded.
