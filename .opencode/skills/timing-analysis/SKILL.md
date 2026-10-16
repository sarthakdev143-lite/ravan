---
name: timing-analysis
description: Use when analyzing code for timing side-channel vulnerabilities in cryptographic or authentication code.
---

# Timing Side-Channels

## When to Use This Skill
- Checking cryptographic code for constant-time operations
- Detecting secret-dependent branches in authentication code
- Understanding how compilers optimize away constant-time guarantees
- Fixing timing vulnerabilities in comparison functions

## Workflow
1. Identify security-sensitive code: password comparison, signature verification, HMAC
2. Check for secret-dependent branches: if/else on secret values
3. Check for secret-dependent array accesses or memory operations
4. Verify constant-time implementations: use specialized libraries when possible
5. Test with timing measurements: measure execution time across different inputs
6. Review compiler output: verify optimizations don't break constant-time properties
7. Fix: replace secret-dependent branches with constant-time alternatives

## Rules
- Use established cryptographic libraries instead of implementing your own
- Never compare secrets with `===` or `strcmp` — use constant-time comparison
- Don't branch on secret data — use bitwise operations instead
- Test timing across different input values to detect variations
- Be aware that JIT compilers and CPU optimizations can break constant-time code
- Use tools like `ct-grind` or `timecop` to verify constant-time properties
