# Legal Scope & Responsible Disclosure

Read this before assessing any target you do not own.

## The authorization question

Unauthorised access to computer systems is a criminal offence in most jurisdictions. "It was
only passive" is **not** a defence — the law generally turns on access without authorisation,
not on whether damage occurred.

| Jurisdiction | Primary statute |
|---|---|
| United States | Computer Fraud and Abuse Act, 18 U.S.C. §1030 |
| United Kingdom | Computer Misuse Act 1990, s1–s3 |
| European Union | Directive 2013/40/EU on attacks against information systems |
| India | Information Technology Act 2000, s43 and s66 |
| Australia | Criminal Code Act 1995, Part 10.7 |

Note that jurisdiction follows the **server**, not the assessor. A target hosted in France
is subject to EU/French law regardless of where you sit.

## Where passive review sits

Passive review — reading DNS records from a public resolver, fetching pages, inspecting
certificates, analysing publicly served JavaScript — is broadly comparable to visiting a
website. It is the same class of activity performed by search engines, link previewers,
certificate transparency monitors and services like Mozilla Observatory.

That does **not** make it automatically lawful in every jurisdiction or every
circumstance, and it does not authorise:

- using a discovered key or endpoint
- submitting data to forms
- sustained request volume that degrades service
- continued probing after being told to stop
- accessing anything behind authentication

This skill enforces some of that mechanically (request budget, delay, no form submission,
no scanning code at all). The rest is your judgement.

## Practical rules

1. **Identify yourself.** Set `--contact` to a real reachable address. It goes in the
   User-Agent. An anonymous scan is indistinguishable from an attack, and operators who
   find it in their logs will treat it as one.
2. **Keep volume trivial.** Default budget 400 requests, 0.7 s delay. For a small shared
   host, raise the delay. Never loop the tool.
3. **Stop on refusal.** If you get 403/429, or a block, or a message from the operator —
   stop. Do not work around it.
4. **Do not touch what you find.** Especially third-party form endpoints and API keys.
   Submitting "just a test" creates real records in a real company's inbox and recruitment
   pipeline, and may constitute unauthorised use of a third-party service.
5. **Handle data carefully.** Anything you collect may include personal data (staff names,
   email addresses, client lists). Store it securely, do not publish it, and delete it when
   the disclosure is resolved.

## Writing the disclosure

Report to the owner, not publicly. In order of preference:

1. A `security.txt` contact, if one exists.
2. A published security or abuse address.
3. Any contact address on the site.
4. The hosting provider's abuse team (e.g. `abuse@hostinger.com`), identifying the domain.
5. The registrar's abuse contact, via WHOIS/RDAP.

Include:

- **What you did**, explicitly stating it was passive and unauthenticated. Listing the
  technique establishes good faith and helps the owner understand the exposure.
- **What you found**, with reproducible evidence — the exact record, header or file offset.
- **Why it matters**, in terms of impact on their business, not CVSS arithmetic.
- **How to fix it**, concretely, with the exact configuration or DNS record.
- **A request log**, so they can see precisely what was requested. This skill appends one
  automatically.
- **A timeline**: state that you will not disclose publicly and propose a window
  (customarily 90 days), and that you will extend it on request.
- **No demands.** Do not ask for payment, bounty, employment or recognition unless the
  organisation publishes a bug bounty covering this scope. Unsolicited invoices after an
  uninvited assessment are how researchers end up in legal trouble.

## If they own the target

Confirm in writing before any active testing. A scope document should cover:

- exact hostnames and IP ranges in scope, and explicitly out of scope
- permitted techniques and prohibited techniques (denial-of-service testing is almost
  always prohibited)
- testing window, and who to contact during it
- data handling: what may be collected, where it is stored, when it is deleted
- third-party services — a hosted form provider, CDN or analytics vendor is **not** in
  scope just because the target's site talks to it. Testing them requires their own
  authorisation.
- emergency abort criteria and contact
- reporting format and deadline

Without that document, stay passive.
