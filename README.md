# Bounty Hunter

A zero-cost, offline-first bug bounty research starter. The goal is legitimate, verified findings, not scanner alerts or mass submissions. This is v0.2, not an autonomous vulnerability hunter and not a source of guaranteed income.

## Run (Node.js 20+)

```sh
node bounty.js discover
node bounty.js test
node bounty.js practice examples/practice.json
node bounty.js review examples/policy.json
```

The example policy is deliberately blocked. Copy it outside this public repository and fill it in only after personally reading the current official brief and confirming eligibility. A READY_FOR_MANUAL_REVIEW result is a checklist result, not permission to access a system. No external scanning, exploit execution, account access or report submission is implemented.

## Research workflow

1. Open an official program directory from discover. Pick a paying program that accepts your participation and the intended research method.
2. Read its current brief, exclusions, AI rules and disclosure restrictions. Record these privately. Do not share confidential program information with AI tools without permission.
3. Practice locally with synthetic fixtures, or separately use authorized learning environments such as OWASP Juice Shop or PortSwigger Academy.
4. Manually verify any real finding within the published rules. A local practice observation or configuration flag does not establish a real vulnerability or bounty eligibility.
5. Use the private report template; submit only substantiated, original findings through the official channel after review. Never publish undisclosed findings, credentials, private program scope or real evidence in this public repository.

## Current coverage
- Official program directory links (not a live payout feed).
- Fail-closed, seven-day policy freshness and participation/AI checklist.
- Synthetic session-cookie configuration review, with clean and defective controls.
- Automated regression checks, including rejection of live inputs.

## Official policy references
- https://www.bugcrowd.com/resources/hacker-resources/code-of-conduct/
- https://docs.bugcrowd.com/researchers/onboarding/ai-privacy-security/
- https://www.hackerone.com/terms/disclosure-guidelines

## Next milestone
Expand local benchmarks across security controls, measure false positives, and add a private opportunity and outcome ledger before considering authorized real-world research. Track confirmed findings, duplicates, rejections, payouts and hours spent separately.

## v0.2 research and accounting

Read [ENGINEERING.md](ENGINEERING.md) for the mission, metrics and promotion gates.

```sh
node research.js test
node research.js benchmark
node research.js practice /path/to/synthetic-fixture.json
node research.js report /path/to/private-checklist.json
node research.js ledger /path/to/private-ledger.json
```

The benchmark checks expected vs observed boolean security controls in synthetic fixtures; null means unknown. It does not independently discover vulnerabilities. Ledger records use unique id, status, hours, cost_cents and payout_cents; only actually paid outcomes count as revenue. Keep real research records outside this public repo. The report checker validates completeness and self-attestations, not authenticity.
