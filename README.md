# Bounty Hunter

A zero-cost, offline-first bug bounty research starter. The goal is legitimate, verified findings, not scanner alerts or mass submissions. This is v0.10, not an autonomous vulnerability hunter and not a source of guaranteed income.

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

## v0.3 defensive configuration review

For businesses reviewing their own Kubernetes workloads or files explicitly provided for review, use the offline JSON manifest auditor. It requires a local regular file (maximum 2 MiB) and an explicit authorized-local flag. It does not connect to a cluster, run workloads, modify files, or send anything to a service.

```sh
node kube-review.js test
node kube-review.js audit examples/kube-demo.json --authorized-local
```

Exit codes: 0 = no gaps in the implemented subset, 1 = invalid input or command, 3 = one or more policy gaps. A zero exit does not establish security or full compliance.

Supported kinds: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob. JSON only. Covers host namespaces, HostProcess, privileged mode, non-root requirements, UID, escalation, seccomp, Linux capability add/drop, and volume types, with pod-level inheritance and init/ephemeral container handling. Linux-only controls are excluded for explicitly Windows workloads. Output contains field paths and remediation, not manifest names, environment values, image names or raw secrets.

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/

This is a partial static configuration check, not a schema validator, runtime security audit, or independent vulnerability discovery system. Policy gaps can be intentional and are not automatically bounty eligible. Review fixes in context with workload owners and test changes before rollout. Keep real manifests and outputs private.

Regression: 25 authored scenarios, 19 expected gaps, 6 malformed inputs rejected. Independent evaluation remains outstanding.

## v0.4 configuration benchmark
The patched Kubernetes auditor correctly classified all 88 official Restricted v1.29 fixture cases. These are now a development set, not a fresh holdout. See ENGINEERING.md for the baseline and limitations.

## v0.5 application security baseline
The Python benchmark workflow checks out the pinned public OWASP BenchmarkPython lab and runs Bandit 1.8.6 on its source files only. It does not run the web application or access a deployed target. The scorer matches each test file and intended CWE to the independently maintained answer key, records failures to evaluate, and reports unadjudicated alerts separately.

For a local Python project you own or have explicit permission to review, Bandit is also available as a defensive code-review tool:
```sh
python -m pip install bandit==1.8.6
bandit -r /path/to/authorized/local/source -f json -o /path/to/private/report.json
```
Keep the report private; it can contain source snippets. Treat alerts as review leads, not confirmed vulnerabilities or bounty claims. No source-code execution, live testing, or automated submission is part of this workflow.

## Local remediation tracking
Run `node remediation.js test` for regression tests, or
`node remediation.js review /path/to/private-assessment.json --authorized-local`
to summarize owner-authorized, human-reviewed remediation records. The input is a JSON object with authorization (owner_or_explicit_permission), as_of (ISO date), and records. Each record requires a unique id, state and priority. Confirmed issues need an owner, remediation and initial_review (reviewer, evidence_ref, date, result=confirmed). Resolved issues also require a distinct retest (reviewer, evidence_ref, date, result=passed). Not-applicable issues require initial_review with result=not_applicable and a rationale. Optional due dates support overdue tracking. This is an attestation checker, not independent proof. Keep all assessment data private and use only opaque local evidence references. Output is aggregate counts without source or evidence text.

## v0.8 unified local assessment
For explicitly authorized local review, prepare a private JSON bundle outside this public repository. Run:
```sh
node local-assessment.js review /path/to/private-assessment.json --authorized-local
```
Bundle fields: schema_version (1), authorization (owner_or_explicit_permission), optional kubernetes (array of JSON workload manifests), optional npm (object with lockfile, an npm v2/v3 package-lock JSON object, and snapshot, an object containing source, as_of and advisories in OSV JSON format), and optional remediation (the private ledger described above).
The dependency module supports stable npm versions, explicit affected versions and supported SEMVER/ECOSYSTEM interval events. Unsupported package identities, versions and advisory ranges are flagged as unknown. A match is a known advisory, not proof of exploitability or a novel finding. No match does not imply safety; the snapshot may be incomplete or outdated. The program does not fetch advisory data or send inventory to external services. Reports may contain package names and versions: keep them private.
The unified review marks absent sections and evaluation failures explicitly. Exit 3 means partial review, exit 1 invalid input, and exit 0 only means the implemented review sections ran; it does not mean the application is secure. Application analyzer experiments remain separate; the combined OWASP lab benchmark is not a production detector.

## v0.9 first-party policy design verifier
```sh
node policy-model.js test
node policy-model.js review examples/policy-model.json --authorized-local
```
This standalone module uses no scanner or external dependency. It compares an explicitly supplied, owner-approved finite authorization contract against a local declarative model of access rules. It enumerates the declared role/action/resource combinations, three resource relationships (own, same_tenant, other_tenant), and two authentication states. The semantics are default deny with explicit deny overriding allow. Rules support exact selectors or a wildcard. Missing contract rows remain unknown; overlapping decisions are review leads. Only the supplied policy model is checked, not actual deployed behavior. Do not submit model mismatches as vulnerability reports. Keep actual designs and review results private. See the synthetic example for the JSON shape.

## v0.10 conditional authorization design review
```sh
node conditional-policy.js test
node conditional-policy.js review examples/conditional-policy.json --authorized-local
```
Schema v2 accepts explicit owner-provided local cases and declarative rules. Rules use role/action/resource selectors, allow/deny effects, optional when and unless expressions, and default deny with explicit deny precedence. Expressions support and/or/not, exists, typed equality and inequality, numeric comparisons and scalar list membership. Operands are literal values or bounded attribute paths under principal/resource/context. No arbitrary expression execution. Missing attributes and incompatible types produce unknown when they can affect a decision. The sample intentionally contains an unresolved case and returns exit 3. Exit 0 means a complete model review, not proof of security. Case identifiers and model decisions are reported; attribute values are not echoed. This verifier does not extract policies from applications, evaluate deployed behavior or establish exploitability. Keep real designs private. The original v1 verifier remains available.
