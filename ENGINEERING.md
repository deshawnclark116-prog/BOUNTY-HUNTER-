# Engineering mission and validation contract

## Objective
Earn legitimate bounties through reproducible, original, high-impact research, subject to explicit authorization and program rules. Optimize realized net dollars per research hour, not report count. Until actual outcomes exist, treat expected earnings and success rates as unknown.

## Architecture and boundaries
1. Opportunity intake: public program directories; human checks current eligibility, rewards, scope, methods, exclusions, confidentiality and AI rules. No target scanning or ranking by suspected weakness.
2. Local research: synthetic fixtures and explicitly authorized practice labs; evaluate security control observations. No live network access, exploit generation, credential access or automated submission in this repository.
3. Evidence review: compare expected and observed behavior, retain uncertainty, require independent verification and demonstrated impact. Never convert practice or automated flags into bounty claims.
4. Report review: fail closed on missing evidence, privacy or policy attestations. Human decides whether to submit via the official channel.
5. Outcome accounting: actual payouts, costs, hours, accepted, duplicate, rejected, and unresolved cases. Store sensitive records privately outside GitHub.

## Release gates
- G0: zero known scope/privacy boundary failures; incomplete and malformed inputs rejected.
- G1: synthetic truth-table controls all pass; unknown observations explicitly abstain.
- G2 (not met): independently authored, labeled local lab cases, including negative controls and ambiguous observations. Freeze rules before evaluation. Report precision, recall, coverage and false positives with sample counts. Aim for >=95% precision and >=80% recall on at least 100 independently labeled cases, with per-category metrics; do not treat targets as achieved merely because the truth-table tests pass.
- G3 (not met): demonstrated repeatability and complete human evidence review on authorized exercises. No private evidence in the public repository.
- G4 (not met): track actual permitted submissions and outcomes, including duplicates and time spent. Review strategy only from observed results; no claims of profitability without actual payments.

## Metrics
Precision = TP/(TP+FP); recall = TP/(TP+FN); coverage = evaluated/(evaluated+unknown). Publish denominators and abstentions. Report acceptance and duplicate rates among resolved submissions separately from pending ones. Net earnings = received payouts minus incurred costs; net hourly = net earnings divided by all recorded hours, including unsuccessful research.

## Baseline as of 2026-11-23
v0.1: 14 core self-check assertions.
v0.2: 26 additional assertions, including 48 deterministic truth-table cases (16 mismatches, 16 matches, 16 unknowns). These are regression cases, not independent vulnerability detection performance. No real vulnerabilities, submissions, or earnings have been demonstrated.

## Platform policy references
- HackerOne: https://www.hackerone.com/policies/code-of-conduct
- Bugcrowd: https://www.bugcrowd.com/resources/hacker-resources/code-of-conduct/
- Bugcrowd submission limits: https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/submissions-limit/

Read current official rules for each program and follow the stricter applicable terms.

## v0.3 defensive audit milestone
Added a local Kubernetes manifest reviewer grounded in a subset of the official Restricted Pod Security Standards. 25 authored fixture cases matched expected findings, including inheritance and OS-specific behavior; 6 malformed cases rejected. These are development regressions, not an independent holdout. G2 remains unmet. The module provides configuration guidance for owners or explicitly authorized reviewers, not exploitability assessments. No live testing or submission added.

## v0.4: official policy conformance repair
- Frozen v0.3 baseline: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45320939440
- Dataset: Kubernetes upstream commit 7c48c2bd72b9bf5c44d21d7338cc7bea77d0ad2a, Restricted v1.29 fixtures (88 cases).
- Baseline: TP 56, TN 18, FP 0, FN 13, errors 1.
- Candidate: commit 2bf7b7697925923120b255f6a629927d008f8df5; https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45321239316
- Candidate: TP 69, TN 19, FP 0, FN 0, errors 0. Internal regression workflow also succeeded.
- Repairs: AppArmor, host ports, proc mount, SELinux, version-specific sysctl allowlist, defaulted volume sources. Local defensive configuration review only.
- The 88 cases became a development/regression set when failure details were inspected. Candidate performance is not holdout performance. The same v1.29 fixture directories in Kubernetes v1.34.0 were checked by blob SHA and contain zero new cases, so they must not be counted as additional evidence.
- G2 remains unmet: fewer than 100 cases and no fresh independent holdout for the repaired candidate. No evidence of general vulnerability discovery or bounty earnings. Future evaluation should use separately authored version-matched cases and independent application-security lab benchmarks without double-counting variants.

## v0.5: independent application-security analyzer baseline
- Dataset: OWASP BenchmarkPython commit f1291485808b66e20ddb6b01b10dc71b3df8c8ba; 1,230 cases, 452 positive and 778 negative, 14 categories.
- Analyzer: unmodified Bandit 1.8.6, static analysis of public lab source only. No app execution or live testing.
- Evaluator: exact case and CWE match. 219 non-target CWE alerts are not adjudicated by this answer key and must not be interpreted as verified findings or false positives.
- Verified run: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45321431766
- Results: TP 108, TN 753, FP 25, FN 344, errors 0; precision 81.20%, recall 23.89%, specificity 96.79%, coverage 100%.
- Four categories had exact-CWE true positives; ten did not. This is an existing-tool baseline, not a novel detector. G2 application-security targets are not met.
- Future defensive assessment research: compare established static analyzers under identical source-only conditions and evaluate repair guidance, with a separate independent holdout before claiming improvements. Preserve all results including failures and do not tune against the full public answer key.
