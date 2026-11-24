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
