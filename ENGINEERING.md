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

## v0.6 experiment: second established source analyzer
- Candidate: unmodified Semgrep Community Edition 1.130.0 with the Python portion of semgrep-rules pinned to a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2.
- Same OWASP Python lab source and exact-case/exact-CWE evaluator as v0.5. Only static analysis of the public lab; no application execution, live targets or automated submissions.
- Normalization preserves distinct CWE IDs from published rule metadata; findings without CWE metadata are counted separately, and unattributed analysis errors invalidate the score rather than silently being treated as negatives.
- Comparison workflow: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45321685819
- Predeclared interpretation: report each analyzer separately, including coverage and unadjudicated alerts. This public benchmark is not a fresh holdout for a combined candidate selected using its results. Do not claim real-world detection or bounty profitability.

- First comparison attempt failed before analysis: the pinned Semgrep release imported pkg_resources, absent from the runner's environment. No score exists for that attempt.
- Environment-only correction: setuptools 80.9.0 pinned; analyzer, rule snapshot, dataset and scoring unchanged. Corrected run: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45321752484

## v0.7: verified second baseline and business remediation
- Corrected Semgrep run succeeded: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45321752484
- TP 71, TN 705, FP 73, FN 381, errors 0. Precision 49.31%, recall 15.71%, coverage 100%. 296 non-target case/CWE alerts and 2,914 alerts without mapped CWE metadata are not adjudicated.
- Bandit remains the stronger overall standalone baseline on this exact-CWE metric. Neither meets application-security gates.
- Public-lab comparison experiment: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45322132797 . Both reports scored separately and via union/intersection only for jointly evaluated cases. This is descriptive lab evidence, not a promoted production detector.
- Local remediation tracker added, 19 authored assertions passed. It separates unreviewed alerts from human-confirmed issues and requires separate dated retest evidence to record a repair as resolved. Evidence attestations are not independently authenticated. Aggregate output omits identifiers and source/evidence data.

## v0.8: unified defensive local assessment
- Verified previous public lab union: TP 148, TN 694, FP 84, FN 304; precision 63.79%, recall 32.74%. Intersection: TP 31, FP 14, FN 421, TN 764. Neither combination qualifies for promotion. Run 45322132797.
- New local npm lockfile/advisory snapshot reviewer and unified local assessment entry point. Stable versions and supported interval types only; unknowns are explicit; no external requests.
- 12 dependency regression assertions and 8 integration assertions passed against the committed module source. A four-entry controlled lockfile tested using published GHSA-35jh-r3h4-6jhm correctly matched two affected versions and excluded two other entries (one fixed version, one unrelated package). This tests known-advisory matching, not novel vulnerability discovery.
- No improvement to the application vulnerability benchmark is claimed. G2 remains unmet. No automatic bounty submissions, live target scanning, exploit execution, or real earnings.

## v0.9: original finite policy model verification
- First-party module policy-model.js, commit c055f673ed0b01989ec7c8748f6689525ffe6ff1. No external scanners or network calls. Exhaustive verification of a finite owner-provided authorization model against an explicit contract. Default deny, deny override, unknown contract coverage, overlap reporting.
- 36 authored regression assertions passed before commit, including 24 deterministic single-cell changes to a synthetic model; each caused the expected one-cell contract mismatch. Not independently authored cases, not discovery of new real-world vulnerabilities, and not comparable to the OWASP code benchmark.
- Limits: declarative model only, no extraction from deployed systems or actual application behavior. No claim that the implementation matches the model. G2 application-security gate remains unmet.

## v0.9 frozen-engine differential stress test
- Engine frozen at c055f673ed0b01989ec7c8748f6689525ffe6ff1. Benchmark af304fb4655b2c8bab34b97b564f09432e28c4cd.
- 302 models: 300 seeded synthetic, one maximum-size synthetic model, one translated Cedar README example. Separately implemented set-expansion oracle agrees on all 302. 47,772 states, 43,145 labeled contract states, 4,627 unknown. 2,664 overgrants, 11,303 undergrants, 4,273 overlaps, 29,178 contract matches. Overlaps can coincide with other categories.
- All 30 rule-order checks and 10 malformed rejection cases passed. Maximum-size model: 15,360 states. Both documented Cedar decisions matched; the remaining 10 states in the translated example were unspecified, not independent labels.
- The first generator had correlated random draws and zero overlaps; corrected benchmark generator only and required nonzero overlap/mismatch coverage. Original engine unchanged.
- Synthetic differential evidence is not a real-world vulnerability benchmark. Only two independently documented decisions were translated; no external authorization engine was executed. General application discovery performance remains unproven.

## v0.9 exhaustive bounded conformance test
- Frozen engine unchanged; benchmark commit 40e8ee06d482e2f7ffa77757c9725ada44f6332a.
- Exhaustively enumerated 4,096 permit/deny masks over six states, each evaluated with three complete contracts and one empty contract: 16,384 model evaluations, 98,304 state evaluations, zero disagreements with closed-form bitmask expectations.
- Maximum declared model: 15,360 states and 200 overlapping rules; 15,360 conflicts and 30,720 total findings correctly reported. Reversing rule and contract order produced identical results; sample input remained unchanged.
- 20/20 malformed model inputs rejected. Total assertions 16,407, zero failures. Maximum model evaluation measured 923 ms in the test isolate (not a production performance guarantee).
- This is synthetic conformance of a bounded policy verifier, not a vulnerability-discovery benchmark. No general application-security performance improvement or independent holdout claim.

## External authorization conformance challenge
- Pinned upstream: cedar-policy/cedar-integration-tests at aff4b8b99acb71aa5b288fa236295cccbb40d541.
- Selected complete multi and example_use_cases request suites (17 suite files, excluding auxiliary schema/policy JSON). Nine suites have unconditional scope predicates representable by the finite model after expanding public fixture entity membership; eight conditional/attribute suites are excluded from evaluated accuracy and included in coverage denominator.
- Test-only adapter translates pinned public source policies into finite rules without consulting expected decisions. Expected request labels are used only as contracts. No live applications, external targets or general Cedar parser. The adapter and engine are evaluated together; the benchmark does not measure discovery or exploitability.
- Report correct, incorrect, allow/deny counts, unexpected grants/denials, and unsupported requests. No promotion based solely on the representable subset.
- Run: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45324430903
