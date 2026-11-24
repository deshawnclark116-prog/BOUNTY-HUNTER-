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

- Verified GitHub Actions job 138210486032: 61 external request labels across the selected 17 suites; 31 evaluated and correct, 0 incorrect, 30 unsupported. 16 allow and 15 deny labels among evaluated requests, zero unexpected grants or denials. Supported-case accuracy 100%, selected-suite coverage 50.82%. These results concern translated policy conformance only, not independent vulnerability discovery. The engine itself was unchanged. G2 remains unmet.

## v0.10 conditional policy model
- First-party verifier conditional-policy.js, commit 5bfd2b2107e6499c656c48ce85b775b7ba4a79b0. 33 authored checks passed. Bounded declarative conditions, typed comparison, attribute paths, list membership, boolean composition and explicit unknown semantics; no dynamic code execution.
- Eight previously unsupported public Cedar fixture suites translated into explicit local contracts and conditions in benchmark/cedar-conditional.js. Translation uses public source policy definitions and fixture entity facts; expected labels are comparison contracts only. This is a known development set, not a fresh holdout.
- Verified run https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45324816722, job 138211762969, both stages passed. Conditional stage: 30/30 correct, 17 allow, 13 deny, zero incorrect/unknown. Earlier finite-model stage: 31/31 correct. Together the two verifiers and fixture-specific adapters cover 61/61 decisions in the selected 17 suites. No general Cedar parser or complete Cedar language support is claimed.
- Scope: explicit owner-provided local models only. External benchmark demonstrates policy conformance, not vulnerability discovery in application implementations. G2 remains unmet; fresh independent validation required.

## Frozen v0.10 head-to-head with OPA
- Conditional engine frozen at commit 5bfd2b2107e6499c656c48ce85b775b7ba4a79b0 (blob c70c89e6ec62aeb390e42d54137820aca30ae2bf).
- New public design: OPA HTTP API authorization documentation, pinned upstream commit 7b037a97dd9b465dedb1c565f778ea06ac5569ea. Base and HR-extended published policies executed by OPA v1.4.2. Our unchanged conditional evaluator receives a manually translated policy and equivalent explicit attributes. No deployed service or HTTP requests.
- Seven documented expected decisions plus generated, nonduplicated input combinations within each stage. Report documented accuracy separately from OPA agreement on generated inputs; neither is a measure of independent vulnerability discovery.
- Comparison run https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45325225063. No general OPA equivalence or superiority claim from this narrow sample.

- Verified successful OPA comparison job 138213081874: base 216/216 agreement (3 documented labels, 213 generated variations), HR extension 216/216 agreement (4 documented labels, 212 generated variations). Total 432/432 agreement, zero disagreement or unknown; both evaluators matched all seven documented labels. OPA allowed 21 and denied 411 cases overall. These are two stages of the same published design, not 432 independently authored policies. No change to the conditional engine. Do not interpret agreement as general superiority or actual vulnerability discovery.

## Frozen v0.10 three-way policy comparison
- Engine unchanged (conditional-policy.js blob c70c89e6ec62aeb390e42d54137820aca30ae2bf). New published design: profile authorization example from OPA policy-testing documentation, pinned source commit 7b037a97dd9b465dedb1c565f778ea06ac5569ea.
- Execute the original four published OPA tests; evaluate the same documented requests and generated variations with OPA v1.4.2, Casbin 1.36.0 and the local verifier. Casbin and the local verifier use explicit fixture-specific translations; OPA executes its original published rules. No live applications or network tests.
- Report documented-label accuracy, generated-case agreement, coverage, definitive disagreements and unknown decisions. The documented source maps an undefined OPA allow rule to deny, while the local verifier preserves uncertainty when missing attributes affect its decision. Do not score abstention as a correct denial.
- Run: https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45325482507

- First three-way run failed because Casbin's matcher parser rejected the not-equal operator. The test-only adapter was corrected to represent identity presence explicitly; engine, cases and expected labels unchanged.
- Verified corrected run https://github.com/deshawnclark116-prog/BOUNTY-HUNTER-/actions/runs/45325535485, job 138214111168: 96 cases, all four published labels correct for all three engines; 94 three-way agreements, two local abstentions, zero definitive disagreements, zero OPA/Casbin disagreements. All 70 generated complete cases agreed; 20 of 22 generated missing-identity cases agreed and two abstained. Coverage 97.92%.
- Across the two distinct comparison experiments: 528 case evaluations, 526 matching decisions, two abstentions, zero definitive disagreements. Only 11 are documented expected labels; remaining 517 are generated inputs. These are policy-model conformance and agreement metrics, not general vulnerability detection accuracy or proof of superiority.

## v0.10 limits: incomplete information and correlated conditions
- Frozen engine blob c70c89e6ec62aeb390e42d54137820aca30ae2bf. Benchmark commit 6127bdbbdcbc8f0471d0355028ef51ac26ff5677. Six authored local policy designs, 243 partial/complete Boolean assignments per design. Separate explicit truth functions and exhaustive completion oracle; synthetic, not independently authored vulnerability labels.
- 1,458 cases: 905 correct definite decisions, 364 justified unknowns, 189 avoidable unknowns, zero unsound definite decisions. All 192 completely specified cases correct. 189 avoidable unknowns occur in correlated partition (27), mutually exclusive conditions (81), and dependent permit/deny (81). This shows conservative local three-valued evaluation is not complete under correlated missing attributes. Correct definitive coverage among 1,094 logically decidable cases is 905/1,094 (82.72%).
- Maximum rule/case dimensions: 200 rules, 2,000 cases, 400,000 pairs; all 2,000 labeled decisions correct, expected and observed conflicts 500. Measured 1,244 ms in test isolate. Separate 11,800-expression-node budget test with 100 cases: 100/100 correct, 539 ms. All 12 malformed models rejected. Timings are test-environment observations, not production guarantees.
- No change to engine. Avoidable uncertainty is retained as an open model-quality issue, not counted as a pass or an unsafe definite decision. New benchmark is regression evidence, not proof of general security or discovery capability.

## v0.11 bounded correlated-predicate refinement
- Candidate commit c639490e648b98fb8db20ad0388998965ae8c209. Refine unresolved model decisions by sharing identical missing-value predicates across conditions and checking invariant outcomes across bounded abstract Boolean completions. Distinct predicates are independent in the abstraction; no attributes are invented, and known existence checks are unchanged. Existing direct decisions remain unchanged. Maximum eight abstract atoms per case and one million estimated evaluation units per review; unresolved cases retain unknown. This is model reasoning, not runtime authorization.
- Development regression: 1,458 cases, 1,094 correct definite decisions (previously 905), 364 justified unknowns, zero avoidable unknowns (previously 189), zero unsound decisions. All 192 fully specified cases, 2,000 maximum-dimension cases, 100 expression-budget cases, 12 malformed models and 33 internal assertions passed.
- Fresh post-freeze synthetic validation: benchmark commit 37b71ab54e46d8cad284a0c3e930c93644f0f40a. Forty new seeded Boolean designs and 3,240 partial/complete inputs; independent bitmask truth oracle; 2,623 correct definite (363 allow, 2,260 deny), 617 justified unknown, zero avoidable unknown or unsound decisions. Four conservative guard checks passed. This remains authored synthetic validation, not a blind external holdout or a vulnerability discovery benchmark.
- Prior Cedar/OPA/Casbin workflows trigger automatically on the candidate change; check actual job results before claiming external regression success.

## Frozen v0.11 typed-domain challenge
- Engine unchanged at c639490e648b98fb8db20ad0388998965ae8c209. New benchmark 926608a83c6d9b8ad828d2f073a0e4a17fd9b55b; 12 authored synthetic numerical/categorical policy designs, 180 complete/partial inputs per design, independent finite-domain completion oracle. Domains are oracle-only and were not given to the verifier.
- 2,160 cases: 1,851 correct definite decisions, 105 necessary unknowns, 204 unknowns avoidable under the oracle's declared domains, zero unsound definite decisions under those domains. All 1,056 completely specified cases correct. Domain-conditioned unknowns are not unsafe decisions or proof of defects absent a valid domain contract.
- Limitation: distinct predicates on one attribute are treated independently, so numerical interval relationships, equality complements, mutually exclusive categories and set containment are not fully resolved. Future design work may support explicit owner-provided typed domains, bounded verification and abstention when domain assumptions are absent.
- Verified v0.11 existing CI successes: Cedar run 45326132649, OPA/Casbin run 45326132792, offline regression 45326191838. No change to engine in this turn. No independent real-world vulnerability discovery or general engine superiority claim.

## v0.12 explicit finite-domain refinement
- Engine commit 048674496eb0e6edb3aa98c4fbe82a13335482e3. Optional schema v2 domains array contains explicit attribute paths and exhaustive homogeneous finite scalar values supplied by the owner. Known values outside a declared domain, duplicate values, unsafe paths and overlapping paths are rejected. Hypothetical values apply to comparisons only; observed existence remains factual. Up to 256 domain assignments per case and a shared bounded refinement work budget. No runtime authorization or discovery claim.
- Development set: unchanged no-domain baseline 1,851 definite, 105 necessary unknown, 204 domain-conditioned unknown. With supplied domains: 2,055 definite, 105 necessary unknown, zero avoidable unknown or unsound decisions in 2,160 cases. 1,056/1,056 complete cases remain correct.
- New post-freeze synthetic validation: commit 025e3036cdf4f5cf0797b5bc84018ae237f6a3d7, six new cross-attribute designs, 720 cases: 647 correct definitive, 73 justified unknown, zero avoidable or unsound decisions; 11/11 guard checks passed.
- Verified external regression workflow success on engine commit: Cedar 45326588540; OPA/Casbin 45326588438; offline regression 45326588600. New domain tests added to CI in 2ef82c023402e640ba0d3362e3de2e341e3946da. Domain assumptions must be accurate and exhaustive; no claim of general policy completeness, independent blind validation or application vulnerability discovery.

## v0.13 observed workflow review
- First-party workflow-review.js at 2fa5732aef599a81f37b3fda167a36ce98aa4cba. Checks explicit owner-authorized local recorded workflow events against a deterministic design contract; reports state continuity, declared transition consistency, rejected-event state change and sequence problems. Missing observations and sequence gaps remain unknown unless a discrepancy is independently established. No event generation, runtime application testing or exploitability claim.
- 87 authored assertions passed, including 72 single-event matrix cases. Separate synthetic benchmark 078c27d9ae55d7b4ec530cb614ed5ea4f4e63962: 300 traces, 12,000 events, expected and observed 775 consistent, 5,026 inconsistent, 6,199 unknown; zero trace-level count disagreements. Maximum declared event budget 50,000 events evaluated, all consistent, 82 ms observed in test isolate (not production guarantee).
- This is a new local trace-conformance capability, not independent source-code analysis or discovery of real vulnerabilities. Benchmark is authored and requires external validation; original authorization engine unchanged.

## Bounty-style evidence readiness challenge (v0.13 frozen)
- Benchmark commit 3049ce363293cd4c91dec2606821f1b3b1b8324e; 10 authored local workflow scenarios, no real assets or reports. Four known discrepancies, two negative controls, four intrinsically uncertain scenarios. Results: 3 TP, 2 TN, 0 FP, 1 abstained positive, 4 correctly unresolved. Precision 3/3, recall including abstention 3/4; tiny synthetic sample, not independent validation.
- Workflow limitation: an independently established accepted undeclared transition is not recognized when the resulting state is missing. Report checklist blocked 10/10 honestly labeled practice cases and 17/17 missing-required-field variants, but a synthetic self-attested complete checklist returned READY_FOR_HUMAN_SUBMISSION_DECISION. The checklist does not authenticate evidence; this is not permission, human approval or a submission. No actual vulnerabilities verified or reports submitted.
- Verified prior v0.13 offline CI success: 45406324340. Application-security G2 and evidence/outcome G3/G4 remain unmet. No demonstrated payouts. Existing OWASP source-analyzer baseline is separate from original local policy and trace verifiers; do not combine accuracy metrics across them.

## v0.14 evidence-handling correction
- Workflow fix 6caa17bb5eef899470aca8e9eef42a74aa75006c detects an accepted transition absent from the declared contract when the pre-state and acceptance are observed, even if the resulting state is missing. A permitted event with missing resulting state remains unknown. 89 authored assertions passed.
- Report checklist 97879c2d3fc526ccc7caaf8bc92fd29b333dd6be now returns CHECKLIST_COMPLETE_UNVERIFIED rather than implying readiness. This is a status correction, not evidence authentication; 26 assertions passed.
- Updated 12,000-event synthetic oracle regression 7d8bf73855038ad62431b28d2118049d2a133b8c: 775 consistent, 5,293 inconsistent, 5,932 unknown; zero trace count disagreements. 267 more inconsistencies recognized versus v0.13. 50,000-event maximum case passed in test isolate.
- Evidence challenge 56149ccd5a54475096afae777188e6c23d56d853: 4 TP, 2 TN, zero FP/FN, 4 correctly unresolved. All 10 practice and 17 missing-field cases blocked. Complete self-attestations labeled unverified. CI regression added 7312b7816ef2b84759dd03b80e97e01f23f97166. These are development regressions, not independent discovery or actual bounty readiness.
- G2/G3/G4 remain unmet: no new independent application vulnerability benchmark, actual evidence verification or real payout. Preserve existing OWASP baseline and avoid reporting workflow mismatch counts as vulnerabilities.
