# Seeded-flaw benchmark

How do you know a design reviewer, human or automated, finds what matters? ThreatLens
answers it the way mutation testing answers it for test suites: start from designs
with no known issues, inject one realistic flaw at a time, and check that the review
names that flaw on the element that was changed.

## Setup
* **Baselines:** four hardened reference architectures in `examples/`: a smart-home
  device cloud, a wearable health-sync service, a managed-device enrollment service,
  and a mobile carrier account and eSIM service. They model classes of consumer
  systems, not any company's real design. Each produces zero findings.
* **Mutation operators (33):** realistic regressions a design change can introduce,
  for example downgrading a flow to plaintext, dropping the caller authentication on a
  hop, removing MFA from login, shipping one fleet-wide device secret, letting the
  recovery flow change the email without re-authentication, removing the step-up on
  number ports (SIM swap), cutting log retention to 14 days, or deleting the detection
  pipeline. Each operator states the finding a reviewer should raise.
* **Cases:** every operator applied to every element it fits in every baseline:
  **174 single-flaw designs.**

## Results

| Reviewer | Seeded flaws found on the right element | Findings on clean baselines |
|---|---:|---:|
| ThreatLens rule engine (35 rules) | **174 / 174** | 0 |
| Gemini 3.8 Flash alone, given only the spec | run `GEMINI_API_KEY=... threatlens bench --llm` (results in `results/bench_llm.json`) | |

The first run of the rule engine scored 170/174. The 4 misses were the same gap in
every baseline: the encryption-at-rest rule did not treat a log store as sensitive,
though security logs hold IP addresses and account IDs. The knowledge base was fixed
to include `logs`, and the benchmark now guards that behaviour in CI.

## What the numbers do and do not show
The same author wrote the operators and the rules, so the rule-engine score mainly
shows the knowledge base covers what it claims and keeps covering it as rules change.
It is a regression suite, not proof of real-world recall. The LLM column is the more
informative experiment: the model receives no hints and must name the flaw and the
element on its own, and the guard counts how many of its suggestions referenced
elements or catalog entries that do not exist.
