# Capability-routing benchmark

This benchmark compares the existing deterministic `capability_search` tool
with the optional private finite-schema recommender. Labels in `cases.json` were
written before either system was run. `catalog.json` is a public-metadata
snapshot of the eight capabilities visible to the evaluated Switchboard
profile; its narrower candidate sets exercise policy filtering.

## Protocol

For each case, give both systems the exact `request` string and only the
capabilities named by `candidate_set`. Do not rewrite requests into search
keywords. A system must not return a capability outside that set.

The lexical baseline uses the production `capability_search` behavior: every
whitespace-delimited query word must match the capability name, title,
description, or tags. Its ordered result list is the ranking; an empty list is
an abstention.

The model backend receives one enum field containing the allowed capability
names and the matching public catalog entries. Use `mode: "tree"`,
`tree_max: 255`, and prompt caching. Require a complete exact probability map;
do not treat a greedy path score as a distribution.

Report:

- **Top-1 accuracy:** cases whose first result equals `expected`, divided by all
  cases. An abstention is incorrect.
- **Top-3 coverage:** cases whose expected capability appears in the first
  three results, divided by all cases.
- **Abstention rate:** lexical empty results, or model results whose normalized
  entropy confidence is below 0.6.
- **Selective accuracy:** top-1 accuracy among non-abstained cases.
- **Confident error rate:** incorrect model top-1 results at confidence 0.6 or
  higher, divided by all cases. This is the safety-sensitive calibration metric.
- **Latency:** cold first request, then warm median and p95 over the corpus.
  Also report two- and four-request wall time because the evaluated runtime can
  serialize concurrent requests.
- **Resource use:** service startup-to-listen time, process memory, GPU/GTT
  allocation, model artifact size, and request errors.

For two or more choices, confidence is:

```text
1 - H(probabilities) / log(number of choices)
```

For one allowed choice it is 1. Record raw choices and distributions so metric
calculation can be repeated. Any missing, extra, non-normalized, unauthorized,
or non-argmax distribution is a request error, not an abstention.

## Environment

The evaluated backend is the pinned parallel-decision llama.cpp fork with
Gemma 4 12B `UD-Q4_K_XL` on Radeon 780M/Vulkan. Runtime and artifact provenance
are recorded in [the operator documentation](../../docs/capability-recommendation.md).
The benchmark sends only the fixture's synthetic requests and public catalog
metadata; it contains no credentials or production data.

## Results

### Lexical baseline

Running the production search algorithm over the frozen snapshot produced no
match for any of the 32 unmodified natural-language requests:

| Metric | Result |
| --- | ---: |
| Top-1 accuracy | 0/32 (0%) |
| Top-3 coverage | 0/32 (0%) |
| Abstention | 32/32 (100%) |
| In-process search median | 0.028 ms |
| In-process search p95 | 0.046 ms |

This does not mean catalog search is broken: it is a strict keyword tool, and a
client can obtain useful results by first reducing a request to matching catalog
terms. It does establish that search is not itself a drop-in natural-language
router on the same inputs.

### Local decision pass (provisional)

The pinned Gemma 4 parallel-decision deployment selected the expected
capability for all 32 cases and never selected a capability outside the case's
authorized candidate set:

| Candidate set | Cases | Top-1 | Server batch time | Reported per decision |
| --- | ---: | ---: | ---: | ---: |
| Full (8 choices) | 20 | 20/20 | 9.734 s | 0.487 s |
| Infrastructure (3 choices) | 6 | 6/6 | 3.325 s | 0.554 s |
| Coordination (3 choices) | 6 | 6/6 | 3.558 s | 0.593 s |
| **Total** | **32** | **32/32 (100%)** | **16.616 s** | **0.519 s weighted** |

There were no request errors. The batches deliberately used different schemas,
so all three reported zero cached prefix tokens. The separate same-schema probe
in the operator documentation measured 0.375 seconds per warm request.

This pass is provisional, not a completed confidence result. The deployed
endpoint exposes only the selected probability (all were at least 0.999996) and
not the complete vector. It therefore cannot support reproducible top-k ranking
or normalized-entropy calibration under this protocol without inventing data.
Rerun and append the raw distributions after the exact-distribution response
extension is deployed.

### Interpretation

On these clear, in-domain requests, the local model adds a useful behavior that
strict catalog search does not provide: direct routing of an unmodified natural-
language request. The observed gain is 32/32 provisional top-1 versus 32/32
lexical abstentions. There were no model selection errors to categorize.

That result does not yet justify making the model a required production
dependency:

- The corpus is small, synthetic, and deliberately clear. It has no ambiguous,
  multi-capability, or out-of-catalog requests and therefore cannot estimate
  false-confidence behavior.
- Every selected score was saturated near 1.0. Without the rest of each vector,
  those values cannot validate entropy confidence or an abstention threshold.
- A warm model decision is roughly four orders of magnitude slower than the
  in-process lexical calculation and the runtime holds about 7.55 GB of process
  memory and 8.8 GB of GTT. Startup takes about 63 seconds and the deployed
  `--parallel 1` configuration serializes simultaneous calls.
- Keyword search remains deterministic, effectively free, and useful as the
  low-confidence fallback after a client supplies appropriate terms.

The evidence supports a feature-gated shadow/pilot, not default-on routing.
Promotion requires the full-distribution patch, a rerun that records entropy
confidence, and a harder independently labeled holdout containing ambiguous and
out-of-domain requests. Recommendation failures must continue to leave search,
activation, and execution untouched.
