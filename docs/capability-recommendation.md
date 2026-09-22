# Private capability recommendation

Switchboard can optionally expose `capability_recommend`. The tool ranks only
capabilities and tools already visible under the authenticated profile and tool
policy. It is advisory: it cannot enable a capability, broaden authority, or
execute a tool.

The supported backend is the reviewed `parallel-decision` extension of
`llama.cpp`, served over `POST /v1/decision`. This avoids adding JevRouter or an
unreviewed model-serving stack to the trusted path. JevRouter can point its
`JEV_API_URL` at another System One implementation, but its `/v1/systemone`
wire format is not the same as the existing decision endpoint. Switchboard
therefore uses a narrow native adapter.

## Data flow and trust boundary

```text
authenticated MCP client
        |
        | capability_recommend(request)
        v
Switchboard
  1. applies profile and exact-tool policy
  2. builds a catalog containing only visible public metadata
  3. POSTs one finite enum decision to the configured HTTPS endpoint
  4. validates the complete returned distribution
  5. returns a ranking and confidence; it performs no action
        |
        v
private llama.cpp /v1/decision endpoint
```

The user's request and filtered public catalog metadata leave the Switchboard
process. Endpoint URLs, header configuration, credentials, hidden capabilities,
policy-denied tools, and upstream tool schemas/descriptions do not. The compact
projection contains capability name/title/description/tags plus allowed tool
names; excluding tool descriptions keeps the model context bounded and reduces
prompt-injection surface. The decision endpoint is still an upstream data
processor and must be private, reviewed, and covered by the egress policy.

The boundary is intentional:

- Switchboard core owns the small adapter, because only core has the
  authoritative authenticated profile, exact-tool policy, catalog projection,
  audit context, and ability to guarantee recommendation-only behavior.
- The model runtime remains an external local service owned by decision-service.
  Model loading, GPU scheduling, source/model pinning, and updates do not belong
  in the gateway process.
- This is not a capability module. A module is a client-visible upstream
  capability; making the recommender one would either send it an unfiltered
  catalog or duplicate identity and policy enforcement across a process
  boundary.

## Backend contract

Run a reviewed build of the pinned `thecodacus/llama.cpp` parallel-decision
fork with at least three reserved decision sequences. The endpoint is disabled
unless `llama-server` is started with `--decision-seqs N`, where `N >= 3`.
Switchboard always requests `mode: "tree"` so the response is an exact finite
distribution rather than a greedy path score.

The fork must include the response extension that returns a `probabilities`
object for each tree-scored field:

```json
{
  "object": "decision",
  "results": [{
    "fields": {
      "capability": {
        "value": "forgejo",
        "probability": 0.8,
        "probabilities": {"forgejo": 0.8, "rilldns": 0.2},
        "tree": true
      }
    }
  }]
}
```

Switchboard rejects greedy results, missing choices, extra choices,
non-normalized probabilities, unauthorized selections, and selections that are
not an argmax. Backend failures fail only the recommendation call; search,
describe, and downstream capabilities remain available.

## Configuration

The feature is absent unless `capability_recommender` is configured:

```json
{
  "capability_recommender": {
    "endpoint": "https://decision.example.com/v1/decision",
    "api_key_env": "SWITCHBOARD_DECISION_TOKEN",
    "model": "gemma-4-12b",
    "timeout_ms": 3000,
    "max_candidates": 64,
    "min_confidence": 0.6
  },
  "egress_policy": {
    "allowed_destinations": ["decision.example.com:443"],
    "allowed_cidrs": ["192.0.2.0/24"]
  }
}
```

`endpoint` must be HTTPS and must pass the normal destination and resolved-IP
egress checks. `api_key_env` names an environment variable; never put the token
itself in configuration. Defaults are a 3-second timeout, 255 candidates, and a
0.6 minimum confidence. Requests are bounded to 32 KiB and complete upstream
payloads to 256 KiB; responses are bounded to 1 MiB. Redirects are rejected.

Three consecutive transport, HTTP, decoding, or contract-validation failures
open an in-process circuit for 30 seconds. Calls fail fast while it is open.
After the cooldown, one request is admitted as a recovery probe; success closes
the circuit and failure reopens it. Caller-cancelled contexts do not count as
backend failures. Circuit state is deliberately local and ephemeral: it limits
load on an unhealthy optional dependency but is not authorization or durable
business state.

The tool is exposed only where catalog discovery is exposed. For authenticated
sessions that means the identity policy must set `discover: true`.

## MCP contract

`capability_recommend` accepts:

```json
{"request": "Find the issues assigned to me", "limit": 5}
```

`request` is required. `limit` controls the abbreviated ranked `candidates`
list, defaults to 5, and is capped at 20. A successful response contains the
selected `choice`, the complete validated `probabilities` map, normalized-
entropy `confidence`, `low_confidence`, optional `fallback`, ranked public
candidate summaries, backend model name, token usage, and timings. The complete
map is retained even when `candidates` is limited, so callers can audit the
confidence calculation.

The ordinary tool-call audit event records identity, identity-policy version,
session, correlation ID, tool policy/version, `capability_recommend`, outcome,
and duration. As with other tools it deliberately omits arguments, results, and
error strings. The correlation ID is forwarded to the decision service. The
request itself cannot be generically redacted without changing routing meaning;
callers should not put secrets in routing requests. Switchboard sends it only
to the explicitly configured private endpoint and never logs it.

## Confidence and fallback

The backend returns the probability distribution. Switchboard derives a
model-independent confidence score using normalized entropy:

```text
confidence = 1 - H(probabilities) / log(number of choices)
```

A single possible capability has confidence 1. A uniform distribution has
confidence 0. If confidence is below `min_confidence`, the response sets
`low_confidence: true` and `fallback: "capability_search"`. Clients should then
use deterministic catalog search or ask the user; low confidence never triggers
an automatic enable or execution.

## Evaluated runtime and operations

The existing local candidate was evaluated with
`gemma-4-12b-it-UD-Q4_K_XL` on a Radeon 780M through Vulkan. The 7,366,423,360
byte GGUF has SHA-256
`90fd944d227e9d9b68e7e2c7d5b57b79d4c66ed521b0919fbbd932cf834f6f8e`
and occupied about 8.8 GB of GTT. On a blinded 80-request decision set it
produced 71 correct decisions, zero request errors, 1.514 s median latency, and
1.546 s p95 latency after warm-up. Treat those figures as the current
single-request baseline; rerun the capability-routing benchmark before raising
concurrency or changing the model, quantization, prompt template, or runtime
commit.

A live capability-shaped probe on the same host measured about 63.3 seconds
from service start to the listening socket, 1.112 seconds for the first request
with a new schema/prefix, and 0.377/0.374 seconds for the next two cached
requests. The deployed server uses `--parallel 1` and serializes simultaneous
HTTP work: two warm requests completed in 0.819 seconds wall time; four
completed in 1.510 seconds, with individual completions spaced at roughly one
warm-request interval. Keep Switchboard's timeout and expected concurrency
consistent with that serialization. A backend timeout or malformed/incomplete
distribution fails the recommendation call closed and does not affect catalog
search or capability execution.

Operational ownership remains with the decision-service deployment. Pin both
the llama.cpp source commit and model artifact checksum, build the binary in the
reviewed deployment pipeline, and roll out through the existing Ansible role.
The deployed runtime is a clean checkout of
[`thecodacus/llama.cpp@14d04e755fa28653e87b9a07072892265bdc0fad`](https://github.com/thecodacus/llama.cpp/tree/14d04e755fa28653e87b9a07072892265bdc0fad);
that source is MIT-licensed. The model artifact comes from
[`unsloth/gemma-4-12b-it-GGUF`](https://huggingface.co/unsloth/gemma-4-12b-it-GGUF)
(`UD-Q4_K_XL`), whose model card identifies Gemma 4 and the quantization as
Apache-2.0. Retain the upstream model card, Apache
license and notices, source repository/revision, quantization provenance, and
artifact checksum with the deployment record. Updates are deliberate
benchmarked changes, not floating downloads.

For an isolated evaluation, pre-stage the reviewed source, toolchain, and model
artifacts, then run the build and benchmark in a container or Bubblewrap
namespace with no network namespace, a read-only source/model mount, a fresh
temporary writable directory, no home-directory mount, and only the required
GPU device. Record hashes outside the sandbox before execution. Do not execute
installer hooks or downloaded packages merely because a project describes
itself as local or open source.

## Adoption decision (2026-09-22)

**Revise / conditional go.** Merge and review the disabled-by-default
Switchboard adapter, but do not enable it for production routing yet. Do not add
EdgeJev or JevRouter. Reuse the existing pinned decision-service runtime after
its exact-distribution response patch is deployed.

The positive evidence is 32/32 provisional top-1 selections on the clear
pre-labeled corpus, compared with 32/32 abstentions when the same unmodified
natural-language requests are given to strict keyword search. The design also
preserves the authorization boundary and leaves model health optional.

The production no-go remains until all of these gates pass:

1. Deploy the reviewed exact-distribution patch through decision-service's
   pinned build and Ansible rollback path; verify complete normalized vectors at
   the private HTTPS endpoint.
2. Run an independently labeled holdout of at least 100 requests, including at
   least 20 ambiguous, multi-capability, or out-of-catalog requests. Require at
   least 90% all-case top-1, 98% top-3 coverage for routable cases, and no more
   than 2% confident errors at the chosen threshold.
3. Confirm warm p95 below 2 seconds at expected load and verify that queueing at
   `--parallel 1` cannot exhaust Switchboard's request budget.
4. Repeat policy-redaction, unauthorized-choice, malformed-distribution,
   timeout, circuit-breaker, and backend-down tests against the deployed path.
5. Run a shadow period with recommendation outcome/latency metrics but no
   automatic activation or execution; review disagreements before enabling the
   tool for clients.

Rollback is configuration removal: omit `capability_recommender` and restart
Switchboard. That removes the tool without changing any profile, authority, or
upstream capability. The decision-service patch has its own pinned deployment
rollback.
