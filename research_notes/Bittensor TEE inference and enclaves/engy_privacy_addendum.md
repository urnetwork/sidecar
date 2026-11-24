# engy (SN53): privacy of prompts and outputs, 2026-11-23 (addendum)

An addendum to other_subnets_survey.md. That survey recorded engy's README line "No TEEs, no trusted hardware". engy's privacy and terms pages add a confidential-computing route, recorded here.

Pages read:
- github.com/hanlinai/engy (README)
- engy.ai, engy.ai/llms.txt and engy.ai/services.json
- engy.ai/privacy (effective 2026-10-21)
- engy.ai/terms (effective 2026-11-20)
- engy.ai/docs/using-the-api/data-retention
- engy.ai/docs/get-started/verify-responses

Pages not read:
- docs/SN53_ONE_PAGER.md (HTTP 503 twice)
- docs/MINER.md and docs/VALIDATOR.md
- the pricing page
- the region-routing, usage-and-logs and signed-receipts docs

## Takeaway

engy's privacy is policy, with one optional route to unattested "confidential computing" workers.

- **Who sees plaintext.** Cloudflare terminates TLS. engy's gateway processes every request in memory. By default, a request may be served by a worker that an independent operator runs, and engy cannot technically guarantee that operator keeps nothing.
- **The ZDR flag.** A request flagged `"provider": {"zdr": true}` goes only to confidential-computing workers or to engy's own machines. It fails with a 503 rather than go elsewhere.
- **No attestation.** No TEE vendor is named, and no evidence reaches the client.
- **Verdict.** engy fails the design's bar on every point: client-verified evidence, E2E to a key bound in it, and no plaintext outside the TEE.

## Cited Findings

**Who sees plaintext:**
- Requests "reach us through Cloudflare (TLS termination and DDoS protection; Cloudflare processes traffic per its own policies)". — [engy privacy](https://engy.ai/privacy)
- Content "is processed in memory, and is gone from the gateway when the response is delivered". — [engy privacy](https://engy.ai/privacy)
- "a request can be served by a worker that an independent operator runs on the engy network". Those operators "hold administrative access to their own machines, so engy cannot technically guarantee non-retention there". — [engy privacy](https://engy.ai/privacy)
- Workers "serve buyer requests routed from the gateway on a local sglang serve". — [engy README](https://github.com/hanlinai/engy)
- Nothing read says validators receive prompts.

**Zero data retention:**
- Default: "Zero data retention is the default for every account. Engy does not store your prompts or the model outputs." — [engy data retention](https://engy.ai/docs/using-the-api/data-retention)
- The exception: "engy keeps the prompts and model outputs of the requests your opt-out covers". — [engy privacy](https://engy.ai/privacy)
- End to end, ZDR needs the flag, set per request, per key or per account. Flagged requests go only to ZDR-certified workers, which are confidential-computing workers or machines engy runs itself. Without one, the request fails with a 503 and "is never sent to any other worker". — [engy privacy](https://engy.ai/privacy); [engy data retention](https://engy.ai/docs/using-the-api/data-retention)
- Without confidential computing, "non-retention is a policy and contractual commitment rather than something engy can technically guarantee". — [engy terms](https://engy.ai/terms)

**Confidential computing:**
- Some workers "run confidential computing, where the CPU and GPU keep request content sealed from the machine's operator". — [engy privacy](https://engy.ai/privacy)
- No TEE vendor, attestation, evidence endpoint or key binding is described. There is no encryption beyond TLS to Cloudflare.
- The README's verification design says "No TEEs, no trusted hardware. The proof pins the math, not the machine." It does not mention the confidential-computing workers. — [engy README](https://github.com/hanlinai/engy)

**TOPLOC:**
- TOPLOC is an activation fingerprint per response that verifiers re-run to check the advertised model produced the output. It proves which model ran and claims no confidentiality.
- A proof handed to a client carries `toploc.prompt_ids`, "The prompt token IDs, after the chat template was applied". engy "does not store the proof". — [engy verify responses](https://engy.ai/docs/get-started/verify-responses)

**Training, logs and retention:**
- "No request or response content is ever used to train, fine-tune, or evaluate models. The only exception is requests you have opted out". Opted-out content is used for engy's own research and "never" sold or published. — [engy privacy](https://engy.ai/privacy)
- Usage metadata (time, model, tokens, cost, latency) is kept while the account exists. Operational logs hold no message content and are "rotated on a short schedule". — [engy privacy](https://engy.ai/privacy)
- Integrity audits are experimental, currently for qwen3.6-35b-a3b only. They keep the response's token IDs, "never the prompt", for up to 30 days. — [engy privacy](https://engy.ai/privacy)
- Payment: gamma at SN53 is credited at $1 per gamma plus 5%. — [engy services](https://engy.ai/services.json)

## Inferences

- Even a ZDR-flagged request is read in plaintext by Cloudflare and engy's gateway before it reaches a confidential worker. The client cannot check that the worker is confidential. So engy cannot meet CO-2 as DESIGN-COMPUTE.md applies it (IC-1, IC-2).
- engy would become a candidate if it exposed attestation for its confidential workers and an E2E path to a key bound in that evidence, so that neither Cloudflare nor its gateway reads a request. It already takes gamma, which Chutes does not (Q-PROV-1).

## Gaps

- The TEE technology, attestation and operators behind the confidential workers are not described in the pages read.
- Which models have ZDR workers is on the pricing page, which was not read.
- The one-pager (HTTP 503) and the miner and validator docs were not read.
