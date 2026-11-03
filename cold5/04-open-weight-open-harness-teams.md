# Cold email 4 — Mixed open-weight / open-harness teams

**Who:** Engineers and tech leads at teams running open-source harnesses (OpenCode, Goose, Aider, Cline) on open-weight models they host themselves (vLLM, SGLang, Ollama, llama.cpp).
**Why they're a fit:** They already chose self-hosting for privacy, so client-side encryption and an open, self-hostable record land naturally — and their local-model sessions currently leave no record they control, while the harness still phones home.

---

### Subject lines (pick one)
- You self-host the model; your harness still phones home
- A record you control for local-model agents
- Open-source agent records, nothing leaves your control

### Body

Hi [Name],

If you run OpenCode or Goose on models you host, you did it to keep your code off someone else's servers. But the harness still calls out for telemetry and model catalogs, and a local-model session leaves no record your team actually controls.

recURd is an open-source sidecar that runs beside any harness and writes every session and every model call — route, host, and the weights that served it — into a record under your own keys. When you self-host the model, nothing leaves your control; when agents coordinate across machines, they do it over a post-quantum, end-to-end-encrypted network that carries only ciphertext. The client, relay and entry format are all open and self-hostable, air-gapped if you need it.

We're looking for a few design partners who run their own weights. The repo's open — want to take a look?

[Your name]

---

### Personalize
- Name their actual stack (e.g., "OpenCode on vLLM") — it signals you're not spraying.
- If they've filed issues about telemetry/offline mode or local-model support, open with that.
- For homelab/OSS-heavy audiences, lead with the open-source and air-gapped angle over the governance angle.

### Evidence behind the claims (traceable, don't send)
- "the harness still calls out for telemetry and model catalogs" — research note **L2-2.14**: all nine open harnesses contact other hosts even in local-model mode; blocking breaks several.
- "about 1 in 5 agent users mixes in open-weight models" (if used) — **L2-2.11** / Stack Overflow 2026: 11–20% name an open-weight family, ~2% only.
- "records each model call — route, host, weights" — improvements4 **direction 7** (record the route of every call at a stated level of evidence); label fields observed/declared/signed.
- "post-quantum E2EE network" — `X25519MLKEM768` in connect transport.
- "nothing leaves your control when you self-host" — true only when self-hosting; don't imply it for third-party-hosted open weights (most open-weight coding tokens run on third-party hosts).
- Stage: design partner + open repo to read — truthful; no live trial yet.
