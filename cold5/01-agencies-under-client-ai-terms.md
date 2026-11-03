# Cold email 1 — Agencies & outsourcers under client AI terms

**Who:** Founders / delivery leads at software agencies, dev shops, and outsourcers (5–150 engineers) whose clients write AI-use rules into contracts.
**Why they're a fit:** They carry the obligation to prove — or restrict — how AI touched a client's code, and some client contracts forbid retaining client data at all. recURd turns that from screenshots-and-spreadsheets into a per-client signed record, with nothing retained where the contract says so.

---

### Subject lines (pick one)
- Proving to [Client] which agents touched their code
- When your client's contract restricts AI
- One AI policy per client, with the receipts

### Body

Hi [Name],

If you ship software for clients, their contracts are starting to dictate how you use AI. Citi, HSBC, Barclays and Lockheed now require sign-off before an agent touches their work, and a few forbid keeping their data at all. Answering that today means screenshots and a spreadsheet nobody trusts.

recURd is an open-source sidecar that runs beside your coding agents — Claude Code, Cursor, Codex, OpenCode — and keeps one signed record per client: which agent and model touched which repo, who approved it, and, where the contract demands it, nothing retained but the metadata. Encryption happens on your own machines; recURd and the network it runs on only ever see ciphertext, so you can hand a client proof without exposing their code to anyone, us included.

We're signing a few design partners who live under these terms. Worth 20 minutes?

[Your name]

---

### Personalize
- Swap `[Client]` for a real client whose sector is known for AI clauses (a bank, an insurer, a defense prime).
- If you know their harness mix, name it instead of the generic list.
- If they've posted about client audits or AI bans, open with that in one line.

### Evidence behind the claims (traceable, don't send)
- "Citi, HSBC, Barclays and Lockheed… require sign-off / forbid retaining data" — research note **L2-2.01**: 13 of 43 large buyers publish binding supplier AI-use terms; 8/13 default-deny AI without authorization; several bar retaining client data ("not stored, logged, cached"). Keep the named list to buyers actually found in 2.01.
- "signed record per client… one AI policy per client" — improvements4 **direction 10** (engagement profiles) and **2.01**.
- "only ever see ciphertext" — market2.md: traffic between recURd instances is E2EE; the network carries only ciphertext.
- Stage: recURd is design-stage — the ask is a **design partner**, not a live trial.
