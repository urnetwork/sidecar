# Cold email 2 — Regulated fintech / security buyers

**Who:** Security, compliance, or platform leads (CISO, head of security, head of platform) at regulated fintech, broker-dealers, and other teams under SOC 2 / DORA / HIPAA-style scrutiny that have started using coding agents.
**Why they're a fit:** Their reviewers ask where agent data gets decrypted and who can read it. CMEK isn't a clean answer (the vendor still unwraps the key). recURd holds no key at all.

---

### Subject lines (pick one)
- Every way your agents reach out — private, approved, recorded
- Where does your agent data get decrypted?
- A record of agent work only your team can read

### Body

Hi [Name],

Coding agents now reach databases, internal services and the open internet on their own, and most leave no record your security team controls. When a reviewer asks where that data gets decrypted, "customer-managed keys" isn't a clean answer — the vendor still unwraps the key to read it.

recURd takes a different line. Encryption happens on your clients; coordination runs over a post-quantum, end-to-end-encrypted network (hybrid ML-KEM-768) that carries only ciphertext. recURd's relay holds no key, so a subpoena for what we store, or a breach of it, yields ciphertext and a short list of metadata — nothing more. Every way an agent reaches out is a scoped, approved grant, written to a signed record only your team can read.

We're onboarding a few regulated design partners. Open to a short, security-focused call?

[Your name]

---

### Personalize
- Name the framework they report against (SOC 2 Type II, DORA, HIPAA) in the first line.
- If they've published a trust page or spoken about agent governance, reference it.
- For EU teams, note self-hosted or EU-hosted relays (blindness is a recognized transfer safeguard; a US-hosted relay is not).

### Evidence behind the claims (traceable, don't send)
- "the vendor still unwraps the key" — improvements4 **direction 8**; Anthropic CMEK docs ("asks your KMS to wrap or unwrap a data key") and EDPB ¶95 (encryption is not a supplementary measure if the importer holds the keys).
- "post-quantum… hybrid ML-KEM-768" — connect code: transport prefers `X25519MLKEM768` (`transfer_peer_capability_observation.go`, `DefaultSequencePostQuantumCurves`).
- "relay holds no key… yields ciphertext and metadata" — market2.md architecture; be ready to show the metadata list (connection pairs, timing/size, account identities, TLS-edge names).
- Don't overclaim: a no-view host can still be a HIPAA business associate and must give breach notice — say blindness **narrows** the review, not removes it (direction 8).
- Stage: design partner, not a live trial.
