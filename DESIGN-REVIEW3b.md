# Review: Sidecar infrastructure technical design, 2026-11-04 draft

Reviewed: `DESIGN.md`, status line "draft for peer review, 2026-11-04." Owner decisions 1–111 (2026-11-03) and 112–135 (2026-11-04) are applied. Nothing in it is implemented. This re-reads the final draft against `DESIGN-REVIEW3.md`, the review of the 2026-11-03 text.

Verdict: **still needs revision before the M2 format freeze.** No owner question remains open, and several of the earlier holes are closed or honestly narrowed. The evs commit is still not the linearizable update §11.8 claims, the published 72-hour removal bound does not survive the adversary §2 names, and harness evidence is still a same-uid hook. Do not freeze format 1, ciphersuite 0x0010, or `record.proto` on this text.

## What the 2026-11-04 draft changed

Decisions 112–125 answered the questions the first review treated as open or unsafe-as-recommended: self-admit (112), any writer leaf commits a signed change (113), agents hold per-generation wraps (114), gkm's visible rows (115), erasure-coding parity and a cold spare (116), no scrub and a public repo (117), every repo merges at each milestone exit (118), the "end-to-end encrypted" claim with an unaudited-crypto disclosure (119), allow-all LAN without a policy, disclosed (120), ports 8443, 8883 and 5671 (121), Team overage at existing rates (122), two name servers at one site (123), outbound mail on the shared load-balancer addresses (124), and a DATA circuit beside BDAT (125).

Decisions 126–135 then closed the questions that pass raised: owner-bound repos need the member's consent (126), a recovery key is one signature toward k after 72 hours (127), the leaf that signed an admission commits that config-group change (128), any admitted reader may witness and shared writers stop at `witness_bound_hours` (129), TLS or ssh off loopback (130), the 7-day cap covers sidecar-held tokens only (131), a chosen overlay block stays in 100.64/10 or RFC 1918 (132), a preservation hold does not block user shredding (133), business-hours review plus a narrow pager (134), and the "validated" mail label (135).

Those are settled. This review does not reopen them. It checks whether the section text does what the decision says, and whether the defects in `DESIGN-REVIEW3.md` are gone.

Eleven questions remain for peer review: Q-TEST-1, Q-TEST-2, Q-CORE-4, Q-TEST-6, Q-CTX-4, Q-KEYS-11, Q-EVS-6, Q-OPS-2, Q-BRIDGE-2, Q-SDK-5, Q-OPS-5. Q-CTX-4 is now on the M2 list. The how-to-review paragraph counts 283 D- items (16 withdrawn) and 169 Q- items (142 decided, 11 open, 12 closed, 4 withdrawn).

## Disposition of the earlier critical findings

| Earlier | Now | Where |
|---|---|---|
| C1. Head commit does not cover the entry versions it names | **Still open, and wider.** Parts write those entries for up to 30 minutes before the seal. | §11.8, lines 4643–4659 |
| C2. Path-level success and a git ref are two histories | **Still open.** Inline bodies no longer blow the 16 MiB body limit; the two histories remain. | §11.7 line 4587, §11.8 lines 4647–4648 |
| C3. P0 schedule and the 7-day cap | **Narrowed.** `strict_exp` is enforced whatever `reject_expired` says (line 2936). M1–M2 daemons are limited to test networks on machines without the app (D-TRUST-3, line 1233; M1 exit, line 8363). Stage 2 is still the M3 exit (line 8365). | §7.4, §23.4 |
| C4. Harness evidence is a self-signature | **Still open.** | §16.6, lines 6324–6332 |
| C5. A withheld removal is not bounded by 24 hours | **Restated, and the bound is now false in the text that publishes it.** | §2.8 line 586, D-TRUST-10 line 1247, §8 line 3445 |
| C6. TLS 1.2 shows recipients to the edge, and the proof is a sketch | **Half closed.** D-SMTP-21 proves the TLS 1.2 server Finished in-circuit and smtp-2 says no key that opens application data (line 1038). The relation is still deferred, and pi1 still "commits key, IV." | §14.5 lines 5692–5705 |
| C7. Site loss skips the sidecar dump, and the RPO sentence is false | **Still open.** | lines 7296 and 7393 |

## Still blocking

### 1. The head commit still does not publish the entry bytes it names

§11.8 steps 5–7 (lines 4643–4648) are the procedure the earlier review rejected. Step 5 `If-Match`es each index entry and directory delta, and may write `log/<n>`, before step 6's `If-Match` on the head. A version counts as committed only once the head or a log page names its push id (line 4666). Path-level compare-and-swap reads the newest *committed* version. On failure, step 7 "remove[s] what 5 wrote."

Two pushes of one path can both observe committed version `v`. The first installs an uncommitted entry. The second gets 412, rereads, sees that the committed version is still `v`, and overwrites the entry. The first push then wins the head. The head names a push id the entry no longer holds. A loser's cleanup can delete the winner.

Multi-part pushes make the window longer. A part runs steps 3–5 and never step 6, for up to 30 minutes (lines 4653–4659). The seal then commits with step 6 and rereads the parts only if the head moved, which is the case where the other writer has not committed yet. Format 1 should not freeze until every entry version, directory delta, and log page is an immutable object keyed by push id, the head `If-Match` is the only read-modify-write, and a retry that finds its push id in the head returns success.

The git split is the same defect one level up. Line 4587 says pushes that add different files to one directory never conflict, and step 7 commits the second push from the same `base_version`. Line 4569 says one evs push carries one git push, and export rebuilds the original oids. After two disjoint pushes the index contains both files and neither sealed commit does. Pick one model in the format-1 text.

### 2. The 72-hour exposure bound does not survive the server the design names

Owner decision 129 is the answer to the earlier C5. D-TRUST-10 (line 1247) lets any admitted reader, agents included, refresh `witnessed_at`, and stops shared-group writers at `witness_bound_hours` (default 72 hours, up to 168). Own-group writers only alarm. Rotations and Removes never stop.

§2.8 (line 586) then says the quiet part: across a split the server makes by dropping traffic, exposure is unbounded. One agreeing `HeadCheck` on the old pin refreshes the witness. A server that delivers the Remove only to the revoker, and delivers the old pin only inside the stale cohort, never starts the timer. §6's risk row says the same: the bound does not hold until a HeadCheck crosses the split.

§8 (line 3445) states the opposite, with no split exception: a withheld Remove exposes a shared group for at most `witness_bound_hours`. The assembly paragraph (line 70) says no section text contradicts a decision. These two sentences contradict each other, and the decision's "at most" is the sentence §2.8 withdraws.

The earlier fix still stands. A writer needs a fresh witness that the current projection is the newest pin held by a quorum of the repo's readers. A peer that is merely behind does not count. A device that learns a higher pin and cannot fetch it stops sealing immediately. Publish §2.8's unbounded split as the residual, and delete §8's "at most."

Personal repos and the v0 pilot (personal networks, owner decision 102) have no bound at all, because own groups only alarm. Say that next to the published number.

### 3. Harness evidence is still a hook any same-uid process can submit

`harness_ok` (lines 6324–6332) is unchanged in substance. The daemon signs channel `harness` with the requesting sidecar's identity key when a hook event matches session, tool, and the argument hash, the member has no other consented device and no presence key, and `evidenceDefault` includes harness. `evidenceDefault` is still every §16.6 channel. The daemon socket admits the daemon's uid. Events bind by session id, and an MCP session joins through pid ancestry. Nothing pins the hook peer to the binary `ur install-harness` sealed.

A prompt-injected agent on that uid can submit the hook event and then the outward tool. Taint requires a fresh decision, and harness is still a legal channel for it. Those decisions are what the server stores. Owner decision 75 can stand. Bind the decision to the pinned harness binary, or leave `harness` out of `evidenceDefault` until that exists. A `/dev/tty` confirmation can stay.

### 4. A removed wrapped writer can still sample the next generation

Decision 114 says wrapped writers rotate but never commit Removes, and that revoking an agent is a generation not wrapped to it. §10.5 (line 4117) says each rotation writes a `ReaderWrap` for every reader with a current `ReaderKey`, and that when only agents drop, any writer rotates without an MLS commit. It also says a Delegation's admitted sidecars hold its private key and a reaped one reads until `DelegationRevoke`.

The party who samples `RK_{g+1}` can wrap it to a `ReaderKey` it still holds. "Any writer" includes the wrapped writer being removed, until the projection that drops it is the version the rotation checks. A shared Delegation key is not taken back by reaping one agent, including on the config repo, which holds policy and `K_sock`. Decision 128 lets the signing leaf commit a config-group admission. It does not take this key back.

Name the signer of an agent-only rotation as a member leaf that is still a reader at `v_{g+1}`, exclude the dropped sidecar's `ReaderKey`, and treat `DelegationRevoke` as the act that starts the generation. A wrap the removed party can reissue is not removal.

### 5. Site loss still restores the wrong Postgres, and the RPO sentence is still false

Line 7296: "No object waits for a copy, so owner decision 89's RPOs (5 min metadata, 1 h segments) hold." Decision 94 removed the off-site replica those numbers measured. Quorum writes are RPO 0 for a drive or one host. Site loss is the objects no device still holds.

The re-seed (line 7393) restores "Postgres from planetoid's newest dump" and empty buckets. Sidecar tables live in their own 14-day dump (ops-2). The runbook never restores it. That dump is the copy of `dns_label`, the mail routing tables, and `sidecar_identity`. Devices do not hold the zone. Restoring without `dns_label` reopens the alias takeover I-14 exists to prevent.

Delete the sentence that the old RPO bounds hold. Restore the sidecar dump in the same procedure, and state which slots a record-class mirror must re-upload. Decision 116's cold spare is the 4-hour figure for a second host, not for the site.

## Major, carried forward

**The content-key ladder is not the post-compromise security D-KEYS-1 claims.** Adds and Updates keep `RK_g` (line 4114). `GenLink` opens every earlier generation (line 4115). An Update heals the MLS leaf and does not rotate the key that encrypts objects. A thief who copied the keychain reads the current generation until the next removal, `ur keys rotate`, or the 30-day schedule, and reads every earlier generation after that. `ur evs rekey` is still v1. Say this in §2.10, or rotate the content key on Update. Suite 0x0010 is X-Wing for confidentiality and Ed25519 for signatures. A later signature break plus an external resync plus this ladder is retroactive for every generation still linked. R-KEYS-12 should say passive-only. The M2 gate should require one 0x0010 interop against a second stack whose KEM is Go's `MLKEM768X25519`, including the exporter and the GenWrap additional data. Vectors under suite `0x0001` do not seal the path secrets that ship.

**A head reader still cannot bind the file it was served.** Q-EVS-6 still recommends trusting evs for changes older than the 64-version window. The window still stores at most 1 KiB of token paths, then only prefixes. `HeadCheck` compares config, projection, and epoch pins. `EvsHeadCheck` is v1 (line 4681). Phones and the mail path are head readers. Disagree with (a). Put `(token path, entry_sha256)` in the head the reader already verifies. The per-repo push sequence (line 2730) does fix the earlier hint bug: a commit on any ref raises one version, so a hint for a second ref is no longer dropped.

**DATA mode cannot finish a large message inside its own limit, and the BDAT proof still has two readings.** D-SMTP-20 (line 5701) proves every DATA body octet because a DATA body can smuggle a second transaction. The section's own cost is over 1 second per 512 bytes in-circuit. The speed gate allows 10 minutes for a 100 KiB DATA message. A message near the 25–50 MiB cap does not finish inside the 2-hour DSN cutoff, so the MXs that lack CHUNKING, which are why decision 125 funded the circuit, still do not get the mail. The BDAT diagram (line 5692) still says pi1 "commits key, IV," and line 5695 still runs Z2–Z6 over every later record, while the BDAT speed gate is a 4 KiB header. State BDAT the way a sound proof has to: Z2 covers the command records and the tail, the client write key stays a witness, and public inputs are the ciphertext plus values the edge already has. `smtpproof/SPEC.md` is still the document that freezes the relation. The TLS 1.2 key disclosure from the earlier review is closed (D-SMTP-21).

**A replying burner's DKIM name still deletes its MX.** Line 5105: a `<sel>._domainkey.<blabel>` "takes `*`'s records, MX included." RFC 4592 does the opposite. Once `<blabel>` exists, queries for its MX and A return NODATA, not the wildcard. Receive-only burners work. The first reply, which decision 79 needs before the PSL listing, is what removes inbound mail for that address. Copy A, AAAA, and MX onto `<blabel>` in the same journal write as the first child.

**iOS in the foreground is still not a receive path.** The edge cannot queue. A miss closes in the handshake. An iOS wake only resyncs. BS1 still waits on the SNI census (line 101), not on whether a sender retries while the app is open. The disclosure in owner decision 12 is accurate. The product sentence that the iOS app receives is not.

## What improved

- `strict_exp` is a server check independent of `reject_expired`, and M1's daemon is confined to test networks without the app credential (lines 1233, 2936, 8363). That is the schedule fix the earlier C3 asked for, short of stage 2 moving forward.
- The TLS 1.2 server write key is no longer given to smtpedge. smtp-2 says no key opens application data.
- DATA mode is specified, with a DSN when the proof cannot finish, instead of a silent BDAT-only ship.
- Q-CTX-4 is on the M2 blocker list, so format 1 no longer freezes with `ur share` unowned.
- Ev's hints use one repo-scoped push sequence (line 2730).
- Decision 126 keeps a network admin from adding readers to a member's vault or mailbox without that member's consent. Decision 128 lets the device that signed an admission commit the config-group Add, which is what self-admit (112) needed. Decision 127 makes a recovery key one signature toward k, so one code does not replace an AdminSet when k>1.
- Decision 118 is in the branch policy and in §23: every touched repo merges at each milestone exit, and M3's pilot runs on production. The earlier "wait for RS1, or the tail never lands" fork is not the live procedure.
- Owner-bound consent, the overlay range, and TLS off loopback are decided and written down.

## Peer-review answers

| Q | Answer |
|---|---|
| Q-EVS-6 | Disagree with (a). Bind the entry hash into the head. See finding 1's neighbor above. |
| Q-OPS-2 | Do not freeze locators on inlining alone. Y2's own figures already sit where packing is required. Reserve a pack address before format 1. |
| Q-CORE-4 | (b), as a server check on refresh and on `POST /network/auth-client` when the bearer is a client token. Defer (c). |
| Q-TEST-1 | (b). Export a small `connect/connecttest`. The helpers are unexported members of `package connect` tests. |
| Q-TEST-2 | (a) and (b). A 3-master Redis cluster and final-upstream MinIO at the release gate, plus a CROSSSLOT lint. |
| Q-TEST-6 | (b). The oneof ban covers envelope, stream, and push messages. The credential message is not one of them. |
| Q-CTX-4 | (a), the live sharer in §9. It is correctly on the M2 list. |
| Q-KEYS-11 | (a), 30 days, then until recent ackers have applied. Size `epoch/<n>` in the NVMe pool. |
| Q-BRIDGE-2 | A fixed window of one client per target, Required, window size 1. Own-client links stay the iOS fallback after measurement. |
| Q-SDK-5 | (b) now. A root-package device role links every root init and every `protocol` descriptor. The 1 MiB gate is not large enough for X-Wing and the MLS subset. Give the bridge messages their own package. |
| Q-OPS-5 | (a), staged, for the dns API. Keep `dnsedge` one host at a time. |
| Q-QUOTA-3 | Keep the 5% latency bar, and add a correctness test: the included balance is exhausted before the credit line, and an edge lease cannot pin the line without a debit. |

Decision 135's "validated" label is settled. A forward-confirmed PTR or an aligned DKIM `d=` on an operator list is not evidence that this message took a DANE or MTA-STS path. The label will over-claim for any sender that is merely on the list. REQUIRETLS remains the sound mark. The disclosure next to the label should say the list is an operator reputation check.

## Before the M2 freeze

1. Make the head `If-Match` the only read-modify-write, over immutable push-keyed entries (finding 1), and pick the git-tip model.
2. Publish the witness residual §2.8 already states, and stop §8 from claiming the 72-hour bound against a splitting server (finding 2).
3. Take `harness` out of `evidenceDefault` until the hook peer is the pinned binary (finding 3).
4. Exclude a dropped agent's `ReaderKey` from the rotation that removes it, and rotate on `DelegationRevoke` (finding 4).
5. Rewrite the RPO sentence and restore the sidecar dump in §19.10 (finding 5).
6. Answer Q-EVS-6 with a head binding, and reserve pack addresses (Q-OPS-2), before format 1 freezes.
7. Keep the 0x0010 freeze at the exit review that has one hybrid interop, and state the ladder's limits next to D-KEYS-1.

The confidentiality claim against a curious file cluster still holds: `RK_g` is stored wrapped, and GKM does not hold a key that opens repo contents. The metadata list is still the right control for what servers see. The defects above are about whether a commit, a removal, and an approval do what those sections say they do.
