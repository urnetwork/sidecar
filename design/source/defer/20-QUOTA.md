### quota-auto-recharge: Auto-recharge of data packs
Stage: Later
- **Deferred:** Buying the next Community or Pro data pack automatically when one runs out, named in §20.16's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. Team needs none, since it is post-paid.
- **Launch instead:** A person buys a data pack by hand. When a balance runs out, the limit's refusal says so (§20.7).
- **Lost:** A Community or Pro network that runs out of transfer is refused until someone buys a pack.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A stored payment method with consent to charge it, a cap, and the purchase path's idempotency under §20.6's draw order.

### quota-invoicing-above-25-seats: Invoicing above 25 seats
Stage: Later
- **Deferred:** Billing a Team by invoice above about 25 seats (R-QUOTA-6; §20.16).
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** Team pays by card through checkout. Invoiced teams use market `manual` (§20.5), and DESIGN.md gives them no self-serve path.
- **Lost:** A larger team cannot start or change an invoiced plan by itself.
- **Dark in code:** The `manual` market is the seam.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Invoices, terms and dunning in the billing provider, and the seat meter's report to it.

### quota-financial-claim-shares: Retuning taskworker's financial claim shares
Stage: Later, once service debits carry production volume
- **Deferred:** A claim share for `FlushServiceDebits`, and with it a retuning of production's financial shares (owner decision 521's option 2; QD-943; §20.6's flush row).
- **Why:** The four existing claim shares at period 8 already spend the half of ordinary claim turns the scheduler allows, and a fifth share at any period would panic every taskworker at construction. Service debits ship dark at M2, so there is no volume to measure yet.
- **Launch instead:** `FlushServiceDebits` takes no claim share. Its chains run on the ordinary queue and their function's indexed lane.
- **Lost:** Behind a totals backlog a flush may wait about a minute per claim, and balances read higher than they are for that long. It delays only the Postgres debit and the token release, never a refusal.
- **Dark in code:** Nothing is switched off. The shares are in server/taskworker/claim_admission.go.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Service debits carry production volume, M5's tls leases at the earliest. Then, from a measurement, the owner of those tunings sets `FlushTransferDebits`, `AdvancePayment` and `FlushServiceDebits` at period 12 each and the totals lane and its drain at 8.

### quota-v1: §20's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §20.16's v1 row. Team at M6: the `team` tier and its prices, seats, checkout, meters, credit line, downgrade jobs and share escrow, with D-QUOTA-9's comparator built dark in M4; the directory's request limits (D-QUOTA-11). Format 2 at M10 (owner decision 169): the search index counting as storage, versionless content's counting and freeing, the drop's rates and freed-byte reports (D-QUOTA-12), and remote search's relayed bytes.
- **Why:** Team ships at M6 and format 2 at M10.
- **Launch instead:** v0: free and pro tiers with their `sidecar:` blocks, counters and refusals at M1; the debit path and leases at M2; edge lease spending at M5, M7 and M9.
- **Lost:** Until M6: the Team tier. Until M10: format 2's accounting.
- **Dark in code:** Built in the same run. The escrow comparator's index is pending in MG6 until M6's Gn-out, and a drop frees nothing until §19.11's `drop` gate turns on (D-PHASE-12).
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6). M6's entry runs §20.9's benchmark and FS-46.
