### phase-rs3-assurance-stage: RS3, recURd's assurance stage
Stage: Later
- **Deferred:** RS3, the third of recURd's stages, "inbox and assurance", released whole once its assurance items land (R-PHASE-4; §20.16, §23.4, §23.16). Its items are a team's own legal holds, compliance mappings, and self-hosted and air-gapped installs; each has its own entry.
- **Why:** R-PHASE-4: the three stages ship whole, in order. RS3's assurance items are outside M0-M10.
- **Launch instead:** RS1 at M4 and RS2 at M6, each released once its last item lands, and BS1, the burner launch, at M8.
- **Lost:** RS3 is not released as a stage, since a stage ships whole.
- **Dark in code:** Nothing is built. The gate tool's `stages.yml` lists RS1, RS2 and BS1 and has no RS3 row (server/local/sidecar-gate).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Each assurance item is designed and built; then RS3 gets its row in `stages.yml` and its release review.

### phase-compliance-mappings: Compliance mappings
Stage: Later, with RS3
- **Deferred:** Mapping the product's controls to compliance frameworks, named in §23.4's Later paragraph. It has no D- item, task or FS row.
- **Why:** It is an RS3 assurance item. DESIGN.md gives no further reason.
- **Launch instead:** The trust documents of §21.11 and §2.8's published list say what servers see; no framework mapping is claimed.
- **Lost:** A buyer who needs a mapping to a named framework does not get one.
- **Dark in code:** Nothing: a mapping is a document.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The owner names the frameworks; the mapping is written against the built system; RS3's review reads it.

### phase-self-hosted-installs: Self-hosted and air-gapped installs
Stage: Later, with RS3
- **Deferred:** Running the server services on a customer's own infrastructure, air-gapped included (owner decision 48; Q-CTX-1; §23.4).
- **Why:** Owner decision 48: self-hosting comes at the later "assured" stage and is kept possible from v0. There is no self-hosted bundle in v0.
- **Launch instead:** URnetwork runs every server service.
- **Lost:** A customer who must run the services itself cannot use the product.
- **Dark in code:** The seam is built: engines reach URnetwork-only infrastructure (Route 53, warp, shared Postgres, connect relays) only through operator-core's interfaces, whose instances an `Env` creates (D-REPO-3; owner decision 251), and `make check`'s layering rules hold it.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** An `Env` over a customer's own stores and DNS, a bundle with its install and upgrade path, an answer for connect relays in an air gap, and the release's signing story for a build URnetwork does not run.
