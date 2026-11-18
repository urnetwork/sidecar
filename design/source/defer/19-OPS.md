### ops-small-object-packing: Packing small segments on the HDD tier
Stage: Later, at its triggers
- **Deferred:** Q-OPS-2's option (a): packing segments under 1 MiB and older than 7 days into larger objects on the HDD tier, never kind-5 segments, which stay deletable one by one (§19.14, §19.18).
- **Why:** The peer review closed Q-OPS-2 with (b) in v0 and (a) as a switch: packing does not reduce GETs, which are about 25,600 of year two's 32,000 drive operations a second, and it turns on only once HDD drive operations pass 50% of measured capacity, after §22.8's `hdd` row at M3.
- **Launch instead:** Q-OPS-2's (b): segments are not packed on the HDD tier. The page cache serves most GETs, and HDD sets per D-OPS-17 carry the rest.
- **Lost:** Nothing until the trigger. Past it, small objects use HDD drive operations that packing would save.
- **Dark in code:** Format 1 freezes what packing needs, so it needs no format change: content-id segment ids, the reserved `spidx/` family and its lookup order, and reserved locator kinds 3 and 4, never a physical address.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8's `hdd` row gives the measured capacity; monitor shows HDD drive operations past 50% of it; then the packer, `spidx/`'s writer and readers, and its FS row are built and the switch turns on.

### ops-next-metadata-cluster: The next metadata cluster
Stage: Later, a tracked item at §19.9's triggers
- **Deferred:** A second metadata cluster, and later ones on new hosts (D-OPS-17; owner decisions 136, 145; §19.9, §19.18, §23.7). FS-63 and FS-119 run again before each new cluster takes repos (§22.17).
- **Why:** v0 has one cluster and one site for metadata (owner decision 94). The metadata tier grows only by whole clusters (owner decision 145), ordered when a trigger fires.
- **Launch instead:** One PM9A3 set of 8 drives with spares. §11.13's write budget refuses the heaviest network first when the set nears its limits.
- **Lost:** Nothing until a trigger. If the order comes late, the write budget refuses pushes, and a full cluster answers 507 CLUSTER_FULL (D-OPS-22).
- **Dark in code:** Placement is built: each repo is placed on a cluster at creation by a create-only `place/<repo_id>` object, so a second cluster needs no format change. monitor projects the triggers.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A trigger: 50% of raw capacity, 40% of inodes, 0.5 drive writes a day, or monitor's projection of one within the hardware's lead time. Then the hardware order, the cluster's bring-up, and FS-63 and FS-119 on it before it takes repos.

### ops-segment-placement: The segment placement and added HDD capacity
Stage: Later, a tracked item at §19.9's hdd trigger
- **Deferred:** A placement for segments that keeps §11.13's receipt check and moves upload load, not only new repos, to added HDD sets; and the added HDD capacity itself (owner decision 550; Q-OPS-11; Q-OPS-2's residual; D-OPS-17; QD-132; §11.22, §19.9, §19.18, §23.4, §23.7).
- **Why:** It is needed before year two's HDD load, not at launch. Owner decision 550 made it a tracked item with a lead time, so that undesigned work with no milestone still has a due date.
- **Launch instead:** One HDD cluster of 4 hosts (owner decision 94). Uploads are admitted up to 50% of its measured drive operations.
- **Lost:** Nothing until the trigger. Past it, uploads are refused at the admission line.
- **Dark in code:** Nothing of the placement is built. monitor's `hdd_trigger_lead_days` is 182, and the rota owns the page.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Engineering writes the placement's design within 8 weeks of M3's exit, when the hdd run first gives an admitted throughput (Q-OPS-11's residual). The work starts at M3's exit and is due before the crossing that §19.9's hdd trigger projects, with a lead time of 26 weeks.

### ops-second-site: A second site or an off-site copy
Stage: Later, decided from operating data
- **Deferred:** A second site for the services and the file clusters, or an off-site copy of the file clusters (owner decisions 89 and 94; Q-OPS-7; §19.18).
- **Why:** The owner's words (owner decision 94): "v0 will have only one cluster and site for each metadata and storage, with 2 replicas in minio." Whether a second site comes in v1 or later is decided from operating data (owner decision 89).
- **Launch instead:** One site. The RPO and RTO targets cover drive and host failures only, and the file clusters have no off-site copy.
- **Lost:** A site loss loses server-held data on the file clusters. Recovery is from devices' local copies (§19.10), and a hold's kept objects are void (§21.9).
- **Dark in code:** Nothing is built. §7.9's site-loss resumption and §19.10's restore are the launch path for a lost site.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Operating data on failures and growth, an owner decision, then a design for replication that keeps evs's single commit point.

### ops-v1: §19's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §19.18's v1 rows. At M6: migration group MG6, then `escrow_draw_order` on (§20.9); the team directory's load; 24/7 review. At M10 (owner decision 169): §19.11's `format2` gate with its purge and drop modes, each observe first and then on; the sweep and D-OPS-21's bounds; the search index's load in §19.9's projection (owner decision 174).
- **Why:** Team ships at M6 and format 2 at M10.
- **Launch instead:** v0: §19.11's rollout order, dark first; one metadata set and the HDD cluster; the sidecar dump with its restore and re-seed drills; infrastructure paging from M3 and business-hours abuse review.
- **Lost:** Until M6: Team billing's draw order and round-the-clock review. Until M10: format 2 in production.
- **Dark in code:** Built in the same run. MG6's migrations stay pending until M6's Gn-out, and the `format2` gate admits internal networks and design partners first.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
