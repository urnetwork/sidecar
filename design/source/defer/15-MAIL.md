### mail-destination-routing: Destination routing on a routed IPv6 block
Stage: Later, if a routed IPv6 block is obtained
- **Deferred:** Routing inbound mail by destination address, which would restore a fallback for senders that send no SNI (owner decision 34; §15.17).
- **Why:** The owner's constraint (owner decision 34): "There are no dedicated ipv4 or ipv6 options currently."
- **Launch instead:** Inbound routing is SNI and DANE only, on the shared lb addresses. M7's census measures which senders send no SNI, and the owner accepts that loss before the burner launch (D-MAIL-9).
- **Lost:** Mail from senders that send no SNI is not delivered; the census sizes it.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A routed IPv6 block from the transit provider, then per-network addresses in §12's records and a route in mxedge.

### mail-team-burners: Team burners
Stage: Later
- **Deferred:** Burner addresses for Team networks, named in §15.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. BS1, the burner launch, is on personal networks.
- **Launch instead:** Burners on personal networks from M8, replies from M9. Team networks get admin, id, group and agent addresses, and scopes.
- **Lost:** A team member has no burner under the team's network.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for who owns a team burner, where its vault entry lives, and how §21's limits count it.

### mail-edge-reputation: Edge reputation from receiver verdicts
Stage: Later
- **Deferred:** Scoring senders at the edge from receivers' verdicts, named in §15.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** mxedge's banner rejects only a commercial feed's botnet and exploit listings and passes other listings on to the receiver (§15.4); the receiver's device verifies SPF, DKIM, DMARC and ARC and scores each message itself (§15.5).
- **Lost:** What one receiver learns about a sender does not protect another.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for what a receiver reports, since a verdict is new server-visible metadata and needs a §2.8 row first.

### mail-named-credentials: Several named mail credentials per network
Stage: Later
- **Deferred:** Several named verifiers per network for IMAP and submission, each made and revoked on its own as app passwords are, with `ur mail credential ls` and `rm` (owner decision 442's option 4; QD-859; §15.10).
- **Why:** Owner decision 442 takes option 1 now and option 4 later.
- **Launch instead:** One credential per network. `ur mail credential` shows its secret once, and the daemon keeps only a verifier.
- **Lost:** A person with two mail clients saves the secret when it is shown, or makes a new one and enters it in each client. One client's credential cannot be revoked alone.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A list of named verifiers in the network's keychain, the two commands, and LOGIN's constant-time compare over every verifier.

### mail-v1: §15's v1 set
Stage: v1 (M7, M8, M10)
- **Deferred:** §15.17's v1 rows. Team (owner decisions 33, 58, 98, 150): network-scope mail indexers, direct MX and strict mode from M7, scopes from M8. M10 (owner decision 169): mail search (D-MAIL-16), IMAP SEARCH on the engine, and phones' remote search over mail.
- **Why:** Team ships at M6 and search at M10.
- **Launch instead:** v0: the platform listener at M5, network mail at M7, burners and IMAP at M8, sending at M9.
- **Lost:** Until those milestones: a team's shared receivers and strict mode, and search over mail.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
