### core-transport-proof-of-possession: Proof of possession on transport auth
Stage: Later
- **Deferred:** Q-CORE-4's option (c): a sidecar proving its ClientKey when it authenticates a connect transport (§5.17; §7.4's residual).
- **Why:** The peer review of 2026-11-04 closed Q-CORE-4 with (b) in v0 and left (c) for later, its residual stated in §7.4.
- **Launch instead:** A `strict_exp` bearer adds a DPoP proof by its ClientKey when it refreshes, exchanges a token or calls `POST /network/auth-client` (§7.4), so a copied token renews, exchanges and mints nothing.
- **Lost:** A token copied alone still authenticates a connect transport until its `exp` (§5's token row; §7.4's residual).
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the proof on connect's transport auth, which is a connect change §4.6 does not list, and its place in §6's Hello.

### core-v1: §5's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §5.17's v1 rows. At M6: several networks per daemon, with team networks (owner decisions 23, 55); the RFC 8628 device grant; agent subkeys; `.ur`'s `claims` and `project`; the directory's control methods, group, local state and settings; the `access_request` action and events (owner decisions 170, 171, 182). At M10: the index cache, search state and `Search` settings (owner decision 163); remote serving (owner decision 175); local deletion of dropped content (owner decision 173); the index, search and drop event kinds.
- **Why:** Team ships at M6 and storage format 2 with search at M10 (owner decisions 55, 163, 169).
- **Launch instead:** v0's daemon serves one personal network per daemon, with M1-M3's enrollment, config repo, gate and `.ur`.
- **Lost:** Until M6 and M10: team networks on a daemon, agent subkeys, the directory, and search.
- **Dark in code:** Built in the same run on the `sidecar` branches, behind each milestone's gates.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
