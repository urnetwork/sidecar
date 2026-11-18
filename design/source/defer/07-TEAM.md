### team-stage-3-hard-gate: Stage 3 of the admin-credential fix
Stage: Later, on app adoption
- **Deferred:** §7.4's stage 3, the hard gate: all 27 AppAdmin routes refuse client credentials (owner decision 45; §7.19; §23.4).
- **Why:** Existing apps still send client credentials to those routes. Stage 3 waits until under 1% of active app clients do so for 14 days, or until `upgrade_required` enforces SDK `bc72b109`.
- **Launch instead:** Stage 1 before any sidecar ships: child and admin-refused clients are refused on the AppAdmin and OwnClientPayout routes, and an allowlist confines `strict_exp` bearers. Stage 2 before the first desktop sidecar runs beside an app or the extension.
- **Lost:** Until stage 3, an older app's own client credential still administers its network on those routes.
- **Dark in code:** The refusal is one predicate, `ClientRefusesAdmin` (server/model), which stages 1 and 2 already use.
- **Held:** Nothing.
- **To bring back:** The adoption measure passes, or `upgrade_required` is enforced; then the predicate refuses every client credential on the 27 routes.

### team-v1: §7's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §7.19's v1 rows. Team at M6: members, roles, invitations, switching, OIDC, domains, JIT, SCIM and `scim_signer`, OAuth clients, full `ur-cli` admin, the audit log, multi-admin teams, config wraps for member devices past the first 1,000 (owner decision 144), and the team directory (owner decisions 170, 171, 182). Every network at M10: `VersioningRules` and `IndexerSet`'s `search` service (owner decisions 157, 163, 164, 175, 178).
- **Why:** Team ships at M6 (owner decisions 55, 102) and storage format 2 at M10 (owner decision 169).
- **Launch instead:** Personal networks, n = 1: auth keys, enrollment, token exchange and the enforced config repo with its authorization log. The k-of-n verifier and proposals are built and tested at M2 though a personal network has one admin.
- **Lost:** Until M6: more than one member in a network. Until M10: versioning rules and search indexers.
- **Dark in code:** Built in the same run. M2's records reserve what M6 and M10 need: `ServiceSettings.directory` (D-TEAM-28) and the `VersioningRules` type.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6). The `admin_user_id` audit blocks members.
