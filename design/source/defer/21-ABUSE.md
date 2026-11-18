### abuse-preservation-holds: Preservation holds, turned on
Stage: Built at M5, off until counsel confirms
- **Deferred:** Placing a preservation hold (§21.9; owner decisions 133, 525, 526, 528, 529; §23.7).
- **Why:** Owner decision 133's condition: counsel confirms it, and each hold kind's applicability (`preserve_2703f`, `report_2258a`), before any hold is placed.
- **Launch instead:** Holds are built and tested, and `holds_enabled` is false, so placement is refused.
- **Lost:** Until counsel confirms, a preservation request cannot be met by placing a hold.
- **Dark in code:** abuse.yml's `holds_enabled`, false (server/abuse_config.go; server/controller/abuse_hold_controller.go refuses placement).
- **Held:** Nothing in the build. §23.7 tracks counsel's confirmation.
- **To bring back:** Counsel's confirmation of owner decision 133's condition and of each hold kind; then `holds_enabled` is set true in each environment's abuse.yml.

### abuse-v1: §21's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §21.18's v1 items: 24/7 review and tightening the team directory's request limits at M6 (§21.7); at M10 (owner decision 169), holds deferring a drop's deletions (owner decision 184).
- **Why:** Team ships at M6 and drops at M10.
- **Launch instead:** v0 at M5, before any public name: §21.6 to §21.10 with the report host, the DMCA agent and business-hours review, with notices on §19.8's rota (owner decisions 134, 143).
- **Lost:** Until M6: review outside business hours, other than the notices the rota carries.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
