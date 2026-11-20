### test-synthetic-main-network: The synthetic main network
Stage: Later
- **Deferred:** A synthetic network on main that repeats scenarios S2 and S5 to S7 every hour (D-TEST-5; QD-594; §22.17).
- **Why:** D-TEST-5 puts it beyond M0-M10. No task builds it (QD-594).
- **Launch instead:** Every scenario runs §22.7's harness and guard at its gate, on T1 to T4.
- **Lost:** No hourly end-to-end probe of production. A break that the monitors' own signals miss shows first to a user.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A network on main set aside for it, the scenarios packaged to run against production under §2.8's rules, and alert classes for their failures.

### test-drop-liveness-two-instances: The drop extension's liveness on two instances
Stage: Review phase
- **Deferred:** TLC's check of `EvsCommit.tla`'s drop extension's liveness, F2DropsEnd and the spec's other properties under weak fairness, with the drop job running in two instances once one lease lapses (§22.8's model row; owner decision 648, whose answer leaves the two instances to the review phase; ledger id QD-1119; the plan's EVSB-M10-07).
- **Why:** The owner accepted the live-drop mode on one instance, as EVSB-M10-07 ran the drop stories by hand; the question priced it as a liveness run per drop story at every gate where the spec's sources changed, and two instances multiply those runs' states. DESIGN.md gives no other reason.
- **Launch instead:** M10's exit needs the live-drop mode: each drop story under the spec's weak-fairness properties on one instance, beside the drop extension's twins and stories (§22.8's model row; §22.10's format 2 row).
- **Lost:** No gate checks that every executing drop still ends while two job instances act on it, a lapsed lease's owner and the instance that took the job over.
- **Dark in code:** run-tlc.sh's live-drop group runs each drop story on one instance; no two-instance liveness configuration is written.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A two-instance configuration for each drop story's liveness run, recorded in modelled.yml as a mode M10's exit needs, with its states and time measured.

### test-v1: §22's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §22.17's v1 rows. At M6: S3b, S4b, the OIDC, JIT, SCIM and custom-domain rows, the seat cases, FS-30's audit reader, S13, FI-25, FI-26 and the M6 cases of FS-84 to FS-88 and FS-97 to FS-101. At M10 (owner decision 169): S11, S12, FI-16 to FI-24, FI-27, FS-64 to FS-81, FS-83, FS-89 to FS-96, FS-107 to FS-112, FS-114's purge and drop cases and FS-125; the index vectors on every leg; git-lfs conformance; both models and `EvsCommit.tla`'s drop extension.
- **Why:** Each test runs at its component's milestone (§23.6's gate map).
- **Launch instead:** v0's rows: T1 to T4, the M2 storage benchmark with D-TEST-11's gate, and each FS at its gate through M9.
- **Lost:** Nothing: a test waits with what it tests.
- **Dark in code:** Built in the same run; the fault catalog holds each row to its gate.
- **Held:** Nothing here. TEST-M6-03 is held with the prefix write rules, under §8's entry.
- **To bring back:** Nothing to bring back: each runs at its milestone's gate (§23.6).
