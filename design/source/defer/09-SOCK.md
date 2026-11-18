### sock-region-aware-selection: Region-aware listener selection
Stage: Later
- **Deferred:** Choosing a listener by region, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why:** §9.17: there is one lb site today, so there is no second region to prefer.
- **Launch instead:** §9.7's scheduler: P2C over the listeners of a name, with its per-dialer clamp on `est`.
- **Lost:** Nothing while there is one site.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A second lb site, then a region value on registrations and a rule in the scheduler.

### sock-slow-start: Slow start for new listeners
Stage: Later
- **Deferred:** Slow start in listener selection, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** A new listener takes its share at once under §9.7's P2C and clamp.
- **Lost:** A listener that has just registered is not ramped up, so a cold one can take a full share of dials.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A measured overload of fresh listeners, then a ramp in the scheduler's settings.

### sock-edge-delegated-ticket-keys: Edge-delegated ticket keys
Stage: Later
- **Deferred:** Ticket keys delegated to edge hosts, so that edges admit streams through a sockets outage (§9.11's alternatives row; §9.17).
- **Why:** §9.11's row gives its cost: keys on edge hosts, while C9 still needs Redis.
- **Launch instead:** The sockets service signs every ticket with keys it reads from vault, and listeners verify them (§9.6, §9.8).
- **Lost:** Edges do not survive a sockets outage: no new ticket is issued while sockets is down.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for which keys an edge may hold and for how long, and a new §2.4 asset row for keys on edge hosts.

### sock-registration-over-push: Registration over push
Stage: Later
- **Deferred:** Listener registration carried over push, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** A registration is a lease that the listener's own client renews by a heartbeat every 15 s, and it lapses 45 s after the last one (§9.5).
- **Lost:** A device that is not connected holds no lease, so its names answer nothing until it connects again.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design, since DESIGN.md says no more than the name: who holds a lease for a sleeping device, and how a wake reaches it through §18.7's push path.

### sock-v1: §9's v1 set
Stage: v1 (M6)
- **Deferred:** §9.17's v1 row: affinity, with §13; Team scope hosts (owner decisions 40, 55, 58), the `smtp/` ones with §15.
- **Why:** Team ships at M6.
- **Launch instead:** v0's `sockets` service at M5: blinded names, `tls/` with §13, tickets, P2C, `SocketHint`, the Go API, `ur socket` and `ur share`.
- **Lost:** Until M6: affinity and Team's scope hosts.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: it ships when M6's gate passes (§23.6).
