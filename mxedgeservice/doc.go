// The mxedge engine (§15.4, D-MAIL-1, D-MAIL-2): what the router and the platform listener share on
// TCP 25. server hosts it, and only server imports this package. Inbound TLS ends at customer receivers,
// so the engine holds no TLS key and sees ciphertext plus §2.8's mx-1. What lives where:
//
//   - settings.go, config/<env>/mxedge.yml.
//   - store.go, MxEdgeStore: the only way this engine reaches Postgres.
//   - dialog.go, the pre-TLS dialog, a state machine that does no I/O.
//   - caps.go, the session caps, in memory.
//   - closed_handshake.go, the fleet's closed-handshake memory in {mxc_}.
//   - service.go, the engine: Serve, a session's path, readiness and drain.
//   - metrics.go, the metric families and their closed label values.
//
// Two roles stand on this: MAIL-M7-19's router, which routes by SNI and splices, and MAIL-M5-03's
// platform listener. Until one replaces MxEdgeService's handoff, every session that reaches STARTTLS's
// 220 closes in the handshake, the temporary failure §15.4 gives anything unroutable, so this engine
// alone delivers nothing and tells no sender no for good.
package mxedgeservice
