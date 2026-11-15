// The mxedge engine (§15.4, D-MAIL-1, D-MAIL-2): what the router and the platform listener share on
// TCP 25. server hosts it, and only server imports this package. Inbound TLS ends at customer receivers,
// so the engine holds no TLS key and sees ciphertext plus §2.8's mx-1. What lives where:
//
//   - settings.go, config/<env>/mxedge.yml.
//   - store.go, MxEdgeStore: the only way this engine reaches Postgres.
//   - dialog.go, the pre-TLS dialog, a state machine that does no I/O.
//   - caps.go, the session caps, in memory.
//   - closed_handshake.go, the fleet's closed-handshake memory in {mxc_}, under the daily k in
//     {vhk}mx:.
//   - service.go, the engine: Serve, a session's path, readiness and drain.
//   - metrics.go, the metric families and their closed label values.
//   - platform.go and platform_session.go, the platform role (D-MAIL-10): TLS ended here, then a
//     go-smtp session that hands each message to PlatformIntake.
//   - router.go, the router role (D-MAIL-1, D-MAIL-2): the ClientHello, a route by SNI alone, the Find
//     and open through MxEdgeDialer; route_cache.go, {mxr_<net>} behind an in-process cache;
//     ingress.go, MailIngress within its bound; ptr.go, the sender's forward-confirmed PTR; splice.go,
//     the splice, its §15.4 bounds and its lease on meter mx.
//
// Two roles stand on this: the router, which NewMxEdgeRouterService starts, and the platform listener,
// which NewMxEdgePlatformService starts. NewMxEdgeService starts the shared front with no role, which
// no host runs: every session that reaches STARTTLS's 220 closes in the handshake, the temporary
// failure §15.4 gives anything unroutable.
package mxedgeservice
