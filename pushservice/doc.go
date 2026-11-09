// §6.8's server push, the server-only half (owner decision 104): what owning services write when a
// client's state changes, what residents and api's long-poll read to tell it, and the arithmetic both
// sides hold versions to. Only server imports this package, so go-redis stays out of this module: every
// store is an interface here, which ServiceHost.Redis and server's model adapter satisfy.
//
// A hint is a prompt, never content (R-PROTO-8). It lands in the client's slot {scp_<C>} as one script
// that raises the topic's version in ver, adds the hint to the stream hint and INCRs n, whose keyspace
// event is the one trigger production's classes emit (D-PROTO-12). Every version travels as a canonical
// decimal string, compared without ever becoming a Lua number, since evs's push sequence is near
// 1.8 x 10^18 and Lua holds doubles.
package pushservice
