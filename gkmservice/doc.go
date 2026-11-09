// The gkm engine (§10.6), which server/cli/gkm hosts at gkm.<root>: a strongly consistent Delivery Service with no
// state of its own (D-KEYS-5, R-KEYS-14). Its records are objects on the metadata clusters, ordered by conditional
// writes, and only acks sit in Redis, as soft state (owner decisions 2, 136, 145). It never holds a group secret, an
// epoch key or an unwrapped RK_g (I-1, R-KEYS-6): it stores ciphertext, MLS handshake bytes and the headers §10.6
// lists, and it reads no proposal.
//
// KEYS-M2-12 built the foundation: the engine and its guard (service.go), the token and scope checks against gkm's
// newest verified state (auth.go), §10.6's scopes block as one route table (routes.go), the object keys (objects.go),
// placement, repo/ and GroupForm resolution (store.go), per-process rate counters (rate.go), GkmHint sending
// (hints.go) and the barriers schedules hold (testhook.go). Each route's handler is its own task's: KEYS-M2-13 the
// per-sidecar routes (keypackages.go, readerkey.go, welcomes.go), KEYS-M2-14 groups, epochs, GroupInfo and acks,
// KEYS-M2-15 generations, wraps, drop keys and recovery wraps. A route whose handler has not landed answers 501
// once the guard has passed it, so nothing reads as served before it is.
package gkmservice
