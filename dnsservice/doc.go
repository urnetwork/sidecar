// The dns engine (§12): one zone per root, signed online and served from memory by the dns edges,
// with every record write one Postgres transaction that takes a serial and a journal row, which the
// edges follow. server hosts it as server/cli/dns, in two roles: API blocks serve §12.8's routes and
// the feed, and dnsedge answers UDP and TCP 53.
//
// Only server imports this package, so no client leg links miekg/dns. What lives where:
//
//   - settings.go, config/<env>/dns.yml.
//   - wire.go, what the journal, snapshots and the feed carry between the block and its edges.
//   - store.go, DnsStore and DnsFeed: the only ways an engine reaches §12.14's tables and an edge
//     reaches the block, so each part here runs on sidecartest's fakes before its real half exists.
//   - zone.go, zone_trie.go and answer.go, a root held at one serial and the unsigned answers it gives.
//   - keyset.go, sign.go, denial.go and selfcheck.go, online signing under DO: the ZSK and the released
//     DNSKEY window, signatures with their cache and cap, compact denial, and the check every zone
//     build and key set passes before it serves.
//   - edge.go and rrl.go, dnsedge: UDP and TCP 53 answered from the view FeedLoop publishes, with
//     response-rate limiting and no query log.
//   - probe.go and probe_tls.go, the lb interface probes and the healthy set edge rows answer from.
//   - feed.go and snapshot_file.go, the edge's feed loop: rows applied and checked before they serve,
//     reloads and their diffs, and the local snapshot a restart serves from.
//   - metrics.go, the metric families and their closed label values.
//
// This package never opens Postgres or Redis itself, and an edge holds neither, so with the core
// down it keeps serving and only writes wait (D-DNS-3, I-12).
package dnsservice
