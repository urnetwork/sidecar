// The test ground: T2 of §22.4, sidecars and engines in one process on fake stores, an injected clock
// and barriers, and what T3 reuses on real stores. Tests here are deterministic: time moves when a
// schedule moves it, and a goroutine is held where a schedule says, so nothing sleeps.
//
// What lives where:
//
//   - clock.go, the injected clock.
//   - barrier.go, the driver behind testHookBarrier, and actor.go, the processes a schedule runs,
//     kills and restarts. testhooks.go and testhooks_enabled.go install the driver on the root and on
//     device/ under sidecar_testhooks; without the tag no site in this module reaches it.
//   - faults.go, a store fault as a plan the next matching operation gets.
//   - blob_history.go, what a store's clients saw, and FI-30's check of it.
//   - privacy_*.go, §22.7's harness: privacy_capture.go the needles (canaries, hooked keys, forbidden
//     values) and the scan's findings, privacy_encode.go the forms a needle takes, privacy_scan.go the
//     one-pass scan, privacy_decompress.go the views a body opens, and the capture points:
//     privacy_handler.go CC1 and the request log, privacy_frame.go CC2's rule and frame sizes,
//     privacy_sources.go CC4 and the classes. leak.go and leak_enabled.go are its self-test's leaks,
//     linked only under sidecar_leaktest. privacy_asserts.go is the assert block's registry, each clause
//     with its gates, owners and registered tests, which a Gn-out sweep reads for what is missing.
//   - metadata_list.go, §2.8's list and its strict reader, and schema_guard*.go, §22.7's guard over it,
//     whose map is testdata/metadata/fields.yml.
//   - fake_blobs*.go, fake_redis*.go and the other fake_ files, a fake of every interface ServiceHost
//     holds, gathered by fake_host.go.
//   - net*.go, connect clients in one process, built on connect's exported API alone (Q-TEST-1).
//   - blobsuite and redissuite, the conformance suites, which take a fake or a real store.
//   - localstack, this module's own clients of the stack in local/, so the suites run on real stores
//     without go-redis or minio-go, which stay out of this module (§4.5).
//   - crossslot, §22.4's static lint, which make check runs on this module and server can run on its own
//     sidecar code.
//   - dns_store_fake.go and dns_store_suite.go, the seams of dnsservice and their suite, which runs
//     here on the fake and in server on dnshost.Store.
//   - mxedge_store_fake.go, mxedgeservice's seam, which MAIL-M7-21's real store replaces.
//   - fake_record_streams.go and fake_record_auth.go, the record's seams (record_seam.go): evs's record-class refs,
//     §7.9's and §8's state at a pin, and §16.6's run files; record_streams_suite.go, the suite RECORD-M3-12's
//     binding passes on T2.
//   - smtp_*_fake.go, the sender's and the engine's seams in memory (§14): FakeSmtpProver,
//     FakeSmtpProofVerifier and FakeSmtpMailbox, whose suite is smtp_mailbox_suite.go.
//   - headcheck_fakes.go, §6.4's HeadCheck sources (rpc_headcheck_sources.go): a network's authorization
//     log as api holds it, which withholds and forks, and each device's log, pins and peers.
//   - smtp_mx*.go, the outside world outbound mail meets: ScriptedMx behind crypto/tls, RecordMx behind
//     a TLS server written from the RFCs, and MxWorld, a signed fixture DNS and dialer, all on
//     in-process pipes; smtp_edge_stub.go, StubSmtpEdge, which runs a sender before the engine exists.
//   - fault, the FS schedule runner (§22.8), with catalog.yml, §22.8's rows and §23.6's gates, and
//     §22.8's rules across runs: twins, every write's lost response, the explorer and replays.
//
// This package and its children import no server package, and server imports them for T3 (D-TEST-2).
package sidecartest
