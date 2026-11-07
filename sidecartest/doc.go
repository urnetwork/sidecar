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
//   - privacy.go, §22.7's capture: canaries, hooked keys and the scan.
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
//   - fault, the FS schedule runner (§22.8).
//
// This package and its children import no server package, and server imports them for T3 (D-TEST-2).
package sidecartest
