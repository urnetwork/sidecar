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
//   - fake_blobs*.go, fake_redis*.go and the other fake_ files, a fake of every interface ServiceHost
//     holds, gathered by fake_host.go.
//   - net*.go, connect clients in one process, built on connect's exported API alone (Q-TEST-1).
//   - blobsuite and redissuite, the conformance suites, which take a fake or a real store.
//   - crossslot, §22.4's static lint.
//   - localstack, this module's own clients of the local stack in local/, so the suites run on real
//     stores without go-redis or minio-go, which stay out of this module (§4.5).
//   - fault, the FS schedule runner (§22.8).
//
// This package and its children import no server package, and server imports them for T3 (D-TEST-2).
package sidecartest
