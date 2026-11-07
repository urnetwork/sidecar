// This module's own clients of the local stack in local/ (§22.4), so blobsuite and redissuite run on
// real stores here, which is what keeps the fakes honest (D-TEST-2). go-redis and minio-go stay out of
// this module (§4.5), so these speak RESP and S3 on the standard library alone. server's ServiceHost is
// what T3 runs; these stand in for it nowhere else, and no release links them.
//
//   - redis*.go, sidecar.Redis on a Redis Cluster: slots, MOVED and ASK, scripts by SHA-1, and the
//     process's one shared key-event subscriber.
//   - blobs*.go, sidecar.BlobStore on MinIO: SigV4, conditional PUTs, and what each answer means under
//     host_blobs.go.
//
// Both dial only what CheckStackAddress allows, so a seed or a redirect pointing anywhere else is
// refused before a socket opens.
//
// The tests that need the stack up carry the sidecar_localstack tag, and fail, rather than skip, when
// it is down: local/stack.sh test runs them. Everything else here runs on an in-process server.

package localstack
