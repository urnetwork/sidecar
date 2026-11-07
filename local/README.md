# The local stack

§22.4's stores for this machine: what `blobsuite` and `redissuite` run on when they are not running on a
fake (D-TEST-2), and what T3 and the engines' store tests dial.

| Store | Shape | Where |
|---|---|---|
| Redis Cluster | 3 masters, no replicas, Redis 8.10.2, production's `Kg$sx` keyspace classes | `127.0.0.1:56401`, `:56402`, `:56403` |
| MinIO | one process, 8 drive directories, EC:4 | `127.0.0.1:59000` |

Everything binds to loopback above port 50000, and `sidecartest/localstack`'s clients refuse to dial
anything else. The containers are `sidecar-test-redis-cluster-0` to `-2` and `sidecar-test-minio`. The
MinIO root user in `docker-compose.yml` is synthetic and reaches nothing but this stack.

```sh
local/stack.sh up       # starts the stores and forms the cluster
local/stack.sh test     # runs the suites on them; make stack-test is the same
local/stack.sh status
local/stack.sh down     # stops them and drops what they held
```

`test` starts the stack if it is down and stops only what it started. Tracks share one stack, and each
suite works under keys of its own, so runs side by side do not collide. A run holds the stack while it
runs, and `down` is refused until it ends.

`make check` needs no Docker, so it leaves all this out: the real-store tests carry the
`sidecar_localstack` tag, and fail, rather than skip, when the stack is down.

## What waits for the fork

This runs a stock MinIO, `cgr.dev/chainguard/minio` pinned by digest, since upstream's Docker Hub and
quay.io images could not be pulled here on 2026-11-06. `minio --version` reads
`RELEASE.2026-10-23T20-06-51Z`. §22.4 asks for MinIO built from the `minio` fork, whose base has PR
#21653, and D-OPS-20's settle rules exist only there.

- **FS-114 waits for the fork.** A stock build keeps none of §19.6's deadline or settle rules, so
  `BlobSettings.SettlePassed` stays false and `blobsuite` names the cases it did not run, in its log, every
  run. Nothing here shows the settle rule holds, and nothing may read a pass from this stack.
- FS-114 also needs T3's 4 × 2 and 4 × 4 sets, with real hosts to lose, which one process is not.
- This image's lineage against PR #21653 is unproven: the suite shows conditional writes on a healthy set,
  not what a read losing quorum does (FS-1, FS-40).

To run the fork once it has a build, set `SIDECAR_LOCAL_MINIO_IMAGE` to its image, and set
`BlobSettings.SettlePassed` only for a build that has passed §22.9's settle cases.

## Not here

T3's MinIO layouts (4 × 2 at EC:4, 4 × 4 at EC:8 and a second metadata cluster) are not in this stack.
§22.15 places the local stack in `server/local`; it lives here because this repository's suites run on it,
and server's T3 dials the same ports.
