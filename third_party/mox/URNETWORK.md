# Local mox subset

This directory holds ten packages of `github.com/mjl-/mox v0.0.17` (module zip
`h1:mzB61AwbTPD2jShT+THCgAeMkoFAfWHOXE7IbMedK9I=`, fetched through
proxy.golang.org and checked against Go's checksum database): `dkim`, `dmarc`
and `spf`, which D-MAIL-3 names, and the seven they import, `dns`, `message`,
`mlog`, `moxio`, `publicsuffix`, `smtp` and `stub`. Each is as published, its
tests included, except for the change to `mlog/log.go` below. Beside them are
mox's two license files, `testdata/message/`'s two messages, which `message`'s
tests read, a `go.mod` naming only what these packages need, and this file.
Nothing else of mox is here. The module path stays `github.com/mjl-/mox`, so a
module replaces it here (QD-193, RESOLUTIONS.md's plan-MAIL-mox-subset).

mox is MIT, in `LICENSE.MIT`. `publicsuffix/public_suffix_list.txt`, which
`publicsuffix` embeds, is Mozilla's Public Suffix List under MPL-2.0, in
`LICENSE.MPLv2.0`, so `dependencies.yml` lists the module as `MIT AND
MPL-2.0`. No file here carries the Go Authors' BSD code mox's README mentions.

## The change

As published, every mox package imports `mlog`, and `mlog` registers three
Prometheus counters, `mox_logging_level_{info,warn,error}_total`, which pull
`prometheus/client_golang` and its dependencies into every leg that links a
verifier. §4.5 keeps prometheus out of sidecar, and plan-MAIL-mox-subset
measured them at about 5.8 MB of an android/arm64 binary. `mlog/log.go`
drops the two prometheus imports, the three counters and the block of
`handler.Handle` that counts a record at info, warn or error. Nothing else
reads them, and logging is otherwise unchanged.

`go.mod` requires `github.com/mjl-/adns`, `github.com/mjl-/flate`,
`golang.org/x/net` and `golang.org/x/text` at mox v0.0.17's versions, and no
other module, so a consumer's module graph gains none of mox's server
dependencies (bbolt, prometheus, sherpa and the rest).

## Checked here

- `go list -deps ./dkim ./dmarc ./spf` on darwin/arm64, linux/amd64,
  windows/amd64, android/arm64, ios/arm64 and js/wasm holds no prometheus, no
  bbolt and no template package, and no third-party module but adns and flate.
- `go build ./...` passes on each of those but js/wasm, where
  `github.com/mjl-/adns` does not compile (`lookupProtocol` and `lookupHost`
  have no js implementation). A file that links these packages must therefore
  stay off js as well as off `sidecar_http`.
- `go test ./...` here passes. The `Example` functions that would resolve
  through the system resolver have no `Output` comment, so they compile and
  never run, and every test resolves through `dns.MockResolver`. `message`'s
  `TestWalkdir` makes empty `testdata/train/ham` and `testdata/train/spam`
  directories, which git does not record, and `moxio`'s `TestLinkOrCopy`
  writes and removes a file beside its package and one in the system's
  temporary directory.

The verifiers log through the `*slog.Logger` their caller passes, and through
mlog's own handler to standard error when it passes nil. A caller in sidecar
passes a logger that writes nothing, since a verifier's log lines name
domains and addresses (I-13).

## Who replaces it

The same modules as `../go-smtp`, with the same paths: `./third_party/mox`
in `sidecar/go.mod`, `../third_party/mox` in `sidecar/cli`,
`sidecar/smtpproof` and `sidecar/mlsinterop`, and
`../sidecar/third_party/mox` (one level further up in the nested sdk modules)
in server, sn and the four sdk modules. upstream's API is a superset of this
subset's, so the release fixture, which builds without replaces, still
builds. Offering the `mlog` change upstream is an outward action for the
owner.
