module github.com/urnetwork/sidecar

go 1.27.4

tool google.golang.org/protobuf/cmd/protoc-gen-go

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/andybalholm/brotli v1.2.7
	github.com/cloudflare/circl v1.6.5
	github.com/creack/pty v1.1.24
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/ebitengine/purego v0.11.2
	github.com/emersion/go-ical v0.0.0-20261112170022-46c5b53a1723
	github.com/emersion/go-imap/v2 v2.0.0-beta.9
	github.com/emersion/go-message v0.18.2
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.25.1
	github.com/emersion/go-webdav v0.8.0
	github.com/google/go-sev-guest v0.15.1-0.20261120002523-d591100d9985
	github.com/google/go-tdx-guest v0.3.2-0.20261123220626-a4ee4f4ee52a
	github.com/google/go-tpm v0.9.8
	github.com/google/jsonschema-go v0.4.3
	github.com/gorilla/websocket v1.5.4-0.20240701034025-d67f41855da4
	github.com/klauspost/compress v1.20.2
	github.com/letsencrypt/pebble/v2 v2.10.3
	github.com/mholt/acmez/v3 v3.1.7
	github.com/miekg/dns v1.1.72
	github.com/mjl-/adns v0.0.0-20260809141028-22f885debe71
	github.com/mjl-/mox v0.0.17
	github.com/modelcontextprotocol/go-sdk v1.7.0
	github.com/pires/go-proxyproto v0.16.0
	github.com/pkg/sftp v1.13.12
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/urnetwork/connect v0.0.0
	github.com/urnetwork/operator-core v0.0.0
	golang.org/x/crypto v0.59.0
	golang.org/x/image v0.44.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
	golang.org/x/text v0.44.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beevik/etree v1.7.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/go-jose/go-jose/v4 v4.1.8 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/letsencrypt/challtestsrv v1.4.2 // indirect
	github.com/mjl-/flate v0.0.0-20250221133712-6372d09eb978 // indirect
	github.com/pion/datachannel v1.6.2 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/ice/v4 v4.4.1 // indirect
	github.com/pion/interceptor v0.1.47 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.17 // indirect
	github.com/pion/rtp v1.10.5 // indirect
	github.com/pion/sctp v1.11.1 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.13 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/pion/turn/v5 v5.0.12 // indirect
	github.com/pion/webrtc/v4 v4.2.18 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.61.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/teambition/rrule-go v1.8.2 // indirect
	github.com/theodorsm/covert-dtls v1.5.1 // indirect
	github.com/urnetwork/glog v0.0.0 // indirect
	github.com/veraison/go-cose v1.1.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260909230408-9b1144b679cb // indirect
	src.agwa.name/tlshacks v0.0.4 // indirect
)

replace github.com/urnetwork/connect => ../connect

replace github.com/urnetwork/operator-core => ../operator-core

replace github.com/pion/sctp => ../connect/sctp

replace github.com/urnetwork/glog => ../glog

replace gvisor.dev/gvisor => ../gvisor

// D-MAIL-3's go-smtp fork and plan-MAIL-mox-subset's mox subset, which every module that links the
// root repeats, since Go does not inherit a replace (QD-193; third_party/*/URNETWORK.md).
replace github.com/emersion/go-smtp => ./third_party/go-smtp

replace github.com/mjl-/mox => ./third_party/mox

// The attestation verifiers' trimmed copies of Google's go-tdx-guest and go-sev-guest (DESIGN-COMPUTE §5.3,
// CONTRACTS C-28), which every module that links the root repeats as it repeats the two above
// (third_party/go-tdx-guest/URNETWORK.md, third_party/go-sev-guest/URNETWORK.md).
replace github.com/google/go-tdx-guest => ./third_party/go-tdx-guest

replace github.com/google/go-sev-guest => ./third_party/go-sev-guest
