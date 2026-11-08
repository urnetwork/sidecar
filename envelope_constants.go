// §6.4's and §6.5's protocol values, on every leg. These are facts of the wire, not tunables, so they
// are constants (D-PROTO-16; connect/CODESTYLE.md's exceptions): another value here is another
// protocol. §6.6's tunables are in envelope_settings.go.

package sidecar

import (
	"time"
)

const (
	// The one public id, "UR", every service rides behind an inner type (§6.4, D-PROTO-1). Untyped, so
	// a connect-facing file passes it as connect.SubprotocolId and this file names no connect type.
	SubprotocolId = 0x5552
	// The last of the ids held beside it, 21843 on (§6.4). sdk refuses all of them for apps (§18).
	SubprotocolHeldLastId = 21851

	// Envelope.version (§6.4). Another major gets Error{VERSION}.
	WireVersionMajor = 1

	// The most one envelope takes on the wire, so frames stay in the 4 KiB pool class and carriers in
	// the 8 KiB one (§6.5, D-PROTO-2).
	MaxEnvelopeByteCount = 4080
	// The most one envelope's body holds, and where a longer body is cut (§6.5).
	MaxEnvelopeBodyByteCount = 4016
	// The most a final chunk's body holds, which leaves room for the whole body's hash (§6.5).
	MaxFinalChunkBodyByteCount = 3980
	// The most one StreamData carries (§6.5).
	MaxStreamDataByteCount = 4000

	// The longest a call runs, before the 60 s sequence exit (§6.6).
	MaxCallTimeout = 55 * time.Second
	// The longest body any peer reassembles, past which a body uses HTTPS (§6.5, §6.6).
	MaxReassemblyBodyByteCount = 1024 * 1024
)

// Envelope.flags (§6.5).
const (
	// Answers a request, echoing its request_id.
	EnvelopeFlagResponse uint32 = 1
	// A failure, with type ERROR and an Error body.
	EnvelopeFlagError uint32 = 2
	// Every chunk but the final (plan-PROTO-small-readings.md's reading 4).
	EnvelopeFlagMore uint32 = 4
	// Expects no answer: Cancel and stream frames (reading 4).
	EnvelopeFlagNoReply uint32 = 8
)
