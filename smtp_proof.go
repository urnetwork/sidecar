package sidecar

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
)

// The seam to the nested module smtpproof (§14.9). The root never requires that module (D-REPO-2):
// cli/ injects a prover on desktop builds and server injects a verifier into smtpedge, each through
// these interfaces. A host with no prover queues its mail for one that has (D-SMTP-18).

// A client record a part refused: unequal ciphertext, or a body past octet n (§14.7). It counts
// toward §14.8's halt, unlike any other way a connection can end.
var ErrSmtpRecordCut = errors.New("smtp record cut")

// A decoded SmtpProof (§14.5).
type SmtpProofPart struct {
	SendId []byte
	// 1 pi1, 2 pi2, 3 pi3, 4 and on later DATA parts.
	Index uint32
	// 1 BDAT, 2 DATA, fixed from pi2 on.
	Mode uint32
	// Client application records covered, by TLS sequence number.
	FirstRecord uint64
	LastRecord  uint64
	Proof       []byte
	// Covers octet n, the end mark in DATA mode, and QUIT.
	Last bool
	// Server records after Finished that this and earlier parts cover.
	ServerRecordCount uint64
	// Ciphertext of each client record the part opens, whole as framed, in sequence order.
	Records [][]byte
}

// What the proofs of one connection are checked against: the declared preamble, the values the edge
// issued, and the two the edge derives itself (§14.5, SPEC.md section 5).
type SmtpProofPreamble struct {
	RecipientDomain  string
	RecipientCount   uint32
	MessageId        string
	HeaderFromDomain string
	DkimSelector     string
	MessageByteCount uint64
	Flags            uint32
	HeloName         string
	XUrRef           string
	FeedbackId       string
	// Never from the sidecar: the edge derives it from the ticket's network.
	EnvelopeDomain string
	// The MX the edge resolved and dialed, which E1 requires the ClientHello's SNI to name.
	MxHost string
}

// Checks one connection's proofs, on the edge. It sees only records and proofs, and neither keeps
// nor logs them past the connection (D-SMTP-10).
type SmtpProofVerifier interface {
	NewSmtpProofSession(preamble *SmtpProofPreamble) (SmtpProofSession, error)
}

// The record gate of one connection (E1-E3). Methods may run concurrently, one goroutine per
// direction. Each that returns records returns those now cleared for the MX, in order, and the gate's
// order is the MX's: a caller writes them before the next such call returns, so ClientRecord,
// DiscloseShts and VerifyPart share one lock or one goroutine around the write. An error ends the
// connection, and is ErrSmtpRecordCut only for §14.7's cuts. The session ends with it: every later
// call is refused, and nothing is returned for the MX after a refusal.
type SmtpProofSession interface {
	// A whole record from the sidecar. It may be held for a part that has yet to verify.
	ClientRecord(record []byte) ([][]byte, error)
	// A whole record from the MX, before it is relayed to the sidecar.
	ServerRecord(record []byte) error
	// The MX closed, which makes any outstanding part moot.
	ServerClosed()
	// TLS 1.3's disclosed SHTS (E2). It is used and forgotten here.
	DiscloseShts(shts []byte) ([][]byte, error)
	// Checks a part. A record the part clears may be returned here.
	VerifyPart(ctx context.Context, part *SmtpProofPart) ([][]byte, error)
	// Whether the MAIL record has been returned for the MX, which is when §14.7 charges the
	// connection a unit. The engine cannot read records, so the gate says. It never turns false.
	MailForwarded() bool
}

// One connection's worth of mail for a prover to send, in the form SPEC.md section 4 fixes.
type SmtpProofJob struct {
	// What SmtpPreambleResult issued, which every part repeats.
	SendId   []byte
	Preamble *SmtpProofPreamble
	// The local part of the envelope sender.
	SenderLocal string
	// The local part of each recipient, all at Preamble.RecipientDomain.
	RecipientLocals []string
	// Header block through its final CRLF CRLF, then body, unstuffed. Preamble.MessageByteCount is
	// its length, or in DATA mode its dot-stuffed length; the prover stuffs it where the mode needs it.
	Message []byte
	// Decides TL1-TL3 over the chain the MX sent, leaf first (§14.4). Nil fails the send.
	VerifyPeer func(chain []*x509.Certificate) error
}

// How a send ended at the MX (§14.5's outcomes that a prover can see).
type SmtpProofResult struct {
	// 1 BDAT, 2 DATA, 0 if the send ended before the mode was known.
	Mode uint32
	// The MX took the message.
	Accepted bool
	// The reply that ended the send when it did not take the message, such as "550".
	RefusedCode string
	// DATA mode and over the prover's smtp_data_proof_bytes, decided before MAIL (§14.5).
	TooLarge bool
	// Set when the mode the MX's EHLO reply selects cannot meet the declared count, BDAT's being the
	// message's length and DATA's its dot-stuffed length. Nothing was sent past EHLO, and one new
	// connection declares this count, after which a second mismatch is deferred
	// (plan-SMTP-preamble-byte-count).
	ReconnectByteCount uint64
}

// Where a prover sends what the edge must see beside the stream.
type SmtpProofChannel interface {
	DiscloseShts(ctx context.Context, shts []byte) error
	SubmitPart(ctx context.Context, part *SmtpProofPart) error
}

// Runs one connection over the stream the edge spliced to the MX: the TLS handshake, every proof and
// every record. It holds all keys and plaintext, so only the sending device runs it. An error can quote
// the message or the MX's replies, so it stays on the device and no SmtpOutcome carries its text.
type SmtpProver interface {
	SendSmtp(ctx context.Context, conn net.Conn, job *SmtpProofJob, channel SmtpProofChannel) (*SmtpProofResult, error)
}
