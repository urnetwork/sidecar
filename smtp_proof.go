package sidecar

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// The seam to the nested module smtpproof (§14.9). The root never requires that module (D-REPO-2):
// cli/ injects a prover on desktop builds and server injects a verifier into smtpedge, each through
// these interfaces. A host with no prover queues its mail for one that has (D-SMTP-18).

// A client record a part refused: unequal ciphertext, or a body past octet n (§14.7). It counts
// toward §14.8's halt, unlike any other way a connection can end.
var ErrSmtpRecordCut = errors.New("smtp record cut")

// The edge holds no key set of the id a preamble names, so it opens no session: SmtpPreambleResult's
// KEYS, with no MX dialed and nothing debited (DESIGN-DETAILS 3.2.5). A prover answers it too for a job
// naming a key set it cannot prove under.
var ErrSmtpProofKeySet = errors.New("smtp proof key set not accepted")

// A decoded SmtpProof (§14.5; DESIGN-DETAILS 3.2.5).
type SmtpProofPart struct {
	SendId []byte
	// The part's ordinal, from 1. Part 1 is the key part.
	Index uint32
	// 0 in part 1; 1 BDAT or 2 DATA from part 2 on, which fixes it.
	Mode uint32
	// Client application records covered, by TLS sequence number. A part that opens none has
	// LastRecord = FirstRecord - 1.
	FirstRecord uint64
	LastRecord  uint64
	// 164 octets.
	Proof []byte
	// Covers octet n, the end mark in DATA mode, and QUIT.
	Last bool
	// Server records after Finished that this and earlier parts cover.
	ServerRecordCount uint64
	// Ciphertext of each client record the part opens, whole as framed, in sequence order.
	Records [][]byte
	// Part 1 only: C, the commitment to both directions' keys and IVs, 64 octets (DESIGN-DETAILS 3.2.2).
	// A uniformly random group element whatever the keys are.
	KeyCommitment []byte
	// The replies the server records this part covers hold (Z8).
	ReplyCount uint32
	// On the part that opens the header block's first record, and no other: how many client records
	// hold the header block. 0 elsewhere.
	HeaderRecordCount uint32
	// On a part that opens a header or body record: the commitment to the scan state after it, 64
	// octets, which the next such part opens. Empty elsewhere.
	Carry []byte
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
	// The key set every part of the connection is proven under: keyset.json's SHA-256, as the preamble
	// named it. A verifier that holds no such set answers ErrSmtpProofKeySet (DESIGN-DETAILS 3.2.7).
	ProofKeySet []byte
}

// Checks one connection's proofs, on the edge. It sees only records and proofs, and neither keeps
// nor logs them past the connection (D-SMTP-10).
type SmtpProofVerifier interface {
	// Whether the verifier holds the key set a preamble names, which the edge asks before it dials, so
	// that KEYS dials no MX and debits nothing (DESIGN-DETAILS 3.2.5). A session needs the MX the dial
	// chose, so it cannot be the first question.
	HoldsKeySet(keySet []byte) bool
	// A session for one connection, under the key set its preamble names: ErrSmtpProofKeySet for a set
	// the verifier does not hold, whatever HoldsKeySet said before.
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
	// The key set the preamble named, which every part is proven under: SmtpProver.KeySet()'s answer, or an
	// older ready set after the edge answered KEYS (DESIGN-DETAILS 3.2.7). A prover refuses a set it cannot
	// prove under with ErrSmtpProofKeySet, before any octet goes to the MX.
	KeySet []byte
	// The most commands one envelope group holds, past what fits the env shape: 0 for what fits, and
	// SmtpSenderSettings.EnvelopeRetryGroupCount on the one retry after EnvelopeRetry (DESIGN-DETAILS 3.2.4).
	EnvelopeGroupMaxCount int
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
	// The MX's replies to one envelope group came as a server record that no part's shape holds, so the
	// connection ended before any message record (DESIGN-DETAILS 3.2.4, 3.5). MAIL went, so a unit was
	// spent. The sender retries once with EnvelopeGroupMaxCount at its retry count, and a second is failed.
	EnvelopeRetry bool
}

// Where a prover sends what the edge must see beside the stream.
type SmtpProofChannel interface {
	DiscloseShts(ctx context.Context, shts []byte) error
	SubmitPart(ctx context.Context, part *SmtpProofPart) error
}

// A prover host's own speed (D-SMTP-20), which it records at p/<sidecar_id> (§15.7) so that a phone's
// composer can show the cap of the hosts that send for it and price a send in units (DESIGN-DETAILS 3.2.6,
// 3.7's SMTP-M9-08 and SMTP-M9-09).
type SmtpProverMeasure struct {
	// smtp_data_proof_bytes: the octets a DATA connection proves in its 2 h. A larger message to an MX
	// without CHUNKING is too_large. 0 when a part cannot prove within 2 minutes.
	DataProofBytes uint64
	// DATA octets proven per second.
	DataBytesPerSecond uint64
	MeasureTime        time.Time
	// What one unit, one part of one 2^20 domain, takes to prove on this host, for the ready family whose
	// unit takes longest.
	UnitTime time.Duration
	// Header octets the first message part opens, for that family: 3.2.6's head, 831 under AES-128-GCM.
	HeadByteCount uint64
	// Header octets each later header part opens, for that family: 3.2.6's rest, 1,199 under AES-128-GCM.
	HeaderRecordByteCount uint64
	// Commands one envelope group holds after the first, for that family: 13 under AES-128-GCM, the first
	// holding MAIL and one fewer RCPT.
	EnvelopeGroupCount uint64
}

// One key set a prover host can prove under, and which of its families are ready (DESIGN-DETAILS 3.2.7).
type SmtpProverKeySet struct {
	// keyset.json's SHA-256, as SmtpPreamble.proof_key_set names it.
	Id []byte
	// The TLS cipher suites whose family has every shape ready in this set, in the order the client offers
	// them. Only these are offered on a connection under this set.
	ReadySuites []uint16
}

// What a prover host holds keys for after PrepareKeys (DESIGN-DETAILS 3.2.7).
type SmtpProverReadiness struct {
	// The pinned key sets with a ready family, newest first. The first is what KeySet returns; on KEYS a
	// sender tries the next, once (DESIGN-DETAILS 3.7's SMTP-M9-08).
	KeySets []*SmtpProverKeySet
	// Every family of every pinned set is ready or refused, so nothing is left to check at idle until the
	// release or its pins change.
	Done bool
}

// Runs one connection over the stream the edge spliced to the MX: the TLS handshake, every proof and
// every record. It holds all keys and plaintext, so only the sending device runs it. An error can quote
// the message or the MX's replies, so it stays on the device and no SmtpOutcome carries its text.
type SmtpProver interface {
	SendSmtp(ctx context.Context, conn net.Conn, job *SmtpProofJob, channel SmtpProofChannel) (*SmtpProofResult, error)
	// Proves at idle what a part costs this host, and holds later sends to it. It takes seconds to
	// minutes, and fails where no keys are loaded.
	Measure(ctx context.Context) (*SmtpProverMeasure, error)
	// The id of the key set this host would prove under now: the newest pinned set with a ready family.
	// Empty when no family is ready, and then the host only queues (D-SMTP-18).
	KeySet() []byte
	// Advances the host's check of its pinned key sets by one shape at most, and reports what is ready. A
	// host calls it at idle, only once mail is enabled on it, since the check fetches transcripts (§2.8
	// smtp-7), and cancels it when a send starts (DESIGN-DETAILS 3.7's SMTP-M9-09).
	PrepareKeys(ctx context.Context) (*SmtpProverReadiness, error)
}
