// The rows SmtpEdgeStore reads and writes (§14.14), each holding only the fields its §2.8 row lists:
// smtp-3 for a send, smtp-4 for a halt, smtp-5 for complaints and aggregates, smtp-6 for DKIM keys. A
// field outside those rows needs a §2.8 row first (I-18), and TestSmtpRecordsHoldNoThirdPartyAddress
// holds the names here to that list.
//
// What never has a field: a recipient, a third-party IP (a reporter's, the last-hop Received IP, a
// report's other source IPs), an MX's IP, a subject, a body, report plaintext, session ciphertext,
// record lengths and the SHTS a sidecar discloses (D-SMTP-10). Strings in a closed set are words from
// the constants here, never text from a report.

package smtpedgeservice

import (
	"crypto/sha256"
	"net/netip"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The TLS levels a send records (§14.4).
const (
	SmtpTlsLevelDane          uint8 = 1
	SmtpTlsLevelMtaSts        uint8 = 2
	SmtpTlsLevelIndependentMx uint8 = 3
	SmtpTlsLevelNone          uint8 = 4
)

// A complaint's type: an ARF Feedback-Type from RFC 5965's registry, or one of the kinds this intake
// adds. An aggregate's sealed copy rides a row of type rua or tlsrpt, which counts as no complaint and
// feeds no halt (plan-SMTP-small-readings#14).
const (
	SmtpComplaintTypeAbuse   = "abuse"
	SmtpComplaintTypeFraud   = "fraud"
	SmtpComplaintTypeVirus   = "virus"
	SmtpComplaintTypeOther   = "other"
	SmtpComplaintTypeNotSpam = "not-spam"
	// RFC 6591's, which reports a failed authentication, not a complaint.
	SmtpComplaintTypeAuthFailure = "auth-failure"
	// Mail to abuse@ or postmaster@ on <root> that carries no feedback report (§21.8).
	SmtpComplaintTypeRole = "role"
	// An aggregate's home for its sealed copy.
	SmtpComplaintTypeRua    = "rua"
	SmtpComplaintTypeTlsRpt = "tlsrpt"
)

// An aggregate's kind (§14.8).
const (
	SmtpAggregateKindDmarc  = "dmarc"
	SmtpAggregateKindTlsRpt = "tlsrpt"
)

// A halt's trigger, one per §14.8 row. SMTP-M9-16 sets them.
const (
	SmtpHaltTriggerLabelComplaint     = "label_complaint"
	SmtpHaltTriggerCommunityComplaint = "community_complaint"
	SmtpHaltTriggerSecondLabel        = "second_label"
	SmtpHaltTriggerProRate            = "pro_rate"
	SmtpHaltTriggerTeamRate           = "team_rate"
	SmtpHaltTriggerFraud              = "fraud"
	SmtpHaltTriggerRecordCuts         = "record_cuts"
	SmtpHaltTriggerHardBounces        = "hard_bounces"
)

// One smtp_send row (§2.8 smtp-3), written after the connection ends. The store keys it by
// (SmtpSendDay(StartTime), SendId), smtp_send's primary key over its daily partitions.
type SmtpSendRecord struct {
	// The 12 random octets X-UR-Ref carries (plan-SMTP-small-readings#3).
	SendId    []byte
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	// The edge's own sending address, never a third party's.
	SendingAddress  netip.Addr
	RecipientDomain string
	// The MX's name, never its IP (D-SMTP-10).
	MxHost    string
	StartTime time.Time
	EndTime   time.Time
	// What the connection relayed, both ways.
	ByteCount uint64
	// SmtpMessageIdHash of the proven Message-ID.
	MessageIdHash []byte
	// The X-UR-Ref key's id, the first octet of the reference.
	XUrRefKeyId uint8
	// The proven counts (Z4).
	RecipientCount   uint32
	MessageByteCount uint64
	// The IANA value.
	TlsVersion uint16
	// SmtpTlsLevel*.
	TlsLevel uint8
	// A word from the edge's closed set of results.
	Result string
	// Empty unless the preamble retried an earlier send.
	RetryOfSendId []byte
}

// What FindSends matches, every field set having to match and an unset one matching anything. A key
// with none of SendId, MessageIdHash, NetworkId or SendingAddress set is refused, so no join scans the
// whole log. Since and Until bound StartTime, inclusive, when set.
type SmtpJoinKey struct {
	// From a verified X-UR-Ref.
	SendId []byte
	// SmtpMessageIdHash of a reported Message-ID.
	MessageIdHash []byte
	// The network whose selector signed the reported headers.
	NetworkId sidecar.Id
	// The last-hop Received IP, for the join only: it is never stored (§2.8 smtp-5).
	SendingAddress netip.Addr
	Since          time.Time
	Until          time.Time
}

// Whether the key names something to match beyond a time range.
func (self *SmtpJoinKey) selective() bool {
	return len(self.SendId) != 0 || len(self.MessageIdHash) != 0 || self.NetworkId != (sidecar.Id{}) || self.SendingAddress.IsValid()
}

// One smtp_complaint row (§2.8 smtp-5): an attributed report's fields and sealed copy.
type SmtpComplaint struct {
	ComplaintId sidecar.Id
	NetworkId   sidecar.Id
	// The verified DKIM d= of the operator that sent it. Empty for role mail, whose sender is a person
	// and is never kept.
	Reporter string
	// SmtpComplaintType*.
	Type        string
	ArrivalTime time.Time
	// The reported From domain: <net>.<root>, a burner's <blabel>.<net>.<root>, or a Team domain. For
	// an aggregate's row, the first reported header_from or policy domain.
	Domain string
	// The DKIM signature attribution rests on, with its result as a word.
	DkimDomain   string
	DkimSelector string
	DkimResult   string
	// SmtpMessageIdHash of the reported Message-ID.
	MessageIdHash []byte
	XUrRef        string
	FeedbackId    string
	// Attribution's confidence, from SMTP-M9-15's closed set.
	JoinResult string
	// The raw report under the network mail key (report_seal.go), cleared at 30 days. Empty when no
	// key was held, in which case the raw bytes were dropped unread.
	SealedReport []byte
}

// One report's counts, inserted once per (Reporter, ReportId) (§14.8, D-SMTP-23). A report at
// <root>'s own rua names several networks, so its counts carry their networks one by one.
type SmtpAggregateReport struct {
	// The verified DKIM d= of the reporter.
	Reporter string
	ReportId string
	// SmtpAggregateKind*.
	Kind string
	// The UTC day the report covers, at midnight.
	Day         time.Time
	ArrivalTime time.Time
	Counts      []*SmtpAggregateCount
}

// One smtp_dmarc_daily row's counts: what one report says of one header_from (a policy domain, for
// TLS-RPT), for URnetwork's sending addresses only.
type SmtpAggregateCount struct {
	NetworkId sidecar.Id
	// Burner labels included (§2.8 smtp-5).
	Domain string
	// DMARC: messages, by policy_evaluated's results.
	MessageCount    uint64
	DkimPassCount   uint64
	SpfPassCount    uint64
	QuarantineCount uint64
	RejectCount     uint64
	// TLS-RPT: sessions, under one policy type (sts, tlsa or no-policy-found).
	PolicyType   string
	SuccessCount uint64
	FailureCount uint64
}

// How long a halt holds from its start, the report's arrival: §14.8's fixed day (owner decision 37;
// PLAN.md:91), a rule rather than a tunable, which every store reads.
const SmtpHaltDuration = 24 * time.Hour

// One smtp_halt row (§2.8 smtp-4: network or burner label, trigger, start). It holds no end, which
// §2.8 does not list: a halt ends SmtpHaltDuration after its start. Lifting one early is SMTP-M9-16's,
// and needs that row to grow first (I-18).
type SmtpHalt struct {
	HaltId    sidecar.Id
	NetworkId sidecar.Id
	// A burner label, or empty for the whole network.
	Label string
	// SmtpHaltTrigger*.
	Trigger string
	// The report's arrival.
	StartTime time.Time
}

// Whether the halt still holds at now.
func (self *SmtpHalt) ActiveAt(now time.Time) bool {
	return now.Before(self.StartTime.Add(SmtpHaltDuration))
}

// One smtp_dkim_key row (§2.8 smtp-6): a sending sidecar's public key under its opaque selector.
type SmtpDkimKey struct {
	// 26 lowercase base32 characters (plan-SMTP-small-readings#5).
	Selector string
	// The d= it signs under.
	Domain    string
	NetworkId sidecar.Id
	SidecarId sidecar.Id
	// rsa-sha256 or ed25519-sha256.
	Algorithm string
	// DER SubjectPublicKeyInfo for RSA, the 32 raw octets for Ed25519.
	PublicKey []byte
	// When the selector was rotated out, from which its row's 30 days run (§14.14). Zero while
	// current. A retired key still checks reports.
	RetireTime time.Time
}

// The UTC day t falls on, counted from the Unix epoch: smtp_send's partition key.
func SmtpSendDay(t time.Time) int64 {
	return t.UTC().Unix() / (24 * 60 * 60)
}

// The UTC midnight starting t's day.
func smtpUtcDay(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// The hash a send record and a complaint both key a Message-ID by: SHA-256 of the id between its angle
// brackets, so the sender's and a report's copies agree whatever whitespace surrounds them.
func SmtpMessageIdHash(messageId string) []byte {
	id := strings.TrimSpace(messageId)
	id = strings.TrimPrefix(id, "<")
	id = strings.TrimSuffix(id, ">")
	if id == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(id))
	return hash[:]
}
