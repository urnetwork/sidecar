//go:build !sidecar_http

// §9's JSON routes, which server/cli/sockets serves at /socket/* and connect/api/bringyour.yml documents
// (§9.15). They name connect.Id, so they stay off the sidecar_http leg with the listeners and dialers
// that use them: a page Worker does neither (§18). socket_ticket.go holds what rides inside them.
//
// Every value here is one §2.8's sock rows show the service, and one no row names stays off the wire
// (I-18). A refusal travels in the body, as Error, and says only what stopped the call, so it never
// tells a caller what a name holds (D-SOCK-15). Bytes are base64, as encoding/json writes them, and
// each ticket or claim among them passes through unchanged, because what verifies is the bytes received.

package sidecar

import (
	"github.com/urnetwork/connect"
)

// What one call or page carries at most, whatever the set's size (§9.5, D-SOCK-3).
const SocketRegistrationPageMaxEntryCount = 1024

// POST /socket/registrations (JSON, connect/api/bringyour.yml): the client's full set, so listen,
// heartbeat, drain and unlisten are one idempotent call; a set over 1,024 entries goes as pages (§9.5).
type SocketRegistrationsArgs struct {
	// Per client, increasing. A set's pages share it, and older sets are refused.
	SetVersion uint64 `json:"set_version"`
	// This page is the whole set within name keys [key_start, key_end).
	KeyStart []byte `json:"key_start"`
	// Empty: unbounded.
	KeyEnd []byte `json:"key_end"`
	// At most SocketRegistrationPageMaxEntryCount, sorted by name key: name, or name_token for blinded
	// names.
	Registrations []*SocketRegistration `json:"registrations"`
}

// A lease on (network_id, name, listener_client_id), at most one per client and name (§9.5). Exactly
// one of Name and NameToken names it. The defaults are what a client fills in, since a JSON zero cannot
// be told from a value left out.
type SocketRegistration struct {
	// tls/, smtp/ and ur/ names only (§9.4).
	Name string `json:"name"`
	// Other names: the token path, 16 B a segment.
	NameToken []byte `json:"name_token"`
	// With name_token: §9.4's 152 B seal.
	SealedName []byte `json:"sealed_name"`
	// Random per Listen. Older tickets are refused.
	ListenId *connect.Id `json:"listen_id"`
	// Default "tcp". One protocol per group.
	Protocol string `json:"protocol"`
	Version  int    `json:"version"`
	// tls/: the ALPN ids served.
	Alpn []string `json:"alpn"`
	// tls/: "http" (default; h2, http/1.1 or no ALPN reach §13.7's HTTP front, D-TLS-13) or "raw".
	// Other names: "".
	AppMode string `json:"app_mode"`
	// Default 100, 1-1000: a relative share.
	Weight int `json:"weight"`
	// Default 256: the hard cap at the listener.
	MaxStreams int `json:"max_streams"`
	// Refuses later registrations.
	Exclusive bool `json:"exclusive"`
	// Honors affinity keys (§9.7).
	Affinity bool `json:"affinity"`
	// Default true. False keeps the lease and takes no tickets.
	Serving bool `json:"serving"`
	// No new tickets. Issued ones are accepted.
	Draining bool `json:"draining"`
	// The load report.
	Inflight int `json:"inflight"`
	// A marshaled bridge.Signed by the identity key, purpose socket-registration, over a
	// protocol.SocketRegistrationClaim. Find returns it with tickets for the dialer's check (§9.6).
	Claim []byte `json:"claim"`
}

// How one entry of a page stands. Anything but ok holds no lease, an unknown value included.
type SocketRegistrationStatus string

const (
	// The lease holds.
	SocketRegistrationStatusOk SocketRegistrationStatus = "ok"
	// It passed before and no longer does: the entry closes with its streams (§9.5).
	SocketRegistrationStatusRevoked SocketRegistrationStatus = "revoked"
	// The gate or the namespace refuses it.
	SocketRegistrationStatusDenied SocketRegistrationStatus = "denied"
	// An exclusive listener or another protocol holds the group.
	SocketRegistrationStatusTaken SocketRegistrationStatus = "taken"
	// The entry itself is malformed.
	SocketRegistrationStatusInvalid SocketRegistrationStatus = "invalid"
)

// Why a whole call was refused: §9.9's codes in §9.6's step order, then a page's own two.
type SocketErrorCode string

const (
	// Find's pick found nothing live and matching.
	SocketErrorCodeNoListener SocketErrorCode = "no_listener"
	// Find's pick found only listeners at max_streams.
	SocketErrorCodeBusy SocketErrorCode = "busy"
	// The projection does not allow the dial.
	SocketErrorCodeDenied SocketErrorCode = "denied"
	// The paying network is spent.
	SocketErrorCodeQuota SocketErrorCode = "quota"
	// The control-plane bound, or a network whose projection is not loaded (§9.10).
	SocketErrorCodeUnavailable SocketErrorCode = "unavailable"
	// A page's set_version is older than the stored one, which the result carries.
	SocketErrorCodeStale SocketErrorCode = "stale"
	// A page is over its size, out of order, or holds an entry outside its range (§9.5).
	SocketErrorCodeInvalid SocketErrorCode = "invalid"
)

// One refusal of a whole call. Nothing was signed or written, and the caller keeps what it held.
type SocketError struct {
	Code SocketErrorCode `json:"code"`
	// How long to wait, in milliseconds, for no_listener, busy, quota and unavailable (§9.9). 0: none
	// given.
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
}

// POST /socket/registrations's answer (§9.5, §9.15). The service re-checks each entry on each call, so
// this is authoritative for the page, and a hint only asks for the next call.
type SocketRegistrationsResult struct {
	// One per entry, in the page's order. Empty when Error refused the page.
	Statuses []SocketRegistrationStatus `json:"statuses"`
	// The stored version, so a refused client can jump past it and a restart is not held back.
	SetVersion uint64 `json:"set_version"`
	// The service's clock in milliseconds, whose offset from the client's a listener applies to tickets
	// (§9.6's step 4).
	ServerTimeMillis uint64 `json:"server_time"`
	// Every key a ticket may verify under, which is admission step 1's list.
	TicketKeys []*SocketTicketKey `json:"ticket_keys"`
	// The urnetwork-edge network's id, which admission steps 3 and 6 compare a ticket's to.
	UrnetworkEdge *connect.Id `json:"urnetwork_edge"`
	// §20 has stopped new streams, so a listener answers quota (§9.6's step 5).
	StreamsStopped bool `json:"streams_stopped"`
	// The page as a whole was refused.
	Error *SocketError `json:"error,omitempty"`
}

// Why a dialer gave up on a ticket, for §9.10's failure_reports_total, as a dialer's own word. §2.8's
// sock-2 shows the failed tickets a retry reports and which were accept timeouts, and nothing finer, so a
// listener's code stays with the dialer until that row names it (I-18). An edge sends only timeout
// (§9.6).
type SocketFailedReason string

const (
	// No accept within the dial's accept timeout.
	SocketFailedReasonTimeout SocketFailedReason = "timeout"
	// Refused before an accept: the listener answered retry, busy, invalid or a code taken as invalid, or
	// the ticket's claim failed the dialer's own check, so it never opened (§9.6).
	SocketFailedReasonRefused SocketFailedReason = "refused"
)

// A ticket that failed its holder. The service verifies it and that the caller is its dialer, so only a
// holder reports (§9.6).
type SocketFailedTicket struct {
	// As its SocketFindTicket carried it.
	Ticket []byte             `json:"ticket"`
	Reason SocketFailedReason `json:"reason"`
}

// POST /socket/find (§9.6). Exactly one of Name and NameToken names the group, as in a registration.
//
// Protocol, MinVersion and Alpn are §9.7's filter, and §2.8's sock-2 does not list them, so they stay off
// the wire until it does (I-18, question plan-SOCK-metadata-rows). A dialer still fills them from its
// settings, and Find answers for every protocol, version and ALPN meanwhile, so a mismatch is the
// dialer's to catch: a claim carries the listener's protocol.
type SocketFindArgs struct {
	// tls/, smtp/ and ur/ names only (§9.4).
	Name string `json:"name,omitempty"`
	// Other names: the token path.
	NameToken []byte `json:"name_token,omitempty"`
	// The network the name is in, resolved per call (D-SOCK-1). ur/ names: urnetwork-edge.
	NetworkId  *connect.Id `json:"network_id"`
	Protocol   string      `json:"-"`
	MinVersion int         `json:"-"`
	Alpn       []string    `json:"-"`
	// tlsedge's keyed hash of the visitor's /24 or /48, which only a Find's own request holds (§9.7).
	AffinityKey []byte `json:"affinity_key,omitempty"`
	// Tickets this dialer's last Find returned that failed it.
	FailedTickets []*SocketFailedTicket `json:"failed_tickets,omitempty"`
	// urnetwork-edge callers only: the process's K clients, one of which each ticket names (§9.6).
	ClientIds []*connect.Id `json:"client_ids,omitempty"`
}

// One listener's ticket and what its dialer checks before OPEN (§9.6).
type SocketFindTicket struct {
	// A marshaled protocol.SignedSocketTicket, which goes into StreamOpen.ticket as it came.
	Ticket []byte `json:"ticket"`
	// The listener's SocketRegistration.Claim.
	Claim []byte `json:"claim"`
}

// POST /socket/find's answer: tickets or one refusal, and a refusal signs nothing (D-SOCK-15).
type SocketFindResult struct {
	Primary *SocketFindTicket `json:"primary,omitempty"`
	// Absent when one listener is all a group has.
	Backup *SocketFindTicket `json:"backup,omitempty"`
	Error  *SocketError      `json:"error,omitempty"`
}

// One name of a network's listing. Exactly one of Name and NameToken names it (§2.8's sock-4).
type SocketListName struct {
	// tls/, smtp/ and ur/ names only.
	Name string `json:"name,omitempty"`
	// Other names: the token path.
	NameToken []byte `json:"name_token,omitempty"`
	// With name_token: what a lister opens with OpenSocketName, dropping what does not open.
	SealedName []byte `json:"sealed_name,omitempty"`
}

// GET /socket/list's answer, for the caller's own network (§9.15). Each page charges the control bound,
// which is why a listing has pages and a refusal.
type SocketListResult struct {
	Names []*SocketListName `json:"names"`
	// What the next page's cursor query takes. Empty: this page is the last.
	NextCursor string `json:"next_cursor"`
	// The page as a whole was refused.
	Error *SocketError `json:"error,omitempty"`
}

// GET /socket/keys's answer: the keys tickets verify under, for anyone (§9.8).
type SocketKeysResult struct {
	Keys []*SocketTicketKey `json:"keys"`
}
