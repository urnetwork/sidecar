// What tlsedge reads and writes outside itself, behind interfaces so the engine imports no server
// package (§4.5): TlsEdgeStore, the label map and network_tls_suspension in Postgres and the connection
// records, and TlsEdgeDialer, Find and the stream to a listener.
//
// The store is server's model.NewTlsEdgeStore (TLS-M5-11) on DNS-M5-10's label map, as
// plan-TLS-edge-data-source settles it: tlsedge reads Postgres through a restricted role, a full
// snapshot at start and then the changes every 5 s, so no connection path waits on it (I-12). Until a
// host supplies one, sidecartest.FakeTlsEdgeStore stands in and the engine is not ready.
// sidecartest.RunTlsEdgeStoreSuite holds both to the rules here.
//
// The dialer is SOCK-M5-13's SocketEdgeDialer once it lands, in this shape so the connection path
// (TLS-M5-10) is tested on a scripted fake before then.
//
// Every interface here is safe for concurrent use, and none is called with a state lock held.

package tlsedgeservice

import (
	"context"
	"io"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// dns_label.kind (§12.5).
type TlsEdgeNameKind string

const (
	// A network's 10-character label.
	TlsEdgeNameKindLabel TlsEdgeNameKind = "label"
	// A network's alias (§12.5, M6).
	TlsEdgeNameKindAlias TlsEdgeNameKind = "alias"
)

// dns_label.state (D-DNS-10). Only a live name routes.
type TlsEdgeNameState string

const (
	TlsEdgeNameStateLive       TlsEdgeNameState = "live"
	TlsEdgeNameStateRetiring   TlsEdgeNameState = "retiring"
	TlsEdgeNameStateTombstoned TlsEdgeNameState = "tombstoned"
)

// One name of §12's label map as tlsedge routes by it, with its network's §12.9 suspensions as they
// stood when the map was read (DNS-M5-14: each change to them moves the network's names' change
// serial, so a change arrives with every name it touches).
type TlsEdgeNameEntry struct {
	// The label or alias: one lowercase LDH label, the <x> of <host>.<x>.<root>.
	Name string
	// Zero for a restore's ownerless name, which routes nothing (§12.5).
	NetworkId sidecar.Id
	Kind      TlsEdgeNameKind
	State     TlsEdgeNameState
	// §12.9's zone suspension: while it holds, none of the network's names routes. ZoneSuspendUntil is
	// zero when only a lift ends it.
	ZoneSuspended    bool
	ZoneSuspendUntil time.Time
	// §12.9's suspended hosts, relative to the network's zones as SuspendHost takes them, such as shop or
	// a.shop: a host here, or below one here, routes nothing. A zone suspension's apex markers are
	// ZoneSuspended, not entries here.
	WithheldHosts []string
}

// The label map at one moment, or its changes since a serial.
type TlsEdgeNameMap struct {
	// The highest change serial read: the next NamesSince's after. A read that found nothing new answers
	// its own after.
	Serial uint64
	// The root's last restore serial (§12.6). A reader that sees it move takes a new snapshot, since a
	// Postgres restore can leave its cursor above every serial the restored rows hold.
	RestoreSerial uint64
	// A snapshot's every name, or the names whose entry changed, in change serial order, each as it
	// stands now. A name that no longer routes comes back in its new state rather than going missing.
	Entries []*TlsEdgeNameEntry
}

// One row of tls_connection_record (§2.8 tls-3; TLS-M5-12's model.TlsConnectionRecord): a visitor's
// connection to a published host. No address: the visitor is a keyed hash of its /24 or /48 (I-13).
type TlsConnectionRecord struct {
	// 16 random bytes, the connection_id of TlsEdgeOpen, which joins abuse reports for 24 h.
	ConnectionId sidecar.Id
	NetworkId    sidecar.Id
	// The published host within the network: @ or a label.
	Host      string
	StartTime time.Time
	// When the connection ended, which places the record in its hour.
	EndTime time.Time
	// Bytes passed, both ways.
	ByteCount int64
	// The visitor's /24 or /48 under the day's key, 16 bytes (TlsVisitorKeys).
	VisitorHash []byte
}

// What tlsedge keeps in Postgres. Called only from the engine's own loops and record batches, off
// every connection's path (I-12). Safe for concurrent use.
type TlsEdgeStore interface {
	// The whole label map of root: every name with its network's suspensions, and the serial to follow
	// from.
	NameSnapshot(ctx context.Context, root string) (*TlsEdgeNameMap, error)
	// The names of root whose entry changed above after, in change serial order, each as it stands now.
	NamesSince(ctx context.Context, root string, after uint64) (*TlsEdgeNameMap, error)
	// Every row of network_tls_suspension, as §13.9's kill switch writes them. A row whose until has
	// passed may still be here until the sweep deletes it, and the kill set reads it as lifted.
	Suspensions(ctx context.Context) ([]*sidecar.TlsSuspendArgs, error)
	// One batch of tls_connection_record rows, in 10 s batches off the path (§13.9).
	InsertConnectionRecords(ctx context.Context, records []*TlsConnectionRecord) error
}

// One end of a stream to a listener, as SocketConn is (§9.9): Close sends StreamClose and stops
// reading, CloseWrite sends StreamClose alone, and Reset sends StreamReset with its code, so a spent
// lease resets with RST_QUOTA (§13.6). A Read or Write after a reset fails. Safe for concurrent use, as
// a net.Conn is.
type TlsEdgeStream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
	Reset(code protocol.StreamResetCode) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// One connection's Find and open, §13.5's steps 4 and 5.
type TlsEdgeDialRequest struct {
	// What the visitor's name mapped to.
	Target *TlsEdgeTarget
	// The ids the visitor offered, in hello order, trimmed as TlsEdgeOpen's (reading 6). Find matches a
	// listener's ALPN against them.
	AlpnIds []string
	// §9.7's affinity key, a keyed hash of the visitor's /24 or /48. Empty until the fleet's daily key
	// lands (plan-TLS-visitor-hash-key), and affinity waits for M6 (TLS-M6-02).
	AffinityKey []byte
	// StreamOpen.metadata for a ticket whose grant ends at grantExpireTimeMillis: TlsEdgeOpen, whose
	// expire_time_millis is that time (§13.5). Called once for each ticket the dialer tries.
	Metadata func(grantExpireTimeMillis uint64) ([]byte, error)
	// The hello's bytes as ReadClientHello read them. The dialer sends the first 2,048 in early_data and
	// the rest at once in StreamData, within the initial window and before the accept (§13.5's step 5).
	HelloBytes []byte
}

// Find (§9.6) as autogroup:public with protocol tls, and the open from the client its ticket names
// (§13.5; SOCK-M5-13's shape). A refusal is a sidecar.SocketCodeError around one of the ErrSocket
// values, which errors.Is reaches: denied answers the visitor as an unknown name does, and no listener,
// busy, quota and unavailable as internal_error. Only an accept timeout blames a listener (§9.6). Safe
// for concurrent use.
type TlsEdgeDialer interface {
	// The K client ids this process holds in urnetwork-edge, which every Find sends. Fewer than
	// TlsEdgeSettings.Clients leaves the engine not ready.
	ClientIds() []sidecar.Id
	// Finds a listener for the request's target and opens a stream to it, trying each ticket in turn.
	Dial(ctx context.Context, request *TlsEdgeDialRequest) (TlsEdgeStream, error)
}
