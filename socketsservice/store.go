// SocketStore: everything the engine keeps, which is soft state in Redis Cluster and nothing else (§9.8,
// D-SOCK-7). server's model.NewSocketStore implements it on §9.8's keys, and sidecartest.FakeSocketStore
// stands in for it, both held to one answer by sidecartest.RunSocketStoreSuite (D-TEST-2). The engine
// imports no go-redis (§4.5), so what a key holds is the store's to encode.
//
// A group is one name of one network, (network_id, name key), and holds that name's listeners, each a
// lease that a page renews. Its keys share one hash tag, so a Find is one script on one slot, and a page
// crosses slots only between groups, the client's set and the network's listing.
//
// Time is the store's own clock, injected, and randomness arrives on Pick's request, so a fake and a Lua
// script given the same clock and draws agree pick for pick. A store keeps a listener's lease by that
// clock: at or past LeaseExpireMillis it takes no tickets and lists nowhere, whatever a backing ttl says.
//
// What every implementation keeps:
//
//   - A page is idempotent. Applying one twice leaves what applying it once did, so a retry, or the next
//     heartbeat after a partial failure, heals it. A store that fails midway leaves leases to expire
//     rather than a set entry naming a lease it never wrote.
//   - A page is the client's whole set within [key_start, key_end): every entry the client held there
//     that the page does not hold is unlistened, and nothing outside the range is touched (D-SOCK-3).
//   - One protocol per group, and an exclusive listener refuses every later registration (§9.5).
//   - Pick changes only the dialer's share of its primary, the reports' exclusions and ejections, and
//     what it trims, so a refused or empty Find writes nothing else.
//   - Nothing here caps names, listeners or streams (owner decision 66).
//
// An error means the store did not answer, so the caller does not know what a write did: the engine
// answers unavailable, and the next call heals it. Safe for concurrent use.

package socketsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// A request a store refuses whole as malformed: a page out of order, an entry outside its range, or a
// name key that is empty. The engine checks pages before they get here, so this is a caller's bug.
var ErrSocketStoreRequest = errors.New("socket store request malformed")

// One registration page as the engine passed it: the entries it allows, every check done and every
// default applied (§9.5).
type SocketStorePage struct {
	// The listener's network, which holds every group of the page (D-SOCK-1). A ur/ listener's is
	// urnetwork-edge.
	NetworkId        connect.Id
	ListenerClientId connect.Id
	SetVersion       uint64
	// The page's range of name keys. An empty KeyEnd is unbounded.
	KeyStart []byte
	KeyEnd   []byte
	// Sorted by name key, each inside the range, at most one per name key. An entry the engine refused
	// is absent, so the store unlistens whatever lease it held.
	Registrations []*sidecar.SocketRegistration
}

// What became of one entry of a page.
type SocketStoreEntryOutcome struct {
	// An exclusive listener or another protocol holds the group, so the entry holds no lease, and a
	// lease it held before is gone.
	Taken bool
	// The group had no live listener before this one: §9.4's FirstListen fires on this.
	FirstListener bool
}

// A lease a call ended, as unlisten or removal left it.
type SocketStoreRemoved struct {
	NetworkId        connect.Id
	ListenerClientId connect.Id
	// The group's name key: an edge name's bytes, or a token path.
	NameKey []byte
	// The group has no live listener left: §9.4's LastUnlisten fires on this.
	LastListener bool
}

// What a page did.
type SocketStorePageResult struct {
	// The page's set_version is older than the stored one, which SetVersion holds, and nothing was
	// written.
	Stale bool
	// The client's stored set_version once the call is done.
	SetVersion uint64
	// One per entry of the page, in its order. Empty when Stale.
	Outcomes []*SocketStoreEntryOutcome
	// Leases inside the range that the client held before the call and holds no more, in name key
	// order: entries the page lacks, entries the engine refused, and entries now taken. The engine
	// answers revoked for a refused entry found here.
	Removed []*SocketStoreRemoved
}

// One listener as the store holds it: what it registered and what a pick reads.
type SocketStoreListener struct {
	// The registration as last written. Inflight is the last report.
	Registration *sidecar.SocketRegistration
	// §9.7's view of it at the store's now, defaults applied, with its dialers' shares.
	Candidate *SocketCandidate
}

// A ticket that failed its holder, verified by the engine to be the caller's (§9.6). An edge reports
// only accept timeouts, which the engine settles before a report gets here.
type SocketStoreReport struct {
	ListenerClientId connect.Id
	// The listen the ticket named. A report for an earlier listen of the same client is ignored.
	ListenId connect.Id
}

// One Find's call (§9.6's step 4).
type SocketStorePickRequest struct {
	NetworkId connect.Id
	NameKey   []byte
	// The Required session's source, which a ticket names (D-SOCK-12), and its network.
	DialerClientId  connect.Id
	DialerNetworkId connect.Id
	// §9.7's filter: "" and 0 ask nothing, and no ALPN ids match every listener.
	Protocol   string
	MinVersion int
	Alpns      []string
	// Two uniform draws for the weighted sample (§9.7's step 2).
	FirstDraw  uint32
	SecondDraw uint32
	// What a group above SampleCount listeners draws its sample with, where the store samples in
	// process. A Redis store samples with ZRANDMEMBER inside the script and ignores this.
	SampleSeed uint32
	// Failed tickets this dialer's last Find returned, applied before the pick so that a Find stays one
	// call (§9.6).
	Reports []*SocketStoreReport
}

// What a Find's call came to.
type SocketStorePickResult struct {
	Outcome SocketPickOutcome
	// Set when Outcome is SocketPickFound. Backup is nil in a group of one.
	Primary *SocketStoreListener
	Backup  *SocketStoreListener
	// How many of the reports excluded a listener for this dialer, and how many ejected one for all,
	// for §9.10's exclusions_total and ejections_total.
	ExclusionCount int
	EjectionCount  int
}

// A lease to end, by who holds it where.
type SocketStoreEntryRef struct {
	ListenerClientId connect.Id
	NameKey          []byte
}

// §9.8's store. See the file header for what every method keeps.
type SocketStore interface {
	// Whether the store answers: the engine's readiness probe.
	Ping(ctx context.Context) error
	// One registration page (§9.5).
	ApplyPage(ctx context.Context, page *SocketStorePage) (*SocketStorePageResult, error)
	// One group-key call (§9.6's step 4, §9.8): trim expired leases, apply the reports, filter or
	// sample, pick, and add the primary to this dialer's share.
	Pick(ctx context.Context, request *SocketStorePickRequest) (*SocketStorePickResult, error)
	// A group's live listeners, in listener client id order: the revocation sweep's read (§9.8).
	ListListeners(ctx context.Context, networkId connect.Id, nameKey []byte) ([]*SocketStoreListener, error)
	// One page of a network's listing, {sn_<network_id>}names (§2.8's sock-4), from cursor, "" first.
	// The next cursor comes back, "" once done. A name may come back on two pages, and a lister keeps
	// one. count bounds what one call examines, so a page may come back short or empty with a cursor.
	ListNames(ctx context.Context, networkId connect.Id, cursor string, count int) ([]*sidecar.SocketListName, string, error)
	// §6.10.1's pair: field dialerClientId of {svc_<listenerClientId>}, holding the grant's expiry in
	// milliseconds, 0 for none, for ttl, which the engine caps (§9.6). A second write replaces the
	// first and its ttl.
	SetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id, grantExpireMillis uint64, ttl time.Duration) error
	// The pair's grant expiry, and whether it is there: CreateContract's one read (§6.10.1).
	GetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id) (grantExpireMillis uint64, found bool, err error)
	// Every pair of a listener, on revocation or its last edge unlisten (§9.6).
	RemoveServicePairs(ctx context.Context, listenerClientId connect.Id) error
	// Everything a removed client holds, through its set: its leases, its set and its pairs, on
	// {X}c_removed (§9.8, D-SOCK-9). A client the store holds nothing for is no error.
	RemoveClient(ctx context.Context, clientId connect.Id) ([]*SocketStoreRemoved, error)
	// Some leases of one network, which no longer pass a re-check (§9.8). A lease already gone is no
	// error.
	RemoveEntries(ctx context.Context, networkId connect.Id, refs []*SocketStoreEntryRef) ([]*SocketStoreRemoved, error)
}
