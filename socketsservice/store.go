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
// Fences (DESIGN-DETAILS 13.2.3). Every lease keeps the authorization log position it was admitted at, the
// highest of every page that wrote it, and the set_version of the page that last wrote it. A lease removed for
// cause at position x leaves a tombstone in its group for TombstoneTtl, and one unlistened by a newer set leaves
// one for UnlistenFenceTtl, so a write admitted below the tombstone's position, or sent by an older set, is refused
// in the script that would make it (13.3's S2 and S3). A listener's pairs removed at x leave a floor that refuses a
// pair written below x for TombstoneTtl (S4). A tombstone is written only where a lease was removed, and a put at or
// above both its numbers clears it. Positions and set versions are compared as numbers, never through a float.
// Fences only refuse writes: no ticket is ever signed on a stored position, only on the signer's own state (X3).
//
// An error means the store did not answer, so the caller does not know what a write did: the engine
// answers unavailable, and the next call heals it. Safe for concurrent use.

package socketsservice

import (
	"bytes"
	"context"
	"errors"
	"math"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// A request a store refuses whole as malformed: a page out of order, an entry outside its range, or a
// name key that is empty. The engine checks pages before they get here, so this is a caller's bug.
var ErrSocketStoreRequest = errors.New("socket store request malformed")

// Why a lease was removed, which its tombstone keeps (DESIGN-DETAILS 13.2.3's x:<L>). The numbers are the
// record's.
type SocketRemoveCause int

const (
	// A page of a newer set lacked the entry: a tombstone at position 0 for UnlistenFenceTtl, which only a
	// page of an older set meets.
	SocketRemoveUnlisten SocketRemoveCause = 0
	// The gate refused the lease at the removal's position: a page's refused entry, the revocation sweep or
	// a Find's listener check. A tombstone for TombstoneTtl.
	SocketRemoveRefused SocketRemoveCause = 1
	// The client was removed (§9.8, D-SOCK-9): a tombstone at SocketRemovedClientPosition for TombstoneTtl,
	// so every later put of the client's is refused while it lives.
	SocketRemoveClientRemoved SocketRemoveCause = 2
)

// The position a client's removal fences at, above any the authorization log reaches. It is no log position,
// so a fence of this cause is never evidence that the log moved.
const SocketRemovedClientPosition uint64 = math.MaxUint64

// One registration page as the engine passed it: the entries it allows, every check done and every
// default applied (§9.5), and the entries it refused (DESIGN-DETAILS 13.2.3's step 6).
type SocketStorePage struct {
	// The listener's network, which holds every group of the page (D-SOCK-1). A ur/ listener's is
	// urnetwork-edge.
	NetworkId        connect.Id
	ListenerClientId connect.Id
	SetVersion       uint64
	// The authorization log position of the gate state the page was judged on (§7.9). Each lease the page
	// writes keeps the higher of this and the position it stood at, and each refused entry is removed at it.
	PolicyVersion uint64
	// The listener's sidecar, the subject a Find's listener check judges (plan-SOCK-client-auth's sidecar_id
	// claim). nil for a ur/ listener, which has none.
	SidecarId *connect.Id
	// The page's range of name keys. An empty KeyEnd is unbounded.
	KeyStart []byte
	KeyEnd   []byte
	// The entries the engine allows: sorted by name key, each inside the range, at most one per name key.
	Registrations []*sidecar.SocketRegistration
	// The name keys of the entries the engine refused: sorted, each inside the range, none also in
	// Registrations. Each lease of one is removed for cause at PolicyVersion, unless a newer page or a newer
	// position wrote it. Whatever else the client's set holds in the range is unlistened.
	RefusedNameKeys [][]byte
}

// What became of one allowed entry of a page. At most one of Fenced, Stale and Taken is set, checked in
// that order; with none set the lease was written.
type SocketStoreEntryOutcome struct {
	// A removal stands at a newer position or by a newer set than the page's, so nothing was written.
	// FencePolicyVersion is the removal's position and FenceCause why it was made: a fence of
	// SocketRemoveRefused names a position some process verified, which is evidence that the log reached
	// it; the other causes name none (SocketRemoveUnlisten fences by set, and SocketRemovedClientPosition is
	// no log position).
	Fenced             bool
	FencePolicyVersion uint64
	FenceCause         SocketRemoveCause
	// A newer page of the same client wrote the lease, so nothing was written (§9.5's older set).
	Stale bool
	// An exclusive listener or another protocol holds the group, so the entry holds no lease, and a
	// lease it held before is gone.
	Taken bool
	// The group had no live listener before this one: §9.4's FirstListen fires on this.
	FirstListener bool
	// The position the lease stood at before the call, 0 when it held none. Above the page's
	// PolicyVersion, a fresher process admitted it.
	PriorPolicyVersion uint64
}

// What a removal for cause did to one lease. Neither Removed nor Kept: there was no live lease.
type SocketStoreRemoval struct {
	// The lease ended, and a tombstone stands in its place.
	Removed *SocketStoreRemoved
	// The lease stands, since a newer page or a newer position wrote it: PolicyVersion is the position it
	// was admitted at, which is evidence that the log reached it when above the removal's.
	Kept          bool
	PolicyVersion uint64
	// Whether the ref's listener's set still holds a name key that begins tls/ or smtp/ once the call is
	// done, as SocketStorePageResult's: with none left and an edge name Removed, the engine removes the
	// listener's pairs (DESIGN-DETAILS 13.2.3's find step 7, and the sweep's). Every ref of one listener
	// carries the same answer.
	EdgeEntriesRemain bool
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
	// The page's set_version is older than the stored one, which SetVersion holds. Refused when the call
	// began, nothing was written and Outcomes is empty; refused when it committed, since a newer page
	// committed meanwhile, Outcomes say what each entry did and the set is the newer page's.
	Stale bool
	// The client's stored set_version once the call is done.
	SetVersion uint64
	// One per allowed entry of the page, in its order; empty when the set refused the page as the call began.
	Outcomes []*SocketStoreEntryOutcome
	// One per RefusedNameKeys, in its order, and empty as Outcomes is. The engine answers revoked for one
	// Removed, and denied for one that held no lease.
	RefusedOutcomes []*SocketStoreRemoval
	// Leases inside the range that the client held before the call and holds no more, in name key
	// order: entries the page lacks, entries the engine refused, and entries now taken or fenced.
	Removed []*SocketStoreRemoved
	// Whether the client's set still holds a name key that begins tls/ or smtp/ once the call is done:
	// with none left and one in Removed, the engine removes the client's pairs (DESIGN-DETAILS 13.2.3's
	// step 9). A token path that happens to begin with those bytes reads as one, which only keeps pairs
	// that EdgePairTtl ends anyway.
	EdgeEntriesRemain bool
}

// One listener as the store holds it: what it registered and what a pick reads.
type SocketStoreListener struct {
	// The registration as last written. Inflight is the last report.
	Registration *sidecar.SocketRegistration
	// §9.7's view of it at the store's now, defaults applied, with its dialers' shares.
	Candidate *SocketCandidate
	// The listener's sidecar, nil for ur/. PolicyVersion is the highest position the lease was admitted at
	// and SetVersion the set_version of the page that last wrote it. A lease written before these were kept
	// reads nil, 0 and 0: the next Find judges it, and the next heartbeat replaces it.
	SidecarId     *connect.Id
	PolicyVersion uint64
	SetVersion    uint64
}

// A network's revocation sweep claim (DESIGN-DETAILS 13.2.3): the position swept and when the claim lapses,
// on the store's clock.
type SocketSweepClaim struct {
	PolicyVersion uint64
	UntilMillis   int64
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
	// One registration page (§9.5; DESIGN-DETAILS 13.2.3's step 6): puts the allowed entries, removes the
	// refused for cause at the page's position, and unlistens what the client's set holds in the range and
	// the page lacks.
	ApplyPage(ctx context.Context, page *SocketStorePage) (*SocketStorePageResult, error)
	// One group-key call (§9.6's step 4, §9.8): trim expired leases, apply the reports, filter or
	// sample, pick, and add the primary to this dialer's share.
	Pick(ctx context.Context, request *SocketStorePickRequest) (*SocketStorePickResult, error)
	// A group's live listeners, in listener client id order: the revocation sweep's read (§9.8).
	ListListeners(ctx context.Context, networkId connect.Id, nameKey []byte) ([]*SocketStoreListener, error)
	// One page of a network's listing, {sn_<network_id>}names (§2.8's sock-4), from cursor, "" first.
	// The next cursor comes back, "" once done. A name may come back on two pages, and a lister keeps
	// one. count bounds what one call examines, so a page may come back short or empty with a cursor.
	// The sweep's claim is no name, and never listed.
	ListNames(ctx context.Context, networkId connect.Id, cursor string, count int) ([]*sidecar.SocketListName, string, error)
	// §6.10.1's pair: field dialerClientId of {svc_<listenerClientId>}, holding the grant's expiry in
	// milliseconds, 0 for none, for ttl, which the engine caps (§9.6). A second write replaces the first
	// and its ttl. Written only at or above a live floor: below it, wrote is false and floor is the floor's
	// position, which is evidence that the log reached it.
	SetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id, grantExpireMillis uint64, ttl time.Duration, position uint64) (wrote bool, floor uint64, err error)
	// The pair's grant expiry, and whether it is there: CreateContract's one read (§6.10.1).
	GetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id) (grantExpireMillis uint64, found bool, err error)
	// Every pair of a listener, on revocation or its last edge unlisten (§9.6), leaving a floor at the
	// higher of position and any live floor for TombstoneTtl.
	RemoveServicePairs(ctx context.Context, listenerClientId connect.Id, position uint64) error
	// Renews a listener's pairs on its accepted edge registration (QD-656): each lives EdgePairTtl more,
	// and never past its grant's expiry, so a pair whose grant has ended goes now.
	TouchServicePairs(ctx context.Context, listenerClientId connect.Id) error
	// Everything a removed client holds, through its set (§9.8, D-SOCK-9): its leases, removed with cause
	// SocketRemoveClientRemoved RemoveClientBatchCount name keys at a time, each batch leaving the set once
	// its leases are gone, so a caller after a failure, or another process on the same event, starts where
	// the work stands; then its set, and its pairs at SocketRemovedClientPosition. A client the store holds
	// nothing for is no error.
	RemoveClient(ctx context.Context, clientId connect.Id) ([]*SocketStoreRemoved, error)
	// Some leases of one network, removed for cause at position (§9.8; DESIGN-DETAILS 13.2.3): the sweep's
	// and a Find's removal of leases that no longer pass a re-check. cause is SocketRemoveRefused, or
	// SocketRemoveClientRemoved at SocketRemovedClientPosition. One answer per ref, in order: a lease
	// admitted above position is kept. A removed lease leaves its client's set, and each answer says whether
	// that set still holds an edge name.
	RemoveEntries(ctx context.Context, networkId connect.Id, cause SocketRemoveCause, position uint64, refs []*SocketStoreEntryRef) ([]*SocketStoreRemoval, error)
	// Takes the network's revocation sweep at position for ttl, unless an unexpired claim at position or
	// above is held: the claim comes back with whether this call took it. held is the claim this caller
	// took last, which it renews at each page of its sweep, or nil for a first claim. A claim at a lower
	// position gives way to one at a higher.
	ClaimSweep(ctx context.Context, networkId connect.Id, position uint64, ttl time.Duration, held *SocketSweepClaim) (claim *SocketSweepClaim, claimed bool, err error)
}

// Whether a removal of this cause at this position is well formed: an unlisten is a page's alone, and a
// client's removal fences at SocketRemovedClientPosition.
func SocketRemovalAllowed(cause SocketRemoveCause, position uint64) bool {
	switch cause {
	case SocketRemoveRefused:
		return true
	case SocketRemoveClientRemoved:
		return position == SocketRemovedClientPosition
	default:
		return false
	}
}

// Whether nameKey is an edge name a pair stands for, tls/ or smtp/: what EdgeEntriesRemain counts.
func SocketPairNameKey(nameKey []byte) bool {
	return bytes.HasPrefix(nameKey, []byte("tls/")) || bytes.HasPrefix(nameKey, []byte("smtp/"))
}
