// GkmClient, §10.14's client of gkm: the only way the rest of a sidecar reaches a repo's keys. §11's writes seal
// to what EnsureWritable returns, its reads open with CurrentRepoKey and RepoKey, its deposits seal to DropKey, and
// §7.9's log applier tells it each new state. §10.14 names the first four calls; CreateGroup, RotateRepo,
// AuthAdvanced and ForgetRepo are KF1, `ur keys rotate`, the applier's call and §11.12's shred.
//
// The real client lands with KEYS-M2-18 to KEYS-M2-22, on the engine KEYS-M2-08 wires in. Until then a sidecar's
// client is gkmRefusingClient, which refuses every call, so nothing reads as keyed while no engine exists, and
// sidecartest.FakeGkm stands in for tests. NewSidecar (CORE-M1-08) does not exist yet; when it does, it hands out
// newGkmRefusingClient until the real client replaces it.
//
// Implementations are safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// No client can answer: the engine is not wired (KEYS-M2-08), or gkm cannot be reached and nothing cached
	// answers instead (KF7).
	ErrGkmUnavailable = errors.New("gkm unavailable")
	// This sidecar does not write the repo in its newest verified state (§8.12).
	ErrGkmNotWriter = errors.New("gkm: not a writer of the repo")
	// No generation may be sealed to yet: the newest does not cover a shrink or expiry this sidecar's state shows,
	// or its drop key has lapsed, and a writer's rotation must come first (§10.5's depositor rule).
	ErrGkmWait = errors.New("gkm: waiting for a covering generation")
)

// The drop key of a repo's newest generation, which a depositor seals to and cannot read back (D-KEYS-8,
// D-KEYS-17).
type GkmDropKey struct {
	RepoId Id
	// The generation pin a deposit carries (§11.8).
	GroupId    Id
	Generation uint64
	Commitment []byte
	// The X-Wing public key from gen/<g>'s GenRotate.
	PublicKey []byte
	// drop_not_after_ms: deposits seal to it only before this.
	NotAfter time.Time
}

// A new repo's group (KF1): ur_group's fields (§10.5).
type GkmCreateGroupArgs struct {
	NetworkId Id
	RepoId    Id
	Kind      protocol.RepoKind
	// The member an owner-bound repo belongs to, nil for any other.
	OwnerMemberId *Id
}

// One sidecar's client of gkm (§10.14). A delivery is judged at its own pin, gen/<g>'s for a staged one and its
// signer's state for a late one, never at this sidecar's tip, so one above the tip is held only once the log reaches
// it (§10.9's judged row). A late delivery is a holder's to make, at a state of its own that names this sidecar
// (§10.9's late row), and this sidecar's own state never stands in for that one.
type GkmClient interface {
	// The newest generation of the repo this sidecar holds, checked against gen/<g>'s C_g (§10.5), for reads. It
	// commits and rotates nothing. ErrGkmAuthAhead when every delivery it holds waits for the log.
	CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error)
	// Generation g of the repo, reached through the ladder from one this sidecar holds. ErrGkmKeyMissing when it
	// holds none at or above g: never defaulted (§10.5). ErrGkmAuthAhead when the one it holds waits for the log.
	RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error)
	// The generation new content seals to, §8.12's primary control: it first commits the pending changes this
	// device may, then rotates when the newest generation does not cover the repo's holders_shrunk_at or an expiry,
	// or is over 30 days old, and refuses to return a key any non-reader holds, a live Delegation's key aside. It
	// acts only on the newest generation, never an older one: ErrGkmAuthAhead while this sidecar's state is below
	// that generation's pin, and ErrGkmKeyMissing while it holds no delivery of it.
	EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error)
	// The newest generation's drop key, under §10.5's depositor rule: its GenRotate verifies, it is gkm's newest,
	// it covers every shrink and expiry this sidecar's state shows, it has not lapsed, and it is not below this
	// sidecar's pin for the repo, which then rises; ErrGkmWait otherwise.
	DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error)
	// KF1: the repo's group, epoch 0 and generation 1 at gkm, then generation 1's deliveries while the repo is still
	// keying, resuming after a crash. Returns RK_1, whose GroupId names the group.
	CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error)
	// `ur keys rotate`: a new generation now, REMOVE if it covers a shrink or expiry since its parent, else REQUEST
	// (§10.5's Rotate), from the newest generation as EnsureWritable reaches it, with its refusals.
	RotateRepo(ctx context.Context, repoId Id) (*EvsRepoKey, error)
	// §7.9's applier, after each entry it applies: the new state, from which pending commits and rotations follow.
	// It never blocks, and a state below one already given changes nothing (I-16).
	AuthAdvanced(state GkmAuthView)
	// §11.12's shred: drops the repo's keys, MLS state and pins here (§10.8: members drop its keys).
	ForgetRepo(ctx context.Context, repoId Id) error
}

// What a sidecar holds until a real client exists: every call refuses with ErrGkmUnavailable, and a new state
// changes nothing, so no caller can read it as keyed.
type gkmRefusingClient struct{}

// The client NewSidecar hands out until KEYS-M2-08 and KEYS-M2-22 wire the real one in.
func newGkmRefusingClient() GkmClient {
	return gkmRefusingClient{}
}

// Refuses.
func (self gkmRefusingClient) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refuses.
func (self gkmRefusingClient) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refuses.
func (self gkmRefusingClient) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refuses.
func (self gkmRefusingClient) DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error) {
	return nil, ErrGkmUnavailable
}

// Refuses.
func (self gkmRefusingClient) CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refuses.
func (self gkmRefusingClient) RotateRepo(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Drops the state: nothing here acts on it.
func (self gkmRefusingClient) AuthAdvanced(state GkmAuthView) {}

// Refuses: there is nothing to drop, and a shred must not read as done here.
func (self gkmRefusingClient) ForgetRepo(ctx context.Context, repoId Id) error {
	return ErrGkmUnavailable
}
