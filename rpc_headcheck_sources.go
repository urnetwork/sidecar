// HeadCheck's seam (§6.4, D-PROTO-14, D-PROTO-17): what each pin's owner implements, so the reconcile
// engine (rpc_headcheck_state.go) compares pins it owns none of. TEAM-M2-10's ConfigClient is the auth
// source, holding the authorization log and its vetoes; KEYS-M2-23 the gen and group sources, from gen/
// and the MLS groups; EVS1-M2-23's EvsClient.RefHeads the ref source; and SidecarAuthority (CORE-M2-01)
// the peer state. Those tasks name HeadCheck in their Needs, so they depend on this file and never the
// reverse; until each lands, sidecartest's fakes stand in (sidecartest/headcheck_fakes.go).
//
// Each source has two halves. Its reads answer from memory, never block and do no I/O, so reconcile
// stays a pure machine that a test runs on fakes. Its acts do the I/O reconcile asks for, and the
// transport (PROTO-M2-03) runs them with no lock held. The engine never re-walks a statement or a gen/
// chain itself: KEYS-M2-23 and EVS1-M2-23 do their own forward reads and pin refusals and answer only
// whether the read reached the peer's pin, forked from it, or went unserved.
//
// No connect type appears here, so the file builds on every leg, and the values below are §6.4's and
// §6.5's protocol values, not tunables: another number is another protocol.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §6.4's and §6.5's HeadCheck bounds.
const (
	// Groups, gens and refs a HeadCheck carries, each, rotating (§6.4).
	HeadCheckMaxListCount = 16
	// Signed RecoveryVetoes a HeadCheck carries (§6.5).
	HeadCheckMaxVetoCount = 4
	// UNVERIFIED pins a HeadCheck carries, highest first (§6.4's relay row).
	HeadCheckMaxUnverifiedSendCount = 4
	// UNVERIFIED pins a device holds, keeping the highest (§6.4's relay row).
	HeadCheckMaxUnverifiedCount = 64
	// Of those, the most taken from one peer (§6.4's relay row).
	HeadCheckMaxUnverifiedPeerCount = 4
	// The longest relay path a receiver keeps once it has appended the sender: the claimant and up to
	// seven relayers (§6.4's relay row, D-PROTO-17).
	HeadCheckMaxPathCount = 8
	// The most a HeadCheckProof holds, what §7.9's retain row keeps on every sidecar, phones included
	// (§6.4, owner decision 147).
	HeadCheckMaxProofByteCount = 64 * 1024
	// The bytes of an authorization chain digest A_n, a generation commitment C_g and a ref chain C_v,
	// each a SHA-256 (§7.9, §10.5, §11.8).
	headCheckDigestByteCount = 32
	// The most an MLS epoch_authenticator takes: the KDF's output, 64 B for SHA-512 (RFC 9420 §8.7).
	headCheckMaxAuthenticatorByteCount = 64
)

var (
	// A HeadCheckSources missing a source. Each is required: a build without one of a component's
	// pins passes a source that holds none, never a nil that would read as nothing to compare.
	errHeadCheckSources = errors.New("invalid head check sources")
	// What AuthProof answers when the entries it keeps do not reach back to the requested position
	// within HeadCheckMaxProofByteCount, phones included (§6.4's auth row): the requester's
	// HeadCheckProofRequest gets Error{NOT_FOUND}.
	ErrHeadCheckProofNotFound = errors.New("head check proof not found")
	// What VerifyAuthProof answers for a proof that does not chain from this device's pin to the
	// claimed one, or whose entries do not verify. Nothing acts on such a proof.
	ErrHeadCheckProofInvalid = errors.New("head check proof invalid")
)

// The authorization log's side (§7.9): this device's pin, the chain digests it keeps, its vetoes, and
// the reads and checks HeadCheck's auth rows ask of api and of a peer's proof. TEAM-M2-10's
// ConfigClient implements it. Safe for concurrent use.
type HeadCheckAuthSource interface {
	// This device's newest verified (n, A_n). Nil before any state verifies, when there is nothing to
	// compare and so no witness.
	Pin() *bridge.AuthPin
	// A_version as the log keeps it (§7.9's retain row), and false for a position it does not keep:
	// before its retention point, or past its pin.
	ChainAt(version uint64) ([]byte, bool)
	// The Signed RecoveryVetoes pending or recently activated in this device's view (§7.9), at most
	// HeadCheckMaxVetoCount, which its HeadCheck carries.
	Vetoes() [][]byte
	// Fetches the entries after this device's pin from api, through.Version at least, and applies them
	// as §7.9's apply row does. It answers once api has served them, or has not within ctx; either
	// way the caller reads Pin and ChainAt to learn whether they chain to through. A fork this finds
	// is the log's own, which it reports to HeadStopState.ReportFork itself.
	FetchAuth(ctx context.Context, through *bridge.AuthPin) error
	// Checks a peer's HeadCheckProof (§6.5): the entries after this device's pin, chaining from its
	// A_n to through, each signed as §7.9's verify row asks, a base's rows by hash from api. Nil only
	// when all of that holds; else ErrHeadCheckProofInvalid. It applies nothing.
	VerifyAuthProof(ctx context.Context, entries [][]byte, through *bridge.AuthPin) error
	// The entries after position after, through this device's pin, as a HeadCheckProof serves them:
	// verbatim, a base as its header only, at most HeadCheckMaxProofByteCount
	// (ConfigClient.HeadCheckProof). ErrHeadCheckProofNotFound when the entries it keeps do not reach
	// back to after within that.
	AuthProof(after uint64) ([][]byte, error)
	// Verifies one Signed RecoveryVeto a peer sent and acts on it by §7.9's precedence rule
	// (ConfigLog.HoldVeto). A veto that does not verify changes nothing and answers an error.
	HoldVeto(ctx context.Context, signedVeto []byte) error
}

// What a source's forward read came to (§6.4's gens and refs rows).
type HeadCheckCatchUp int

const (
	// The read reached the peer's pin, which now matches this device's.
	HeadCheckCaughtUp HeadCheckCatchUp = 1
	// The chain does not reach the peer's pin, or does not extend this device's: a fork, which the
	// source has refused as its pin rules say.
	HeadCheckCatchUpForked HeadCheckCatchUp = 2
	// The store did not serve what the read needed, which proves nothing either way.
	HeadCheckCatchUpUnserved HeadCheckCatchUp = 3
)

// §10.5's generation pins: for each repo, its group's newest gen/ C_g this device holds. KEYS-M2-23
// implements it. Safe for concurrent use.
type HeadCheckGenSource interface {
	// The generation pins this device holds for repos the peer also reads, in a stable order, so the
	// transport rotates through them (§6.4).
	GenHeads(peerSidecarId Id) []*protocol.GenHead
	// This device's pin for one group's gen/ chain, false when it holds none.
	GenHead(groupId Id) (*protocol.GenHead, bool)
	// Reads gen/ from this device's pin up to through.Generation, checking each link (§10.5), as
	// KEYS-M2-23's forward read does, and refuses and alarms on a chain that does not reach through.
	CatchUpGen(ctx context.Context, through *protocol.GenHead) (HeadCheckCatchUp, error)
}

// §10.4's epoch pins: the MLS groups this device is a leaf of. Agents and wrapped member devices are
// leaves of none of those they read, so they compare generations there instead (§6.4's witnesses).
// KEYS-M2-23 implements it. Safe for concurrent use.
type HeadCheckGroupSource interface {
	// The groups this device and the peer are both leaves of, with this device's epoch pins, in a
	// stable order.
	GroupHeads(peerSidecarId Id) []*protocol.GroupHead
	// This device's epoch pin for a group it is a leaf of, false when it is a leaf of none by that id.
	GroupHead(groupId Id) (*protocol.GroupHead, bool)
}

// One ref pin (§11.8), with the group its repo seals under, which a fork there stops.
type HeadCheckRef struct {
	Head *protocol.RefHead
	// The §10 group of the ref's repo.
	GroupId Id
}

// §11.8's ref pins. EVS1-M2-23's EvsClient.RefHeads implements it. Safe for concurrent use.
type HeadCheckRefSource interface {
	// The ref pins this device holds for refs the peer also reads, in a stable order.
	RefHeads(peerSidecarId Id) []*protocol.RefHead
	// This device's pin for one ref, false when it holds none.
	RefHead(repoId Id, refId Id) (HeadCheckRef, bool)
	// Reads the ref's signed statements from this device's version up to through.Version and
	// recomputes C forward (§11.9), as EVS1-M2-23's walk does, and refuses and alarms on a chain that
	// does not extend this device's pin or does not reach through.
	CatchUpRef(ctx context.Context, through *protocol.RefHead) (HeadCheckCatchUp, error)
}

// How this device's newest verified state holds one sidecar, for §6.4's witness and relay rows. The
// zero value is a sidecar no admission names, which counts for nothing.
type HeadCheckPeer struct {
	// A SidecarAdmit names it, whatever has happened since.
	Admitted bool
	// A revocation names it.
	Revoked bool
	// §7.9's cascade parks it.
	Parked bool
	// An active Suspend names it (§8.8). It still answers HeadCheck, since suspension gates grants
	// and witnessing, not identity, but it counts as no witness.
	Suspended bool
}

// §7.9's admissions as HeadCheck reads them. CORE-M2-01's SidecarAuthority implements it, on TEAM's
// ConfigState, so the standing rules stay there. Safe for concurrent use.
type HeadCheckPeerState interface {
	// The sidecar as this device's newest verified state holds it.
	HeadCheckPeer(sidecarId Id) HeadCheckPeer
}

// Every source HeadCheck compares, for one network. Each is required.
type HeadCheckSources struct {
	Auth   HeadCheckAuthSource
	Gens   HeadCheckGenSource
	Groups HeadCheckGroupSource
	Refs   HeadCheckRefSource
	Peers  HeadCheckPeerState
}

// Refuses sources with one missing.
func (self *HeadCheckSources) validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: none", errHeadCheckSources)
	case self.Auth == nil:
		return fmt.Errorf("%w: no auth source", errHeadCheckSources)
	case self.Gens == nil:
		return fmt.Errorf("%w: no gen source", errHeadCheckSources)
	case self.Groups == nil:
		return fmt.Errorf("%w: no group source", errHeadCheckSources)
	case self.Refs == nil:
		return fmt.Errorf("%w: no ref source", errHeadCheckSources)
	case self.Peers == nil:
		return fmt.Errorf("%w: no peer state", errHeadCheckSources)
	}
	return nil
}
