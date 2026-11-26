//go:build !ios_extension && !sidecar_http

// How a reader holds a card path to its writer (DESIGN-COMPUTE §20.4's "every reader holds each path to its owner",
// §20.5, D-SKILL-10; SKILL-M11-02): EVS does not stop one writer of a repo rewriting another's path, so every device
// that reads a member's agents repo judges each version of cards/<name>.json itself, oldest first, and takes only:
//
//	first     the path's first version whose card its own writer pushed: the card's sidecar, which the config gives
//	          the repo's member (an untagged device of the member, or a tagged sidecar the member sponsors); for the
//	          person's me card, an untagged consented device of the member the card names, the repo's owner
//	same      a later version keeping the card's name, agent, sidecar and member, pushed by its writer as above
//	retire    a later version setting retired and changing nothing else, pushed by any untagged consented device of
//	          the member, an idle card's retirement (§20.5)
//	reuse     a version naming another agent, pushed by that card's own writer, once the card it replaces was retired
//	          at least SkillSettings.NameReuseAfter before the push (§20.5's reuse, as an overlay address's tombstone)
//
// Every other version is passed over, the version before it standing, and alarmed once a push as record_alarm
// path_rule: another sidecar's version, a tagged sidecar's version of a card not its own, a card that does not parse
// or names another name, a removal (a card is retired, never removed) and a version the repo's prefix rules do not let
// this device follow. A path whose walk does not reach its first version, or passes SkillSettings.CardHistoryMaxCount
// versions, is withheld (ErrAgentCardWithheld), never judged from part of it.
//
// The taken version's push provenance rides with the card (AgentCardRead.Provenance): what §20.6's stubs judge its
// text's trust by (SKILL-M11-03). An enclave's agents' cards, whose writer is an incarnation carrying the enclave's
// tags, wait for the enclaves feature (M14): such a writer is no member device here, so its versions are passed over.
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// A card path a reader cannot judge: its walk did not reach the path's first version, or ran past its bound.
var ErrAgentCardWithheld = errors.New("agent card withheld: its versions could not all be judged")

// The judgments at a state that hold an agents repo's paths to their writers.
type AgentsAuthority interface {
	// The member the config gives a sidecar: an untagged device's admission's member, a tagged sidecar's live
	// sponsor; false for none.
	MemberOf(sidecarId Id) (Id, bool)
	// Whether the sidecar is an untagged device the config consents for memberId (§8.5's consented(d, M)): who writes
	// the person's me card and retires an idle one.
	UntaggedConsented(sidecarId Id, memberId Id) bool
	// The member's agents repo: its first standing one in log order (AclState.AgentsRepo).
	AgentsRepo(memberId Id) (Id, bool)
	// Whether repoId is a standing agent repo the log binds to memberId (AclState.MemberAgentRepo).
	MemberAgentRepo(memberId Id, repoId Id) bool
	// Whether it is one whose RepoCreate filed labelMac, an agent name's keyed label (AclState.MemberAgentRepoLabeled).
	MemberAgentRepoLabeled(memberId Id, repoId Id, labelMac []byte) bool
	// Whether the network's agent_repos feature is on (ConfigState.AuthFeatureOn).
	AgentReposOn() bool
}

// The judgments at one ConfigState.
type agentsStateAuthority struct {
	state *ConfigState
	acl   *AclState
}

// The judgments at state, or an error when its acl rows do not build.
func NewAgentsAuthority(state *ConfigState) (AgentsAuthority, error) {
	if state == nil {
		return nil, ErrAgentsUnavailable
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	return &agentsStateAuthority{state: state, acl: acl}, nil
}

// The admission's member, or a tagged sidecar's live sponsor; a revoked sidecar names none.
func (self *agentsStateAuthority) MemberOf(sidecarId Id) (Id, bool) {
	sidecar := self.state.Sidecar(sidecarId)
	if sidecar == nil || sidecar.Row.GetRevokedAt() != 0 {
		return Id{}, false
	}
	if len(sidecar.TagIds) != 0 {
		return self.state.Sponsor(sidecarId)
	}
	return sidecar.MemberId, sidecar.MemberId != (Id{})
}

// §8.5's consented(d, M) at the state: an untagged, standing device of memberId.
func (self *agentsStateAuthority) UntaggedConsented(sidecarId Id, memberId Id) bool {
	return self.acl.ConsentedFor(sidecarId, memberId)
}

// The member's first standing agents repo in log order.
func (self *agentsStateAuthority) AgentsRepo(memberId Id) (Id, bool) {
	return self.acl.AgentsRepo(memberId)
}

// Whether the log binds the standing agent repo to memberId.
func (self *agentsStateAuthority) MemberAgentRepo(memberId Id, repoId Id) bool {
	return self.acl.MemberAgentRepo(memberId, repoId)
}

// Whether the log binds the standing agent repo to memberId under labelMac.
func (self *agentsStateAuthority) MemberAgentRepoLabeled(memberId Id, repoId Id, labelMac []byte) bool {
	return self.acl.MemberAgentRepoLabeled(memberId, repoId, labelMac)
}

// Whether the state's newest base turns agent_repos on.
func (self *agentsStateAuthority) AgentReposOn() bool {
	return self.state.AuthFeatureOn(AuthFeatureAgentRepos)
}

// What an agents repo's reader calls: EvsRepo's, which the tests fake.
type AgentsRepoAccess interface {
	// A path's versions, newest first.
	History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error)
	// One version's bytes, and its provenance where the args ask for it.
	ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error)
	// Writes held to the versions their caller read (EvsPathWrite.IfVersion).
	WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error)
	// A directory's children.
	List(ctx context.Context, args *EvsReadArgs) (*EvsListing, error)
}

var _ AgentsRepoAccess = (*EvsRepo)(nil)

// One card path as a reader judged it.
type AgentCardRead struct {
	Name AgentName
	// The card taken, nil where no version is one the path's rules take.
	Card *AgentCard
	// The path version taken, its push's signer and time, and its push's provenance (nil where evs gave none).
	Version         uint64
	WriterSidecarId Id
	Time            time.Time
	Provenance      *EvsPushProvenance
	// The path's newest version, a write's base: 0 where evs shows nothing.
	Newest uint64
	// The versions passed over, each alarmed once a push, oldest first.
	PassedOver []uint64
}

// What one card version's read writes into: its bytes, refusing any past maxByteCount.
type agentCardBuffer struct {
	maxByteCount int
	data         []byte
}

// A card past its bound.
var errAgentCardOversize = errors.New("past the card's bound")

// Appends data, refusing what would pass the bound.
func (self *agentCardBuffer) Write(data []byte) (int, error) {
	if self.maxByteCount < len(self.data)+len(data) {
		return 0, errAgentCardOversize
	}
	self.data = append(self.data, data...)
	return len(data), nil
}

// Whether signer is card's own writer in memberId's agents repo: for a me card, an untagged consented device of the
// member it names, the repo's owner; for any other, its sidecar, which the config gives the repo's member.
func agentCardWriter(authority AgentsAuthority, memberId Id, card *AgentCard, signer Id) bool {
	if card.Person() {
		return card.MemberId == memberId && authority.UntaggedConsented(signer, memberId)
	}
	if signer != card.SidecarId {
		return false
	}
	signerMember, found := authority.MemberOf(signer)
	return found && signerMember == memberId
}

// The card at name in memberId's agents repo as its rules take it (see the file header), each version passed over
// alarmed through alarm (nil for none). ErrAgentCardWithheld where the walk cannot judge the path whole; a path evs
// shows nothing of reads as no card.
func agentsReaderCheck(ctx context.Context, repo AgentsRepoAccess, authority AgentsAuthority, memberId Id, name AgentName,
	settings *SkillSettings, alarm func(version *EvsHistoryVersion)) (*AgentCardRead, error) {
	read := &AgentCardRead{Name: name}
	path := AgentCardPath(name)
	history, err := repo.History(ctx, &EvsReadArgs{Path: path})
	if errors.Is(err, ErrEvsPathAbsent) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	if 0 < len(history.Versions) {
		read.Newest = history.Versions[0].Version
	}
	if !history.Whole || settings.CardHistoryMaxCount < len(history.Versions) {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardWithheld, path)
	}
	versions := slices.Clone(history.Versions)
	slices.Reverse(versions)
	passOver := func(version *EvsHistoryVersion) {
		read.PassedOver = append(read.PassedOver, version.Version)
		if alarm != nil {
			alarm(version)
		}
	}
	for _, version := range versions {
		if version.Ignored || version.Removed {
			passOver(version)
			continue
		}
		buffer := &agentCardBuffer{maxByteCount: settings.CardMaxByteCount}
		info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Version: version.Version, Provenance: true}, buffer)
		if errors.Is(err, errAgentCardOversize) {
			passOver(version)
			continue
		}
		if err != nil {
			return nil, err
		}
		card, err := ParseAgentCard(buffer.data, settings)
		if err != nil || card.Name != name {
			passOver(version)
			continue
		}
		signer := version.SignerSidecarId
		taken := false
		switch current := read.Card; {
		case current == nil:
			taken = agentCardWriter(authority, memberId, card, signer)
		case agentCardSameAgent(current, card):
			taken = agentCardWriter(authority, memberId, current, signer) ||
				(agentCardRetiredOnly(current, card) && authority.UntaggedConsented(signer, memberId))
		case current.IsRetired():
			// another agent takes the name once the card it replaces has been retired NameReuseAfter
			taken = !version.Time.Before(current.Retired.Add(settings.NameReuseAfter)) && agentCardWriter(authority, memberId, card, signer)
		}
		if !taken {
			passOver(version)
			continue
		}
		read.Card, read.Version, read.WriterSidecarId, read.Time = card, version.Version, signer, version.Time
		read.Provenance = nil
		if info != nil {
			read.Provenance = info.Provenance
		}
	}
	return read, nil
}
