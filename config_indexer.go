// §7.9's IndexerSet and SponsorSet as rules of the log (owner decisions 83, 150, 175, 177, 178; D-TEAM-27):
//
//	IndexerSet  network scope by an Owner's or Admin's device; member scope by a consented device (§8.5) of the
//	              subject's member, the subject itself a consented device of that member; retire also by the subject
//	              itself; the subject neither ephemeral nor read_only; the newest per (sidecar_id, scope) holds, a
//	              device at both scopes running their union; retire and the subject's revocation end it, and a parked
//	              subject serves nothing until lifted, nor one an active Suspend names until its Unsuspend
//	SponsorSet  an admin's device names the member that sponsors a tagged sidecar; until one does, a removed
//	              member's agents resolve to autogroup:admin (Sponsor)
//
// A designation grants no key, grant or read: it names who runs a service within what it already reads. api sees its
// signer, subject, scope and retire; services is sealed to the config's current generation (IndexerServices,
// plan-TEAM-sealed-field-format), and readers ignore a value they do not know. Rows carry each designation that holds
// (question team-m2-07-indexer-rows), so it survives a fold at every reader.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Registers IndexerSet's and SponsorSet's rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_INDEXER_SET,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckIndexerSet,
		apply:      configApplyIndexerSet,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_SPONSOR_SET,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckSponsorSet,
		apply:      configApplySponsorSet,
	})
}

// A designation's key: its subject and scope.
type configIndexerKey struct {
	sidecarId Id
	scope     protocol.IndexerScope
}

// An IndexerSet: a known scope; a subject this state admits and has not revoked, neither ephemeral nor read_only, at
// member scope an untagged device consented for its member; services unless it retires; and one device signer that may
// designate at that scope, or the subject itself retiring.
func configCheckIndexerSet(state *ConfigState, statement *configStatement) error {
	designation := statement.body.(*protocol.IndexerSet)
	subjectId, err := IdFromBytes(designation.GetSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(designation.GetSidecarId()))
	}
	subject := state.sidecars[subjectId]
	switch {
	case subject == nil || subject.GetRevokedAt() != 0:
		return fmt.Errorf("%w: a designation of no admitted sidecar", ErrConfigRule)
	case subject.GetEphemeral() || configRowReadOnly(subject):
		return fmt.Errorf("%w: an ephemeral or read_only subject serves nothing", ErrConfigRule)
	case designation.GetScope() != protocol.IndexerScope_INDEXER_SCOPE_NETWORK && designation.GetScope() != protocol.IndexerScope_INDEXER_SCOPE_MEMBER:
		return fmt.Errorf("%w: scope %d", ErrConfigRule, designation.GetScope())
	case !designation.GetRetire() && len(designation.GetSealedServices()) == 0:
		return fmt.Errorf("%w: a designation of no service", ErrConfigRule)
	case len(statement.signers) != 1 || statement.signers[0].Kind != ConfigSignerSidecar:
		return fmt.Errorf("%w: a designation takes one device's signature", ErrConfigSigner)
	}
	if designation.GetRetire() && statement.signers[0].SidecarId == subjectId {
		return nil
	}
	if designation.GetScope() == protocol.IndexerScope_INDEXER_SCOPE_NETWORK {
		if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
			return configRoleAdmitsMembers(role)
		}); !ok {
			return fmt.Errorf("%w: a network designation needs an Owner's or Admin's device", ErrConfigAuthority)
		}
		return nil
	}
	subjectMemberId, untagged := configRowMember(subject)
	acl, err := state.Acl()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if !untagged || !acl.ConsentedFor(subjectId, subjectMemberId) {
		return fmt.Errorf("%w: a member designation's subject is a consented device of its member", ErrConfigRule)
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return memberId == subjectMemberId && acl.ConsentedFor(signerId, memberId)
	}); !ok {
		return fmt.Errorf("%w: a member designation needs a consented device of the subject's member", ErrConfigAuthority)
	}
	return nil
}

// An IndexerSet's effect: the designation for (sidecar_id, scope) is this one, or none once it retires.
func configApplyIndexerSet(next *configStateBuilder, statement *configStatement) error {
	designation := statement.body.(*protocol.IndexerSet)
	subjectId, err := IdFromBytes(designation.GetSidecarId())
	if err != nil || len(statement.signers) == 0 {
		return fmt.Errorf("%w: a designation of no sidecar", ErrConfigRule)
	}
	key := configIndexerKey{sidecarId: subjectId, scope: designation.GetScope()}
	if designation.GetRetire() {
		next.putIndexer(key, nil)
		return nil
	}
	next.putIndexer(key, &bridge.IndexerRow{
		SidecarId:      subjectId.Bytes(),
		Scope:          uint32(designation.GetScope()),
		Signer:         statement.signers[0].RowsSigner(),
		At:             statement.n,
		SealedServices: bytes.Clone(designation.GetSealedServices()),
	})
	return nil
}

// One IndexerSet designation that holds and serves.
type ConfigIndexer struct {
	SidecarId Id
	Scope     protocol.IndexerScope
	// Who signed it, and its entry.
	Signer Id
	At     uint64
	// IndexerServices, sealed to the config's generation as the entry carried it, which a config reader opens
	// (OpenConfigBody); a value it does not know it ignores.
	SealedServices []byte
}

// Every designation that holds and whose subject serves at this state: not retired, the subject not revoked, not
// parked and named by no active Suspend (§8.6: a Suspend removes its activations), by subject then scope. A state whose
// acl rows do not build, which no base carries, answers none.
func (self *ConfigState) Indexers() []ConfigIndexer {
	indexers := []ConfigIndexer{}
	acl, err := self.Acl()
	if err != nil {
		return indexers
	}
	for _, key := range self.indexerKeys() {
		row := self.indexers[key]
		subject := self.sidecars[key.sidecarId]
		if subject == nil || subject.GetRevokedAt() != 0 || subject.GetParkedAt() != 0 || acl.Suspended(key.sidecarId) {
			continue
		}
		indexer := ConfigIndexer{SidecarId: key.sidecarId, Scope: key.scope, At: row.GetAt(), SealedServices: row.GetSealedServices()}
		if signerId, err := IdFromBytes(row.GetSigner()); err == nil {
			indexer.Signer = signerId
		}
		indexers = append(indexers, indexer)
	}
	return indexers
}

// The designations naming the device that hold and serve, as CORE's SidecarIndexerAuthority answers them.
func (self *ConfigState) IndexerDesignations(sidecarId Id) []SidecarIndexerDesignation {
	designations := []SidecarIndexerDesignation{}
	for _, indexer := range self.Indexers() {
		if indexer.SidecarId == sidecarId {
			designations = append(designations, SidecarIndexerDesignation{Scope: indexer.Scope})
		}
	}
	return designations
}

// The designations' keys, by subject then scope.
func (self *ConfigState) indexerKeys() []configIndexerKey {
	keys := make([]configIndexerKey, 0, len(self.indexers))
	for key := range self.indexers {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a configIndexerKey, b configIndexerKey) int {
		if c := a.sidecarId.Cmp(b.sidecarId); c != 0 {
			return c
		}
		return cmp.Compare(a.scope, b.scope)
	})
	return keys
}

// A SponsorSet: a tagged sidecar this state admits and has not revoked, a member of this state as its sponsor, and an
// admin's device, an Owner's or Admin's, as its one signer (owner decision 83).
func configCheckSponsorSet(state *ConfigState, statement *configStatement) error {
	sponsorSet := statement.body.(*protocol.SponsorSet)
	sidecarId, err := IdFromBytes(sponsorSet.GetSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(sponsorSet.GetSidecarId()))
	}
	sponsorId, err := IdFromBytes(sponsorSet.GetSponsorMemberId())
	if err != nil {
		return fmt.Errorf("%w: a sponsor_member_id of %d bytes", ErrConfigRule, len(sponsorSet.GetSponsorMemberId()))
	}
	row := state.sidecars[sidecarId]
	switch {
	case row == nil || row.GetRevokedAt() != 0 || len(row.GetTagIds()) == 0:
		return fmt.Errorf("%w: a sponsor names only an admitted tagged sidecar", ErrConfigRule)
	case state.members[sponsorId] == nil:
		return fmt.Errorf("%w: a sponsor that is no member", ErrConfigRule)
	case len(statement.signers) != 1:
		return fmt.Errorf("%w: a SponsorSet takes one device's signature", ErrConfigSigner)
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return configRoleAdmitsMembers(role)
	}); !ok {
		return fmt.Errorf("%w: a SponsorSet needs an admin's device", ErrConfigAuthority)
	}
	return nil
}

// A SponsorSet's effect: the tagged sidecar's sponsor is the member it names.
func configApplySponsorSet(next *configStateBuilder, statement *configStatement) error {
	sponsorSet := statement.body.(*protocol.SponsorSet)
	sidecarId, err := IdFromBytes(sponsorSet.GetSidecarId())
	if err != nil {
		return err
	}
	row := next.sidecarForWrite(sidecarId)
	if row == nil {
		return fmt.Errorf("%w: no such sidecar", ErrConfigRule)
	}
	row.Sponsor = bytes.Clone(sponsorSet.GetSponsorMemberId())
	return nil
}

// IndexerSet's search service (TEAM-M10-01, TEAM-M10-02; §11.14, §18.4; D-TEAM-27, D-EVS-58; owner decisions 126, 157,
// 175, 177, 178): which designated indexers d may answer searcher p's remote searches over repo R at this state S, as
// DESIGN-DETAILS 7.2.2's E1 to E6. Both ends call it, each in its own newest verified state at every send and every
// page (FI-24): the asker with itself as searcher, the indexer with the requester as searcher, checking that its own
// id is in the answer, so E1 and E2 are judged for the indexer by this code too.
//
//	E1  d stands: admitted, not revoked, parked or suspended, its admission not past not_after; neither ephemeral
//	    nor read_only; d is not p
//	E2  scopes(d), the scopes at which d's designation holds with services that open and name search, is not empty
//	E3  p stands as d does, and is an untagged member device, not ephemeral
//	E4  d and p both read R (§8.12's RepoReaders), and R's kind is none of secret, config, mailcfg
//	E5  R owner-bound to member M (a vault or mailbox): d is a consented device of M (§8.5), whoever else reads R;
//	    member is in scopes(d), or network is and S holds one member (a personal network); and p is a consented
//	    device of M or the subject of a live EvsShare of R
//	E6  R a team repo (general, which a group inbox is, record, team_record, the directory): network is in
//	    scopes(d), or member is and d and p are untagged devices of one member
//
// So a member's own vault and mailbox go only to that member's consented indexers, a vault another member shared goes
// only to its owner's, the audit reader, which is neither an owner's device nor a share's subject, gets none, and a
// tagged indexer, consented for no one, answers team repos only, at network scope. A kind this code does not know
// answers none.
//
// services opens a designation's sealed services, the caller holding the key of the config's generation
// (OpenConfigBody); a designation it cannot open serves no search.
func (self *ConfigState) SearchIndexersFor(searcherId Id, repoId Id, services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)) []Id {
	acl, err := self.Acl()
	if err != nil || services == nil {
		return nil
	}
	repo := acl.Repo(repoId)
	// E3
	searcher, standing := self.standingSidecar(searcherId, self.timeMs)
	if repo == nil || !standing || !configRowMemberDevice(searcher) || acl.Suspended(searcherId) {
		return nil
	}
	searcherMember, _ := configRowMember(searcher)
	// E4's kinds, and which of E5 and E6 decides
	ownerBound := false
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX:
		ownerBound = true
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		protocol.RepoKind_REPO_KIND_DIRECTORY:
	default:
		return nil
	}
	readers := self.RepoReaders(repoId)
	if !slices.Contains(readers, searcherId) {
		return nil
	}
	ownerId := Id{}
	if ownerBound {
		// E5's third line, which no indexer changes
		ownerId, err = IdFromBytes(repo.GetOwnerMemberId())
		if err != nil || ownerId == (Id{}) {
			return nil
		}
		if !acl.ConsentedFor(searcherId, ownerId) && !self.evsShareSubject(acl, searcherId, repoId) {
			return nil
		}
	}
	oneMember := len(self.members) == 1

	// E2: Indexers answers by subject then scope, so a subject's scopes are adjacent
	type searchScopes struct {
		sidecarId Id
		network   bool
		member    bool
	}
	subjects := []searchScopes{}
	for _, indexer := range self.Indexers() {
		offered, opened := services(indexer)
		if !opened || !slices.Contains(offered, protocol.IndexerService_INDEXER_SERVICE_SEARCH) {
			continue
		}
		if len(subjects) == 0 || subjects[len(subjects)-1].sidecarId != indexer.SidecarId {
			subjects = append(subjects, searchScopes{sidecarId: indexer.SidecarId})
		}
		scopes := &subjects[len(subjects)-1]
		switch indexer.Scope {
		case protocol.IndexerScope_INDEXER_SCOPE_NETWORK:
			scopes.network = true
		case protocol.IndexerScope_INDEXER_SCOPE_MEMBER:
			scopes.member = true
		}
	}

	answering := []Id{}
	for _, scopes := range subjects {
		if !scopes.network && !scopes.member {
			continue
		}
		// E1; Indexers left out a revoked, parked or suspended subject
		indexer, standing := self.standingSidecar(scopes.sidecarId, self.timeMs)
		if !standing || indexer.GetEphemeral() || configRowReadOnly(indexer) || scopes.sidecarId == searcherId {
			continue
		}
		// E4
		if !slices.Contains(readers, scopes.sidecarId) {
			continue
		}
		answers := false
		if ownerBound {
			answers = acl.ConsentedFor(scopes.sidecarId, ownerId) && (scopes.member || (scopes.network && oneMember))
		} else {
			indexerMember, indexerUntagged := configRowMember(indexer)
			answers = scopes.network || (scopes.member && indexerUntagged && indexerMember == searcherMember)
		}
		if answers {
			answering = append(answering, scopes.sidecarId)
		}
	}
	return answering
}

// Whether the sidecar is the subject of a live EvsShare of the repo at this state's time, as §8.5 gives its read: a
// share whose signer counts (a consented device of the repo's owner, outside every cascade), unexpired, whose subject
// names the sidecar as §8.6 reads a share's subject.
func (self *ConfigState) evsShareSubject(acl *AclState, sidecarId Id, repoId Id) bool {
	repo := acl.repos[repoId]
	sidecar := acl.sidecarState(sidecarId)
	if repo == nil || sidecar == nil {
		return false
	}
	for i := range repo.shares {
		share := &repo.shares[i]
		if !share.valid || (share.expiresMs != 0 && share.expiresMs <= self.timeMs) {
			continue
		}
		if acl.namesSidecar(sidecar, share.subject, sidecar.ephemeral) {
			return true
		}
	}
	return false
}

// The network's indexers at the newest verified state, for `ur indexer ls`.
func (self *Sidecar) Indexers() ([]ConfigIndexer, error) {
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	return state.Indexers(), nil
}

// The config generation's key was not given, so services cannot be sealed: the designation is refused, never signed
// with its services in the clear.
var errConfigIndexerNoKey = errors.New("no key of the config's generation here: an indexer's services ride sealed to it")

// Designates this device as an indexer at scope for services (TEAM-M2-18's `ur indexer add`), as the person confirmed
// it (origin, never MCP or a hook), its services sealed to the config's current generation, whose key configKey answers
// (the GkmClient's CurrentRepoKey of the config repo): nil holds none, and the act is refused. search is refused on an
// app host, since an indexer is an always-on `ur daemon` (owner decisions 150, 197).
func (self *Sidecar) DesignateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService, appHost bool,
	configKey func(ctx context.Context) (*EvsRepoKey, error), origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if appHost && slices.Contains(services, protocol.IndexerService_INDEXER_SERVICE_SEARCH) {
		return errors.New("an app host answers no remote search: search is an always-on daemon's")
	}
	if len(services) == 0 {
		return errors.New("a designation names at least one service")
	}
	identity := self.currentIdentity()
	if identity == nil {
		return ErrSidecarNoIdentity
	}
	if configKey == nil {
		return errConfigIndexerNoKey
	}
	repoKey, err := configKey(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", errConfigIndexerNoKey, err)
	}
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	err = act.AddSealed(bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{SidecarId: identity.SidecarId.Bytes(), Scope: scope},
		func(header *bridge.StatementHeader, statement proto.Message) error {
			sealed, err := SealConfigBody(repoKey, NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, header), &protocol.IndexerServices{Services: services}, nil)
			if err != nil {
				return err
			}
			statement.(*protocol.IndexerSet).SealedServices = sealed
			return nil
		})
	if err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}

// Retires this device's designation at scope (`ur indexer rm`), as the person confirmed it; the subject itself may sign
// it (§7.9's IndexerSet).
func (self *Sidecar) RetireIndexerScope(ctx context.Context, scope protocol.IndexerScope, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	identity := self.currentIdentity()
	if identity == nil {
		return ErrSidecarNoIdentity
	}
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	if err := act.Add(bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{SidecarId: identity.SidecarId.Bytes(), Scope: scope, Retire: true}); err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}
