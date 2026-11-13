// AclState: the immutable acl part of §7.9's S(n), built once per position from that state's AclRows and
// a view of its admissions, so a gate or a client checks without a lock and without allocating. Ids map to
// dense ints, and the sets a check intersects are bitsets over the rows' rules: which rules each atom and
// each sidecar is in the src of, which rules reach each sidecar as a destination, and which rules each
// action, each repo and each socket kind holds. A check intersects a few of these and then reads each
// candidate rule's expiry against now, so a rule's expiry takes effect at exactly its time with no rebuild.
//
// The rows carry the target forms ACL-M2-04's compile writes (acl-m2-02-state-readings #2): an atom,
// autogroup:self and autogroup:internet among them; a sidecar, a client no binding names or another
// network; a repo by id, or by sixteen zero bytes for every general or record repo (evs:*, a bare *); one
// socket's token paths, each t_1 || ... || t_n of 16-byte segments (§9.4), or with socket_prefix every
// name strictly below one, no token meaning every application socket; a tls/ or smtp/ name or a dns host,
// glob kept, in public_name; mail_send. A bare * compiles to several of these. In a rule allowing route,
// subject targets are its via subjects (§8.10). Rows carry no ports and no CIDRs, only whether a rule
// limits ports (plan-BRIDGE-gate-row-prefixes #1): a gate decides who reaches whom, and a client's
// AclEngine checks ports and addresses from AclLocalPolicy.
//
// Malformed rows refuse to build: an atom or id of the wrong size, a duplicate atom or repo, a target with
// two kinds set. A target with no kind this code knows, from a later format, matches nothing, and so does
// an action value it does not know, so an older reader never allows what it cannot read.
//
// The config repo's row is the state's own (QD-719). §7.9's bootstrap creates the config repo and no RepoCreate
// ever files it, so no rows hold an AclRepo for it: where the rows hold none, the state adds
// AclRepo{repo_id: Genesis.config_repo_id, kind: config}, with no owner, no admins and no access log, so §8.5's
// config kind default answers it alike in every reader, gate and api, each of which holds the Genesis. The
// rows' bytes do not change, and Rows answers the rows as they came. Rows that give the Genesis's config repo
// another kind refuse to build, and with the row standing a RepoCreate of that id is a second one, so no
// statement moves the config onto another kind's rules. A view with no Genesis, a test's, gets no such row.
//
// The added row's holders_shrunk_at is the state's own position: no rows carry the config's shrinks yet
// (question acl-config-repo-row-shrunk-at), so until they do every position counts as one, the closed
// direction, and §10.6's gate takes a config write only under a generation pinned at the state judging it.
//
// Safe for concurrent use once built.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Why NewAclState refused, wrapped with the field.
var ErrAclRowsInvalid = errors.New("invalid acl rows")

// §8.8's bound on a projection's atoms, a format constant that every reader holds alike.
const aclRowsMaxAtomCount = 4096

// §9.4's token per socket name segment.
const aclSocketTokenByteCount = 16

// The highest AclAction value this code reads; a higher one matches nothing.
const aclActionMax = protocol.AclAction_ACL_ACTION_SEND

// The actions a dial or route reach reads (§8.10's contract rule).
const aclReachActions = 1<<uint32(protocol.AclAction_ACL_ACTION_DIAL) | 1<<uint32(protocol.AclAction_ACL_ACTION_ROUTE)

// The actions that grant something on an evs repo.
const aclEvsActions = 1<<uint32(protocol.AclAction_ACL_ACTION_READ) | 1<<uint32(protocol.AclAction_ACL_ACTION_WRITE) |
	1<<uint32(protocol.AclAction_ACL_ACTION_ADMIN) | 1<<uint32(protocol.AclAction_ACL_ACTION_DEPOSIT)

// A set of a state's rules, one bit per rule index.
type aclBits []uint64

// Whether the rule is in the set.
func (self aclBits) has(index int32) bool {
	return self[index>>6]&(1<<(uint32(index)&63)) != 0
}

// Puts the rule in the set.
func (self aclBits) set(index int32) {
	self[index>>6] |= 1 << (uint32(index) & 63)
}

// Adds every rule of other.
func (self aclBits) union(other aclBits) {
	for i := range self {
		self[i] |= other[i]
	}
}

// One socket target: alternative token paths for one name, or with prefix every name strictly below each.
type aclSocketTarget struct {
	tokenPaths [][]byte
	prefix     bool
}

// Whether the target holds the token path of one socket.
func (self *aclSocketTarget) covers(nameToken []byte) bool {
	if len(nameToken) == 0 || len(nameToken)%aclSocketTokenByteCount != 0 {
		return false
	}
	if self.prefix && len(self.tokenPaths) == 0 {
		return true
	}
	for _, tokenPath := range self.tokenPaths {
		if self.prefix {
			if len(tokenPath) < len(nameToken) && bytes.HasPrefix(nameToken, tokenPath) {
				return true
			}
		} else if bytes.Equal(tokenPath, nameToken) {
			return true
		}
	}
	return false
}

// Whether some socket name is in both targets: a socket dial grant reaches a listener there (§8.10).
func (self *aclSocketTarget) overlaps(other *aclSocketTarget) bool {
	if (self.prefix && len(self.tokenPaths) == 0) || (other.prefix && len(other.tokenPaths) == 0) {
		return true
	}
	for _, a := range self.tokenPaths {
		for _, b := range other.tokenPaths {
			switch {
			case self.prefix && other.prefix:
				if bytes.HasPrefix(a, b) || bytes.HasPrefix(b, a) {
					return true
				}
			case self.prefix:
				if len(a) < len(b) && bytes.HasPrefix(b, a) {
					return true
				}
			case other.prefix:
				if len(b) < len(a) && bytes.HasPrefix(a, b) {
					return true
				}
			default:
				if bytes.Equal(a, b) {
					return true
				}
			}
		}
	}
	return false
}

// Whether some target of one list overlaps some target of the other.
func aclSocketTargetsOverlap(sockets []aclSocketTarget, otherSockets []aclSocketTarget) bool {
	for i := range sockets {
		for j := range otherSockets {
			if sockets[i].overlaps(&otherSockets[j]) {
				return true
			}
		}
	}
	return false
}

// One rule of the rows, classified once.
type aclRule struct {
	row   *protocol.AclRule
	index int32
	// false for an activated grant whose requests rule the rows no longer hold (FS-14)
	enabled bool
	// ms since the epoch; 0 none
	expiresMs int64
	// a bit per AclAction value
	actions uint32
	// sorted atom indexes
	srcAtoms []int32
	// subject targets
	atomTargets    []int32
	selfTarget     bool
	internetTarget bool
	sidecarTargets []Id
	clientTargets  []Id
	networkTargets []Id
	// resource targets
	repoTargets  []Id
	repoWildcard bool
	sockets      []aclSocketTarget
	publicNames  []string
	mailSend     bool
	// the rule's ip field names ports, which the rows do not carry (plan-BRIDGE-gate-row-prefixes #1)
	portsLimited bool
}

// Whether the rule holds the action.
func (self *aclRule) allows(action protocol.AclAction) bool {
	return self.actions&(1<<uint32(action)) != 0
}

// Whether the rule is in force at nowMs: not ended, and unexpired, an expiry taking effect at exactly its
// time (§8.6's rows(t)).
func (self *aclRule) activeAt(nowMs int64) bool {
	return self.enabled && (self.expiresMs == 0 || nowMs < self.expiresMs)
}

// Whether the rule names the atom in its src.
func (self *aclRule) hasSrcAtom(atomIndex int32) bool {
	_, found := slices.BinarySearch(self.srcAtoms, atomIndex)
	return found
}

// One indexed sidecar: its admission classed, and the rule sets a check intersects.
type aclSidecarState struct {
	id    Id
	facts *AclSidecar
	class AclSubjectClass
	// an admission that names a member or tags; anything else is no admission
	valid      bool
	revoked    bool
	parked     bool
	suspended  bool
	memberGone bool
	notAfterMs int64
	tagged     bool
	ephemeral  bool
	readOnly   bool
	memberId   Id
	// the member that autogroup:self and approvers read: its member, or a tagged one's live sponsor
	owner      Id
	hasOwner   bool
	autogroups uint32
	// sorted atom indexes it holds
	atoms []int32
	// rules it is in the src of
	srcRules aclBits
	// dial or route rules whose subject targets name it
	reachRules aclBits
	// listen rules on token-path sockets it is in the src of
	listenRules aclBits
	// for an ephemeral sidecar, the rules §8.6's ceiling counts: those naming it directly
	ceilingRules aclBits
	// whether it writes config heads
	configWriter bool
	// §8.5's consent, from acl_consent.go's replay: whether a clause held, and the position it first did
	hasConsent  bool
	consentedAt uint64
}

// One indexed repo: its folded access log.
type aclRepoState struct {
	row      *protocol.AclRepo
	kind     protocol.RepoKind
	ownerId  Id
	deleted  bool
	admins   map[Id]bool
	revoked  map[Id]bool
	shares   []aclRepoShare
	grants   []aclRepoGrant
	consents map[Id]bool
}

// One EvsShare row, already judged: its signer a consented device of the owner and outside every cascade.
type aclRepoShare struct {
	row       *protocol.AclRepoShareRow
	subject   Id
	expiresMs int64
	valid     bool
}

// One RepoGrant row.
type aclRepoGrant struct {
	row       *protocol.AclRepoGrantRow
	subject   Id
	expiresMs int64
}

// The acl part of one state S(n).
type AclState struct {
	rows *protocol.AclRows
	view AclAuthView
	pin  *bridge.AuthPin

	// atom id to dense index: 1 to 14 are the autogroups by value, 0 is never used
	atomIndexes map[Id]int32
	atomCount   int32

	rules         []aclRule
	ruleWordCount int

	// by atom index: the rules whose src names it
	srcRulesByAtom []aclBits
	// by AclAction value: the rules allowing it
	actionRules []aclBits
	// dial or route rules with an autogroup:self target
	selfReachRules aclBits
	// dial rules with a token-path socket target
	socketDialRules aclBits
	// by rule index, for a socket dial rule: the listen rules whose token-path sockets overlap its own
	listenOverlaps []aclBits
	// rules with an evs action on the wildcard repo target
	wildcardRepoRules aclBits
	// by repo: rules with an evs action naming it
	repoRules map[Id]aclBits

	sidecarIndexes map[Id]int32
	sidecars       []aclSidecarState

	// by member: the atoms whose member_ids name it, user and group atoms
	memberAtoms    map[Id][]int32
	clientAtoms    map[Id][]int32
	networkAtoms   map[Id][]int32
	roleAtoms      map[string][]int32
	principalAtoms map[string][]int32

	repos map[Id]*aclRepoState
	// the Genesis's config repo and the sidecar that signed it, zero for a view with no Genesis
	configRepoId   Id
	genesisOwnerId Id

	// subjects an active Suspend names (plan-ACL-folded-grant-state #1)
	suspended map[Id]bool
}

// A rows error naming its field. The field is the rows' own, never a name from a policy (I-13).
func aclRowsRefusal(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrAclRowsInvalid, fmt.Sprintf(format, a...))
}

// A 16-byte id from rows bytes.
func aclRowsId(idBytes []byte, field string) (Id, error) {
	id, err := IdFromBytes(idBytes)
	if err != nil {
		return Id{}, aclRowsRefusal("%s is not 16 bytes", field)
	}
	return id, nil
}

// Builds the acl part of the state view describes from its rows. The rows and the view must not change
// afterward; the state keeps both.
func NewAclState(rows *protocol.AclRows, view AclAuthView) (*AclState, error) {
	if rows == nil || view == nil {
		return nil, aclRowsRefusal("no rows or no view")
	}
	self := &AclState{
		rows:           rows,
		view:           view,
		pin:            view.Pin(),
		atomIndexes:    map[Id]int32{},
		repoRules:      map[Id]aclBits{},
		sidecarIndexes: map[Id]int32{},
		memberAtoms:    map[Id][]int32{},
		clientAtoms:    map[Id][]int32{},
		networkAtoms:   map[Id][]int32{},
		roleAtoms:      map[string][]int32{},
		principalAtoms: map[string][]int32{},
		repos:          map[Id]*aclRepoState{},
		suspended:      map[Id]bool{},
	}
	for autogroup := protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER; autogroup <= aclAutogroupMax; autogroup += 1 {
		self.atomIndexes[AclAutogroupAtom(autogroup)] = int32(autogroup)
	}
	self.atomCount = int32(aclAutogroupMax) + 1

	sidecarListedAtoms, err := self.indexAtoms()
	if err != nil {
		return nil, err
	}
	if err := self.indexRules(); err != nil {
		return nil, err
	}
	if err := self.indexSuspensions(); err != nil {
		return nil, err
	}
	if err := self.indexRepos(); err != nil {
		return nil, err
	}
	if err := self.indexConfigRepo(); err != nil {
		return nil, err
	}
	self.indexSidecars(sidecarListedAtoms)
	self.replayConsent()
	self.judgeShares()
	return self, nil
}

// The dense index of an atom, a new one for an atom first seen.
func (self *AclState) atomIndex(atom Id) int32 {
	if index, found := self.atomIndexes[atom]; found {
		return index
	}
	index := self.atomCount
	self.atomIndexes[atom] = index
	self.atomCount += 1
	return index
}

// Indexes the rows' atoms, and returns which atoms list each sidecar for indexSidecars.
func (self *AclState) indexAtoms() (map[Id][]int32, error) {
	if aclRowsMaxAtomCount < len(self.rows.GetAtoms()) {
		return nil, aclRowsRefusal("%d atoms, over %d", len(self.rows.GetAtoms()), aclRowsMaxAtomCount)
	}
	sidecarListedAtoms := map[Id][]int32{}
	for i, atomRow := range self.rows.GetAtoms() {
		atom, err := aclRowsId(atomRow.GetAtom(), fmt.Sprintf("atoms[%d].atom", i))
		if err != nil {
			return nil, err
		}
		if aclAtomHasAutogroupForm(atom) {
			return nil, aclRowsRefusal("atoms[%d] has an autogroup's form", i)
		}
		if _, found := self.atomIndexes[atom]; found {
			return nil, aclRowsRefusal("atoms[%d] repeats an atom", i)
		}
		index := self.atomIndex(atom)
		add := func(idBytesList [][]byte, field string, atomsByIds map[Id][]int32) error {
			for j, idBytes := range idBytesList {
				id, err := aclRowsId(idBytes, fmt.Sprintf("atoms[%d].%s[%d]", i, field, j))
				if err != nil {
					return err
				}
				atomsByIds[id] = append(atomsByIds[id], index)
			}
			return nil
		}
		if err := add(atomRow.GetMemberIds(), "member_ids", self.memberAtoms); err != nil {
			return nil, err
		}
		if err := add(atomRow.GetSidecarIds(), "sidecar_ids", sidecarListedAtoms); err != nil {
			return nil, err
		}
		if err := add(atomRow.GetClientIds(), "client_ids", self.clientAtoms); err != nil {
			return nil, err
		}
		if err := add(atomRow.GetNetworkIds(), "network_ids", self.networkAtoms); err != nil {
			return nil, err
		}
		// tag owners are CanApplyTag's, read from the row itself, and never make a subject's atoms
		for j, ownerBytes := range atomRow.GetTagOwnerMemberIds() {
			if _, err := aclRowsId(ownerBytes, fmt.Sprintf("atoms[%d].tag_owner_member_ids[%d]", i, j)); err != nil {
				return nil, err
			}
		}
		if role := atomRow.GetRole(); role != "" {
			self.roleAtoms[role] = append(self.roleAtoms[role], index)
		}
		if principal := atomRow.GetPrincipal(); principal != "" {
			self.principalAtoms[principal] = append(self.principalAtoms[principal], index)
		}
	}
	return sidecarListedAtoms, nil
}

// Indexes the rows' rules and the sets checks intersect.
func (self *AclState) indexRules() error {
	requestRuleIds := map[string]bool{}
	for _, request := range self.rows.GetRequests() {
		requestRuleIds[string(request.GetRuleId())] = true
	}
	rowRules := self.rows.GetRules()
	self.rules = make([]aclRule, len(rowRules))
	self.ruleWordCount = (len(rowRules) + 63) / 64
	for i, row := range rowRules {
		rule := &self.rules[i]
		rule.row = row
		rule.index = int32(i)
		rule.expiresMs = row.GetExpires()
		rule.enabled = len(row.GetSourceRuleId()) == 0 || requestRuleIds[string(row.GetSourceRuleId())]
		for _, action := range row.GetActions() {
			if protocol.AclAction_ACL_ACTION_UNSPECIFIED < protocol.AclAction(action) && protocol.AclAction(action) <= aclActionMax {
				rule.actions |= 1 << action
			}
		}
		for j, atomBytes := range row.GetSrcAtoms() {
			atom, err := aclRowsId(atomBytes, fmt.Sprintf("rules[%d].src_atoms[%d]", i, j))
			if err != nil {
				return err
			}
			rule.srcAtoms = append(rule.srcAtoms, self.atomIndex(atom))
		}
		slices.Sort(rule.srcAtoms)
		rule.srcAtoms = slices.Compact(rule.srcAtoms)
		for j, target := range row.GetTargets() {
			if err := self.classifyTarget(rule, target, fmt.Sprintf("rules[%d].targets[%d]", i, j)); err != nil {
				return err
			}
		}
		rule.portsLimited = row.GetPortsLimited()
	}

	newBits := func() aclBits {
		return make(aclBits, self.ruleWordCount)
	}
	self.srcRulesByAtom = make([]aclBits, self.atomCount)
	for i := range self.srcRulesByAtom {
		self.srcRulesByAtom[i] = newBits()
	}
	self.actionRules = make([]aclBits, aclActionMax+1)
	for i := range self.actionRules {
		self.actionRules[i] = newBits()
	}
	self.selfReachRules = newBits()
	self.socketDialRules = newBits()
	self.wildcardRepoRules = newBits()
	for i := range self.rules {
		rule := &self.rules[i]
		for _, atomIndex := range rule.srcAtoms {
			self.srcRulesByAtom[atomIndex].set(rule.index)
		}
		for action := protocol.AclAction_ACL_ACTION_DIAL; action <= aclActionMax; action += 1 {
			if rule.allows(action) {
				self.actionRules[action].set(rule.index)
			}
		}
		if rule.actions&aclReachActions != 0 && rule.selfTarget {
			self.selfReachRules.set(rule.index)
		}
		if rule.allows(protocol.AclAction_ACL_ACTION_DIAL) && 0 < len(rule.sockets) {
			self.socketDialRules.set(rule.index)
		}
		if rule.actions&aclEvsActions != 0 {
			if rule.repoWildcard {
				self.wildcardRepoRules.set(rule.index)
			}
			for _, repoId := range rule.repoTargets {
				repoRules, found := self.repoRules[repoId]
				if !found {
					repoRules = newBits()
					self.repoRules[repoId] = repoRules
				}
				repoRules.set(rule.index)
			}
		}
	}
	// a socket dial grant reaches the subjects that listen on what it names (§8.10)
	self.listenOverlaps = make([]aclBits, len(self.rules))
	for i := range self.rules {
		dialRule := &self.rules[i]
		if !self.socketDialRules.has(dialRule.index) {
			continue
		}
		overlaps := newBits()
		for j := range self.rules {
			listenRule := &self.rules[j]
			if !listenRule.allows(protocol.AclAction_ACL_ACTION_LISTEN) {
				continue
			}
			if aclSocketTargetsOverlap(dialRule.sockets, listenRule.sockets) {
				overlaps.set(listenRule.index)
			}
		}
		self.listenOverlaps[dialRule.index] = overlaps
	}
	return nil
}

// Sorts one target into its rule, refusing one with two kinds set. One with none, from a later format,
// adds nothing.
func (self *AclState) classifyTarget(rule *aclRule, target *protocol.AclTarget, field string) error {
	kindCount := 0
	count := func(set bool) {
		if set {
			kindCount += 1
		}
	}
	count(len(target.GetAtom()) != 0)
	count(len(target.GetSidecarId()) != 0)
	count(len(target.GetNetworkId()) != 0)
	count(len(target.GetRepoId()) != 0)
	count(len(target.GetSocketTokens()) != 0 || target.GetSocketPrefix())
	count(target.GetPublicName() != "")
	count(target.GetMailSend())
	count(len(target.GetClientId()) != 0)
	if 1 < kindCount {
		return aclRowsRefusal("%s sets %d kinds", field, kindCount)
	}
	switch {
	case len(target.GetAtom()) != 0:
		atom, err := aclRowsId(target.GetAtom(), field+".atom")
		if err != nil {
			return err
		}
		switch autogroup, _ := aclAtomAutogroup(atom); autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_SELF:
			rule.selfTarget = true
		case protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET:
			rule.internetTarget = true
		default:
			rule.atomTargets = append(rule.atomTargets, self.atomIndex(atom))
		}
	case len(target.GetSidecarId()) != 0:
		sidecarId, err := aclRowsId(target.GetSidecarId(), field+".sidecar_id")
		if err != nil {
			return err
		}
		rule.sidecarTargets = append(rule.sidecarTargets, sidecarId)
	case len(target.GetClientId()) != 0:
		clientId, err := aclRowsId(target.GetClientId(), field+".client_id")
		if err != nil {
			return err
		}
		rule.clientTargets = append(rule.clientTargets, clientId)
	case len(target.GetNetworkId()) != 0:
		networkId, err := aclRowsId(target.GetNetworkId(), field+".network_id")
		if err != nil {
			return err
		}
		rule.networkTargets = append(rule.networkTargets, networkId)
	case len(target.GetRepoId()) != 0:
		repoId, err := aclRowsId(target.GetRepoId(), field+".repo_id")
		if err != nil {
			return err
		}
		if repoId == (Id{}) {
			rule.repoWildcard = true
		} else {
			rule.repoTargets = append(rule.repoTargets, repoId)
		}
	case len(target.GetSocketTokens()) != 0 || target.GetSocketPrefix():
		socket := aclSocketTarget{prefix: target.GetSocketPrefix()}
		for j, tokenPath := range target.GetSocketTokens() {
			if len(tokenPath)%aclSocketTokenByteCount != 0 || (len(tokenPath) == 0 && !socket.prefix) {
				return aclRowsRefusal("%s.socket_tokens[%d] is no token path", field, j)
			}
			if 0 < len(tokenPath) {
				socket.tokenPaths = append(socket.tokenPaths, tokenPath)
			}
		}
		rule.sockets = append(rule.sockets, socket)
	case target.GetPublicName() != "":
		rule.publicNames = append(rule.publicNames, target.GetPublicName())
	case target.GetMailSend():
		rule.mailSend = true
	}
	return nil
}

// Indexes the active Suspends.
func (self *AclState) indexSuspensions() error {
	for i, suspension := range self.rows.GetSuspensions() {
		subject, err := aclRowsId(suspension.GetSubject(), fmt.Sprintf("suspensions[%d].subject", i))
		if err != nil {
			return err
		}
		self.suspended[subject] = true
	}
	return nil
}

// Indexes the rows' repos and their folded access logs.
func (self *AclState) indexRepos() error {
	for i, row := range self.rows.GetRepos() {
		field := fmt.Sprintf("repos[%d]", i)
		repoId, err := aclRowsId(row.GetRepoId(), field+".repo_id")
		if err != nil {
			return err
		}
		if repoId == (Id{}) {
			return aclRowsRefusal("%s names the wildcard repo", field)
		}
		if _, found := self.repos[repoId]; found {
			return aclRowsRefusal("%s repeats a repo", field)
		}
		repo := &aclRepoState{
			row:      row,
			kind:     row.GetKind(),
			admins:   map[Id]bool{},
			revoked:  map[Id]bool{},
			consents: map[Id]bool{},
		}
		if len(row.GetOwnerMemberId()) != 0 {
			if repo.ownerId, err = aclRowsId(row.GetOwnerMemberId(), field+".owner_member_id"); err != nil {
				return err
			}
		}
		deletion := row.GetDeletion()
		repo.deleted = deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0
		for j, consentedBytes := range row.GetConsentedSidecarIds() {
			sidecarId, err := aclRowsId(consentedBytes, fmt.Sprintf("%s.consented_sidecar_ids[%d]", field, j))
			if err != nil {
				return err
			}
			repo.consents[sidecarId] = true
		}
		for j, admin := range row.GetAdmins() {
			sidecarId, err := aclRowsId(admin.GetSidecarId(), fmt.Sprintf("%s.admins[%d].sidecar_id", field, j))
			if err != nil {
				return err
			}
			// a removed admin's row stays for RepoAdminAt's earlier positions (QD-743) and administers nothing now
			if AclRepoAdminStands(admin) {
				repo.admins[sidecarId] = true
			}
		}
		for j, revoke := range row.GetRevokes() {
			subject, err := aclRowsId(revoke.GetSubject(), fmt.Sprintf("%s.revokes[%d].subject", field, j))
			if err != nil {
				return err
			}
			repo.revoked[subject] = true
		}
		for j, grant := range row.GetGrants() {
			subject, err := aclRowsId(grant.GetSubject(), fmt.Sprintf("%s.grants[%d].subject", field, j))
			if err != nil {
				return err
			}
			repo.grants = append(repo.grants, aclRepoGrant{row: grant, subject: subject, expiresMs: grant.GetExpires()})
		}
		for j, share := range row.GetShares() {
			subject, err := aclRowsId(share.GetSubject(), fmt.Sprintf("%s.shares[%d].subject", field, j))
			if err != nil {
				return err
			}
			repo.shares = append(repo.shares, aclRepoShare{row: share, subject: subject, expiresMs: share.GetExpires()})
		}
		self.repos[repoId] = repo
	}
	return nil
}

// Indexes the Genesis's config repo: the row the rows hold for it, which must be of kind config, or else the state's
// own row (the file's header, QD-719). A view with no Genesis, or one naming no config repo, indexes none.
func (self *AclState) indexConfigRepo() error {
	genesis := self.view.Genesis()
	if genesis == nil {
		return nil
	}
	if ownerId, err := IdFromBytes(genesis.GetOwnerSidecarId()); err == nil {
		self.genesisOwnerId = ownerId
	}
	configRepoId, err := IdFromBytes(genesis.GetConfigRepoId())
	if err != nil || configRepoId == (Id{}) {
		return nil
	}
	self.configRepoId = configRepoId
	if repo, found := self.repos[configRepoId]; found {
		if repo.kind != protocol.RepoKind_REPO_KIND_CONFIG {
			return aclRowsRefusal("repos give the config repo another kind")
		}
		return nil
	}
	self.repos[configRepoId] = &aclRepoState{
		row: &protocol.AclRepo{
			RepoId:          configRepoId.Bytes(),
			Kind:            protocol.RepoKind_REPO_KIND_CONFIG,
			HoldersShrunkAt: self.pin.GetVersion(),
		},
		kind:     protocol.RepoKind_REPO_KIND_CONFIG,
		admins:   map[Id]bool{},
		revoked:  map[Id]bool{},
		consents: map[Id]bool{},
	}
	return nil
}

// Indexes every sidecar the view holds: classes it, gathers its atoms and builds its rule sets.
func (self *AclState) indexSidecars(sidecarListedAtoms map[Id][]int32) {
	sidecarIds := slices.Clone(self.view.SidecarIds())
	slices.SortFunc(sidecarIds, Id.Cmp)
	sidecarIds = slices.Compact(sidecarIds)
	self.sidecars = make([]aclSidecarState, 0, len(sidecarIds))
	for _, sidecarId := range sidecarIds {
		facts := self.view.Sidecar(sidecarId)
		if facts == nil || facts.Row == nil {
			continue
		}
		self.sidecarIndexes[sidecarId] = int32(len(self.sidecars))
		self.sidecars = append(self.sidecars, self.newSidecarState(sidecarId, facts, sidecarListedAtoms[sidecarId]))
	}

	newBits := func() aclBits {
		return make(aclBits, self.ruleWordCount)
	}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		sidecar.srcRules = newBits()
		sidecar.reachRules = newBits()
		sidecar.listenRules = newBits()
		if !sidecar.valid {
			continue
		}
		for _, atomIndex := range sidecar.atoms {
			sidecar.srcRules.union(self.srcRulesByAtom[atomIndex])
		}
		if sidecar.ephemeral {
			sidecar.ceilingRules = newBits()
			for _, atomIndex := range sidecar.atoms {
				if self.namesSidecarDirectly(sidecar, atomIndex) {
					sidecar.ceilingRules.union(self.srcRulesByAtom[atomIndex])
				}
			}
		}
		for j := range self.rules {
			rule := &self.rules[j]
			if rule.actions&aclReachActions != 0 && self.sidecarIsSubjectTarget(sidecar, rule) {
				sidecar.reachRules.set(rule.index)
			}
			if rule.allows(protocol.AclAction_ACL_ACTION_LISTEN) && 0 < len(rule.sockets) && sidecar.srcRules.has(rule.index) {
				sidecar.listenRules.set(rule.index)
			}
		}
	}
}

// Classes one admission and gathers what a check reads of it.
func (self *AclState) newSidecarState(sidecarId Id, facts *AclSidecar, listedAtoms []int32) aclSidecarState {
	row := facts.Row
	sidecar := aclSidecarState{
		id:           sidecarId,
		facts:        facts,
		revoked:      row.GetRevokedAt() != 0,
		parked:       self.view.Parked(sidecarId),
		suspended:    self.suspended[sidecarId],
		notAfterMs:   row.GetNotAfter(),
		tagged:       0 < len(facts.TagIds),
		ephemeral:    facts.Ephemeral,
		readOnly:     facts.hasCapability(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY),
		memberId:     facts.MemberId,
		configWriter: self.view.IsConfigWriter(sidecarId),
	}
	// an admission names a member or tags (§7.9's SidecarAdmit), never both and never neither
	sidecar.valid = sidecar.tagged != (facts.MemberId != Id{})
	if !sidecar.valid {
		sidecar.class = AclSubjectClassOther
		return sidecar
	}
	switch {
	case sidecar.ephemeral:
		sidecar.class = AclSubjectClassEphemeral
	case sidecar.tagged:
		sidecar.class = AclSubjectClassTagged
	default:
		sidecar.class = AclSubjectClassMemberDevice
	}
	atoms := slices.Clone(listedAtoms)
	sidecar.autogroups = aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR) |
		aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK)
	if sidecar.tagged {
		// a tagged subject takes its tags and no user atom (§8.4)
		sidecar.autogroups |= aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED)
		// a tag no row or rule names grants nothing, so it takes no index
		for _, tagId := range facts.TagIds {
			if index, found := self.atomIndexes[tagId]; found {
				atoms = append(atoms, index)
			}
		}
		sidecar.owner, sidecar.hasOwner = self.view.Sponsor(sidecarId)
	} else {
		member := self.view.Member(facts.MemberId)
		sidecar.memberGone = member == nil
		sidecar.owner = facts.MemberId
		sidecar.hasOwner = true
		// untagged sidecars are autogroup:member, ephemeral ones too (plan-ACL-small-readings #8), and
		// only untagged ephemeral ones autogroup:ephemeral (§8.4)
		sidecar.autogroups |= aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
		if sidecar.ephemeral {
			sidecar.autogroups |= aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL)
		}
		sidecar.autogroups |= aclRoleAutogroups(member.GetRole())
		atoms = append(atoms, self.memberAtoms[facts.MemberId]...)
	}
	for autogroup := protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER; autogroup <= aclAutogroupMax; autogroup += 1 {
		if sidecar.autogroups&aclAutogroupBit(autogroup) != 0 {
			atoms = append(atoms, int32(autogroup))
		}
	}
	slices.Sort(atoms)
	sidecar.atoms = slices.Compact(atoms)
	return sidecar
}

// Whether a rule's subject targets name the sidecar as a destination: an atom it holds, or its id.
// autogroup:self depends on the source, so a check reads it, never this.
func (self *AclState) sidecarIsSubjectTarget(sidecar *aclSidecarState, rule *aclRule) bool {
	for _, atomIndex := range rule.atomTargets {
		if _, found := slices.BinarySearch(sidecar.atoms, atomIndex); found {
			return true
		}
	}
	return slices.Contains(rule.sidecarTargets, sidecar.id)
}

// The state's (n, A_n).
func (self *AclState) Pin() *bridge.AuthPin {
	return self.pin
}

// The rows this state was built from, which a caller must not change.
func (self *AclState) Rows() *protocol.AclRows {
	return self.rows
}

// Whether the rows hold a network's document rather than the implicit one (owner decisions 50, 105).
func (self *AclState) HasDocument() bool {
	return self.rows.GetHasDocument()
}

// A repo's folded row, or nil when the state holds no such repo. The config repo's is the state's own where the
// rows hold none (QD-719). The caller must not change it.
func (self *AclState) Repo(repoId Id) *protocol.AclRepo {
	if repo, found := self.repos[repoId]; found {
		return repo.row
	}
	return nil
}

// Every repo the state holds, sorted: the rows' repos and the config repo, which the rows may not hold (QD-719). What
// lists a network's repos reads this, not Rows.
func (self *AclState) RepoIds() []Id {
	repoIds := make([]Id, 0, len(self.repos))
	for repoId := range self.repos {
		repoIds = append(repoIds, repoId)
	}
	slices.SortFunc(repoIds, Id.Cmp)
	return repoIds
}

// The network's config repo, the Genesis's, and false for a view with no Genesis.
func (self *AclState) ConfigRepoId() (Id, bool) {
	return self.configRepoId, self.configRepoId != (Id{})
}

// Whether an active Suspend names the subject (plan-ACL-folded-grant-state #1), for §7.9's leaves rule.
func (self *AclState) Suspended(subjectId Id) bool {
	return self.suspended[subjectId]
}

// The indexed sidecar, or nil.
func (self *AclState) sidecarState(sidecarId Id) *aclSidecarState {
	if index, found := self.sidecarIndexes[sidecarId]; found {
		return &self.sidecars[index]
	}
	return nil
}

// The number of rules set in a bitset, for tests.
func (self aclBits) count() int {
	total := 0
	for _, word := range self {
		total += bits.OnesCount64(word)
	}
	return total
}
