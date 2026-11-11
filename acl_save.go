//go:build !sidecar_http && !ios_extension

// §8.8's Saving on a config writer's device (D-ACL-1, D-ACL-9, R-ACL-10): validate, compile, test, preview, sign, in
// that order, then hand the head to TEAM's writer, which saves it to the config repo and publishes its base under §7.9's
// fold rules. Nothing here files a statement or posts a base.
//
//	tables    every tag and group the document names keeps the atom id the head holds for its name, and a new name
//	          draws 16 random bytes, redrawn while the first 15 are zero (plan-ACL-atom-and-rule-ids #1); a name the
//	          document no longer names leaves the table, so a tag made again gets a new id; every rule keeps the id
//	          its canonical form's SHA-256 holds and a new form draws one (#3); resolve holds one row per user:,
//	          network: and client: selector the document names and no other, each from the save's resolver, else the
//	          head's own row (plan-ACL-selector-resolution)
//	validate  ValidateAclPolicy: §8.8's Saving list, every refusal at once
//	compile   CompileAcl and CompileAclLocal over the head the save makes and the writer's state, and the rows'
//	          limits (AclRowsCheckLimits, the 4 MiB of ProjectionRows)
//	test      AclPolicyTestRun: a failing test blocks the head, and the head in force stays (D-ACL-9)
//	preview   each repo's readers added and removed, each repo that cannot seat a reader (§8.12, AclUnseated), each
//	          new or changed resolve row with the member's role and devices, and the rules added and removed
//	sign      AclSave, only from a person's confirmation (D-CORE-13), and only while the writer's head still holds the
//	          policy and tables the preview was made on, so the person signs what they saw
//
// A rollback is a save of an older source: a new head at the next config_version, never a lower one (I-16). The change
// audit is the config repo's signed head history, which AclLog lists from the verified log (QD-555).
//
// Not on the page Worker's leg, which writes no config head. Ids are drawn from crypto/rand, which no test hook covers:
// they are opaque ids, not keys.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The writer's config head no longer holds the policy and tables the save was previewed on: preview again.
	ErrAclSaveStale = errors.New("acl save: the config head moved since the preview")
	// The save was not confirmed by a person, or named another preview than the one planned now.
	ErrAclSaveUnconfirmed = errors.New("acl save: no confirmed preview")
)

// The head files a save writes.
var aclSaveHeadPaths = []string{
	ConfigHeadPolicyPath, ConfigHeadTagsPath, ConfigHeadGroupsPath, ConfigHeadRulesPath, ConfigHeadResolvePath,
}

// The head files a preview stands on: what a save writes, and the labels and K_sock its compile reads.
var aclSaveBasePaths = []string{
	ConfigHeadPolicyPath, ConfigHeadTagsPath, ConfigHeadGroupsPath, ConfigHeadRulesPath, ConfigHeadResolvePath,
	ConfigHeadLabelsPath, ConfigHeadSocketKeyPath,
}

// What resolves a document's selectors at save, beside the head's resolve file (plan-ACL-selector-resolution): the
// writer's own invite records and GET /network/members for an email, §12's labels for a network, a dual-signed binding
// the writer verified for a client. An answer is a proposal, which the preview shows and the person confirms. Each
// answers false for what it does not know.
type AclSaveResolver interface {
	ResolveMember(ctx context.Context, email string) (Id, bool, error)
	ResolveNetwork(ctx context.Context, text string) (Id, bool, error)
	// The sidecar the client's binding names; bound false for a client with none, which stays a literal client id.
	ResolveClient(ctx context.Context, clientId Id) (sidecarId Id, bound bool, err error)
}

// What one save plans from.
type AclSaveInput struct {
	// The document's source.
	Policy []byte
	// The writer's config head, whose tables keep their ids.
	Head *ConfigHead
	// The writer's newest verified state: the members and sidecars the atoms expand over, the log's acl statements,
	// and what the preview compares with.
	State *ConfigState
	// The tier's acl_* limits; nil judges the format alone.
	Limits *AclLimits
	// Nil resolves from the head's own rows alone.
	Resolver AclSaveResolver
	// §12's ResolveNetworkLabel for validation; nil before M5's labels.
	ResolveNetworkLabel func(text string) (Id, bool)
	// The network's Team scopes for validation (ACL-M6-01); nil before M6's, and every scope host refuses.
	ResolveScope func(label string) (AclScope, bool)
	// The leaves of the data repos the writer holds trees for, for the unseated preview; nil takes the seating rule.
	LeavesByRepo map[Id][]Id
	// Where new ids come from; nil is crypto/rand.
	Random io.Reader
	// The time the tests and the preview judge at.
	Now time.Time
}

// One save's plan: the head it writes and everything the person previews before signing.
type AclSavePlan struct {
	// The head the plan stands on, and the head it makes from it.
	BaseHead *ConfigHead
	Head     *ConfigHead
	Policy   *AclPolicy
	Rows     *protocol.AclRows
	Local    *AclLocalPolicy
	Tests    *AclPolicyTestReport
	Preview  *AclSavePreview
	// SHA-256 over the base's acl files and the planned policy and resolve rows, which a confirmed save names so it signs
	// what was seen.
	Digest [sha256.Size]byte
}

// What the person sees before signing (§8.8's Saving).
type AclSavePreview struct {
	// Each repo whose readers change, by repo.
	Readers []AclSaveReaderChange
	// Each data repo that cannot seat a reader (§8.12).
	Unseated []AclUnseatedRepo
	// Each new or changed resolve row.
	Resolutions []AclSaveResolution
	// The rules and requests rules added and removed, by id.
	RulesAdded   []Id
	RulesRemoved []Id
}

// One repo's readers before and after.
type AclSaveReaderChange struct {
	RepoId  Id
	Added   []Id
	Removed []Id
}

// One new or changed resolve row, with what it names in the state.
type AclSaveResolution struct {
	// "user", "network" or "client".
	Kind string
	// The email or network text the document writes, or the client id; local to the person's device.
	Text string
	Id   Id
	// The id the head held before, zero for a new row.
	PreviousId Id
	// A user's role and devices in the state; MemberUnknown when the state holds no such member.
	Role          bridge.MemberRole
	SidecarIds    []Id
	MemberUnknown bool
}

// Draws a 16-byte id, redrawn while its first 15 bytes are zero so it never takes an autogroup's form.
func aclSaveDrawId(random io.Reader) (Id, error) {
	for {
		id := Id{}
		if _, err := io.ReadFull(random, id[:]); err != nil {
			return Id{}, err
		}
		if !aclAtomHasAutogroupForm(id) {
			return id, nil
		}
	}
}

// The names a document's selectors use, by kind, each once and sorted.
type aclSaveNames struct {
	tags     map[string]bool
	groups   map[string]bool
	users    map[string]bool
	networks map[string]bool
	clients  map[Id]bool
}

// Every name the document's selectors and resources hold.
func aclSaveNamesOf(policy *AclPolicy) *aclSaveNames {
	names := &aclSaveNames{tags: map[string]bool{}, groups: map[string]bool{}, users: map[string]bool{}, networks: map[string]bool{}, clients: map[Id]bool{}}
	add := func(selector AclSelector) {
		switch selector.Kind {
		case AclSelectorTag:
			names.tags[selector.Name] = true
		case AclSelectorGroup:
			names.groups[selector.Name] = true
		case AclSelectorUser:
			names.users[selector.Name] = true
		case AclSelectorNetwork:
			if selector.Name != "*" {
				names.networks[selector.Name] = true
			}
		case AclSelectorClient:
			names.clients[selector.Id] = true
		}
	}
	addResources := func(resources []AclResource) {
		for _, resource := range resources {
			if resource.Kind == AclResourceSubject {
				add(resource.Subject)
			}
		}
	}
	for _, group := range policy.Groups {
		add(group.Group)
		for _, member := range group.Members {
			add(member)
		}
	}
	for _, tagOwner := range policy.TagOwners {
		add(tagOwner.Tag)
		for _, owner := range tagOwner.Owners {
			add(owner)
		}
	}
	for _, grant := range policy.Grants {
		for _, selector := range slices.Concat(grant.Src, grant.Via) {
			add(selector)
		}
		addResources(grant.Dst)
	}
	for _, request := range policy.Requests {
		for _, selector := range slices.Concat(request.Src, request.Approver) {
			add(selector)
		}
		addResources(request.Dst)
	}
	if policy.Audit != nil {
		add(policy.Audit.Reader)
	}
	for _, test := range policy.Tests {
		add(test.Src)
		for _, check := range slices.Concat(test.Accept, test.Deny) {
			if check.Resource.Kind == AclResourceSubject {
				add(check.Resource.Subject)
			}
		}
	}
	return names
}

// A head file decoded into message, empty when the head holds none.
func aclSaveDecode(head *ConfigHead, path string, message proto.Message) error {
	if data := head.File(path); data != nil {
		if err := proto.Unmarshal(data, message); err != nil {
			return fmt.Errorf("%w: the head's %s file", ErrAclCompile, path)
		}
	}
	return nil
}

// A message as its head file's bytes, deterministically.
func aclSaveEncode(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// The atom table a document's names make from the head's: each name its id, a new one drawn, in name order.
func aclSaveAtomTable(previous *protocol.ConfigAtomTable, names map[string]bool, random io.Reader) (*protocol.ConfigAtomTable, error) {
	held := map[string][]byte{}
	for _, row := range previous.GetAtoms() {
		if id, err := IdFromBytes(row.GetAtomId()); err == nil && !aclAtomHasAutogroupForm(id) {
			held[row.GetName()] = row.GetAtomId()
		}
	}
	table := &protocol.ConfigAtomTable{}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		atomId := held[name]
		if atomId == nil {
			drawn, err := aclSaveDrawId(random)
			if err != nil {
				return nil, err
			}
			atomId = drawn.Bytes()
		}
		table.Atoms = append(table.Atoms, &protocol.ConfigAtomName{Name: name, AtomId: bytes.Clone(atomId)})
	}
	return table, nil
}

// The rules table a document's rules make from the head's: each canonical form its id, a new form drawing one, in
// key order.
func aclSaveRuleTable(previous *protocol.ConfigRuleTable, policy *AclPolicy, random io.Reader) (*protocol.ConfigRuleTable, error) {
	held := map[[sha256.Size]byte][]byte{}
	for _, row := range previous.GetRules() {
		if len(row.GetCanonicalSha256()) == sha256.Size && len(row.GetRuleId()) == aclAtomByteCount {
			held[[sha256.Size]byte(row.GetCanonicalSha256())] = row.GetRuleId()
		}
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		return nil, err
	}
	canonicals := map[[sha256.Size]byte]bool{}
	for _, key := range keys {
		canonicals[key.CanonicalSha256] = true
	}
	table := &protocol.ConfigRuleTable{}
	for _, canonical := range slices.SortedFunc(maps.Keys(canonicals), func(a [sha256.Size]byte, b [sha256.Size]byte) int { return bytes.Compare(a[:], b[:]) }) {
		ruleId := held[canonical]
		if ruleId == nil {
			drawn, err := aclSaveDrawId(random)
			if err != nil {
				return nil, err
			}
			ruleId = drawn.Bytes()
		}
		table.Rules = append(table.Rules, &protocol.ConfigRuleId{CanonicalSha256: bytes.Clone(canonical[:]), RuleId: bytes.Clone(ruleId)})
	}
	return table, nil
}

// The resolve file a document's selectors make: each from the resolver, else the head's row; a name neither knows has
// no row, which validation then refuses.
func aclSaveResolution(ctx context.Context, previous *protocol.ConfigResolution, names *aclSaveNames, resolver AclSaveResolver) (*protocol.ConfigResolution, error) {
	resolution := &protocol.ConfigResolution{}
	heldMembers := map[string][]byte{}
	for _, row := range previous.GetMembers() {
		heldMembers[row.GetEmail()] = row.GetMemberId()
	}
	for _, email := range slices.Sorted(maps.Keys(names.users)) {
		memberId := heldMembers[email]
		if resolver != nil {
			resolved, found, err := resolver.ResolveMember(ctx, email)
			if err != nil {
				return nil, err
			}
			if found {
				memberId = resolved.Bytes()
			}
		}
		if memberId != nil {
			resolution.Members = append(resolution.Members, &protocol.ConfigMemberResolution{Email: email, MemberId: bytes.Clone(memberId)})
		}
	}
	heldNetworks := map[string][]byte{}
	for _, row := range previous.GetNetworks() {
		heldNetworks[row.GetText()] = row.GetNetworkId()
	}
	for _, text := range slices.Sorted(maps.Keys(names.networks)) {
		networkId := heldNetworks[text]
		if resolver != nil {
			resolved, found, err := resolver.ResolveNetwork(ctx, text)
			if err != nil {
				return nil, err
			}
			if found {
				networkId = resolved.Bytes()
			}
		}
		if networkId != nil {
			resolution.Networks = append(resolution.Networks, &protocol.ConfigNetworkResolution{Text: text, NetworkId: bytes.Clone(networkId)})
		}
	}
	heldClients := map[Id][]byte{}
	for _, row := range previous.GetClients() {
		if clientId, err := IdFromBytes(row.GetClientId()); err == nil {
			heldClients[clientId] = row.GetSidecarId()
		}
	}
	for _, clientId := range slices.SortedFunc(maps.Keys(names.clients), Id.Cmp) {
		row := &protocol.ConfigClientResolution{ClientId: clientId.Bytes(), SidecarId: bytes.Clone(heldClients[clientId])}
		if resolver != nil {
			sidecarId, bound, err := resolver.ResolveClient(ctx, clientId)
			if err != nil {
				return nil, err
			}
			if bound {
				row.SidecarId = sidecarId.Bytes()
			}
		}
		resolution.Clients = append(resolution.Clients, row)
	}
	return resolution, nil
}

// Plans one save: the tables, validation, the compile and its limits, the tests and the preview. An error is a document
// the writer may not save at all; failing tests come back in the plan, and AclSave refuses them.
func PlanAclSave(ctx context.Context, input *AclSaveInput) (*AclSavePlan, error) {
	if input == nil || input.Head == nil || input.State == nil || input.Policy == nil {
		return nil, fmt.Errorf("%w: no document, head or state", ErrAclCompile)
	}
	random := input.Random
	if random == nil {
		random = cryptorand.Reader
	}
	policy, err := ParseAclPolicy(input.Policy)
	if err != nil {
		return nil, err
	}

	previousTags, previousGroups := &protocol.ConfigAtomTable{}, &protocol.ConfigAtomTable{}
	previousRules, previousResolve := &protocol.ConfigRuleTable{}, &protocol.ConfigResolution{}
	for path, message := range map[string]proto.Message{
		ConfigHeadTagsPath: previousTags, ConfigHeadGroupsPath: previousGroups,
		ConfigHeadRulesPath: previousRules, ConfigHeadResolvePath: previousResolve,
	} {
		if err := aclSaveDecode(input.Head, path, message); err != nil {
			return nil, err
		}
	}
	names := aclSaveNamesOf(policy)
	tags, err := aclSaveAtomTable(previousTags, names.tags, random)
	if err != nil {
		return nil, err
	}
	groups, err := aclSaveAtomTable(previousGroups, names.groups, random)
	if err != nil {
		return nil, err
	}
	rules, err := aclSaveRuleTable(previousRules, policy, random)
	if err != nil {
		return nil, err
	}
	resolve, err := aclSaveResolution(ctx, previousResolve, names, input.Resolver)
	if err != nil {
		return nil, err
	}

	head := input.Head
	for path, message := range map[string]proto.Message{
		ConfigHeadTagsPath: tags, ConfigHeadGroupsPath: groups, ConfigHeadRulesPath: rules, ConfigHeadResolvePath: resolve,
	} {
		data, err := aclSaveEncode(message)
		if err != nil {
			return nil, err
		}
		if head, err = head.WithFile(path, data); err != nil {
			return nil, err
		}
	}
	if head, err = head.WithFile(ConfigHeadPolicyPath, input.Policy); err != nil {
		return nil, err
	}

	compileRows := ConfigCompileRowsOf(input.State)
	compile, err := NewAclCompileInput(head, compileRows)
	if err != nil {
		return nil, err
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: compile, Limits: input.Limits, ResolveNetworkLabel: input.ResolveNetworkLabel,
		ResolveScope: input.ResolveScope}); err != nil {
		return nil, err
	}
	rows, err := CompileAcl(compile)
	if err != nil {
		return nil, err
	}
	local, err := CompileAclLocal(compile)
	if err != nil {
		return nil, err
	}
	projection, err := CompileProjectionRows(head, compileRows)
	if err != nil {
		return nil, err
	}
	if err := AclRowsCheckLimits(rows, len(projection), input.Limits); err != nil {
		return nil, err
	}
	tests, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: compile, View: input.State, Now: input.Now})
	if err != nil {
		return nil, err
	}
	plan := &AclSavePlan{BaseHead: input.Head, Head: head, Policy: policy, Rows: rows, Local: local, Tests: tests}
	if plan.Preview, err = aclSavePreview(input, rows, previousResolve, resolve); err != nil {
		return nil, err
	}
	plan.Digest = aclSaveDigest(input.Head, head)
	return plan, nil
}

// SHA-256 over what a person previews and signs: the base head's acl files, and the planned head's policy and resolve
// rows, each path and length-prefixed, in a fixed order. The ids a save draws for new names are left out, since each
// plan draws its own and none changes what the head means.
func aclSaveDigest(base *ConfigHead, planned *ConfigHead) [sha256.Size]byte {
	hash := sha256.New()
	write := func(head *ConfigHead, path string) {
		data := head.File(path)
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		length := uint64(len(data))
		if data == nil {
			length = ^uint64(0)
		}
		for shift := 56; 0 <= shift; shift -= 8 {
			hash.Write([]byte{byte(length >> shift)})
		}
		hash.Write(data)
	}
	hash.Write([]byte("urnetwork-sidecar-v1/acl-save\x00"))
	for _, path := range aclSaveBasePaths {
		write(base, path)
	}
	for _, path := range []string{ConfigHeadPolicyPath, ConfigHeadResolvePath} {
		write(planned, path)
	}
	return [sha256.Size]byte(hash.Sum(nil))
}

// The preview: readers before and after each repo, unseatable repos, resolve rows new or changed, rules added and
// removed.
func aclSavePreview(input *AclSaveInput, rows *protocol.AclRows, previousResolve *protocol.ConfigResolution, resolve *protocol.ConfigResolution) (*AclSavePreview, error) {
	preview := &AclSavePreview{}
	before, err := input.State.Acl()
	if err != nil {
		return nil, err
	}
	after, err := NewAclState(rows, input.State)
	if err != nil {
		return nil, err
	}
	repoIds := map[Id]bool{}
	for _, repos := range [][]*protocol.AclRepo{before.Rows().GetRepos(), rows.GetRepos()} {
		for _, repo := range repos {
			if repoId, err := IdFromBytes(repo.GetRepoId()); err == nil {
				repoIds[repoId] = true
			}
		}
	}
	for _, repoId := range slices.SortedFunc(maps.Keys(repoIds), Id.Cmp) {
		readersBefore, readersAfter := before.RepoReaders(repoId, input.Now), after.RepoReaders(repoId, input.Now)
		change := AclSaveReaderChange{RepoId: repoId}
		for _, reader := range readersAfter {
			if !slices.Contains(readersBefore, reader) {
				change.Added = append(change.Added, reader)
			}
		}
		for _, reader := range readersBefore {
			if !slices.Contains(readersAfter, reader) {
				change.Removed = append(change.Removed, reader)
			}
		}
		if 0 < len(change.Added) || 0 < len(change.Removed) {
			preview.Readers = append(preview.Readers, change)
		}
	}
	preview.Unseated = AclUnseated(after, input.LeavesByRepo, input.Now)

	previousMembers := map[string]Id{}
	for _, row := range previousResolve.GetMembers() {
		if memberId, err := IdFromBytes(row.GetMemberId()); err == nil {
			previousMembers[row.GetEmail()] = memberId
		}
	}
	for _, row := range resolve.GetMembers() {
		memberId, err := IdFromBytes(row.GetMemberId())
		if err != nil || previousMembers[row.GetEmail()] == memberId {
			continue
		}
		resolution := AclSaveResolution{Kind: "user", Text: row.GetEmail(), Id: memberId, PreviousId: previousMembers[row.GetEmail()]}
		if member := input.State.Member(memberId); member != nil {
			resolution.Role = member.GetRole()
			for _, sidecarId := range input.State.SidecarIds() {
				if admission := input.State.Sidecar(sidecarId); admission != nil && admission.MemberId == memberId && admission.Row.GetRevokedAt() == 0 {
					resolution.SidecarIds = append(resolution.SidecarIds, sidecarId)
				}
			}
			slices.SortFunc(resolution.SidecarIds, Id.Cmp)
		} else {
			resolution.MemberUnknown = true
		}
		preview.Resolutions = append(preview.Resolutions, resolution)
	}
	previousNetworks := map[string]Id{}
	for _, row := range previousResolve.GetNetworks() {
		if networkId, err := IdFromBytes(row.GetNetworkId()); err == nil {
			previousNetworks[row.GetText()] = networkId
		}
	}
	for _, row := range resolve.GetNetworks() {
		if networkId, err := IdFromBytes(row.GetNetworkId()); err == nil && previousNetworks[row.GetText()] != networkId {
			preview.Resolutions = append(preview.Resolutions, AclSaveResolution{Kind: "network", Text: row.GetText(), Id: networkId, PreviousId: previousNetworks[row.GetText()]})
		}
	}

	ruleIds := func(rows *protocol.AclRows) map[Id]bool {
		ids := map[Id]bool{}
		for _, rule := range rows.GetRules() {
			if ruleId, err := IdFromBytes(rule.GetRuleId()); err == nil && len(rule.GetSourceRuleId()) == 0 {
				ids[ruleId] = true
			}
		}
		for _, request := range rows.GetRequests() {
			if ruleId, err := IdFromBytes(request.GetRuleId()); err == nil {
				ids[ruleId] = true
			}
		}
		return ids
	}
	beforeIds, afterIds := ruleIds(before.Rows()), ruleIds(rows)
	for _, ruleId := range slices.SortedFunc(maps.Keys(afterIds), Id.Cmp) {
		if !beforeIds[ruleId] {
			preview.RulesAdded = append(preview.RulesAdded, ruleId)
		}
	}
	for _, ruleId := range slices.SortedFunc(maps.Keys(beforeIds), Id.Cmp) {
		if !afterIds[ruleId] {
			preview.RulesRemoved = append(preview.RulesRemoved, ruleId)
		}
	}
	return preview, nil
}

// Hands a planned head to the writer, which saves it and publishes its base: refused while a test fails, so the head
// in force stays (D-ACL-9), and while the writer's head no longer holds what the plan stood on (ErrAclSaveStale).
// Answers the base's pin.
func AclSave(ctx context.Context, writer *ConfigWriter, plan *AclSavePlan) (*bridge.AuthPin, error) {
	if writer == nil || plan == nil {
		return nil, ErrAclSaveUnconfirmed
	}
	if err := plan.Tests.Err(); err != nil {
		return nil, err
	}
	return writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		for _, path := range aclSaveBasePaths {
			if !bytes.Equal(head.File(path), plan.BaseHead.File(path)) {
				return nil, fmt.Errorf("%w: its %s file changed", ErrAclSaveStale, path)
			}
		}
		next := head
		for _, path := range aclSaveHeadPaths {
			var err error
			if next, err = next.WithFile(path, plan.Head.File(path)); err != nil {
				return nil, err
			}
		}
		return next, nil
	})
}

// One config head the verified log put in force: the base that first named its config_version, who signed that base
// and when api sequenced it (QD-555's change audit).
type AclLogEntry struct {
	ConfigVersion uint64
	// The base's position and its time_ms.
	N      uint64
	TimeMs int64
	// The config writer that signed the base.
	SignerSidecarId Id
}

// The heads the state's log keeps the bases of, oldest first: the change audit over the log's retained window.
func AclLog(state *ConfigState) []AclLogEntry {
	entries := []AclLogEntry{}
	if state == nil || state.history == nil {
		return entries
	}
	view := state.history.view.Load()
	if view == nil {
		return entries
	}
	seen := map[uint64]bool{}
	for n := max(view.from, 1); n <= state.n; n += 1 {
		kept := state.keptEntryAt(n)
		if kept == nil || kept.entry.GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		signed, header, err := configParseBase(kept.entry)
		if err != nil || seen[header.GetConfigVersion()] {
			continue
		}
		signer, err := configBaseSigner(signed)
		if err != nil {
			continue
		}
		seen[header.GetConfigVersion()] = true
		entries = append(entries, AclLogEntry{ConfigVersion: header.GetConfigVersion(), N: n, TimeMs: kept.entry.GetTimeMs(), SignerSidecarId: signer})
	}
	return entries
}

// This network's config writer, its verified state and its current head: what a save plans on.
func (self *Sidecar) aclSaveContext(ctx context.Context) (*ConfigWriter, *ConfigState, *ConfigHead, error) {
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return nil, nil, nil, ErrAgentPlanNoState
	}
	writer := authority.client.Writer()
	if writer == nil {
		return nil, nil, nil, fmt.Errorf("%w: no config writer runs for this network on this device", ErrConfigWriterNotWriter)
	}
	state := authority.client.State()
	if state == nil {
		return nil, nil, nil, ErrAgentPlanNoState
	}
	if err := CheckConfigHeadWriter(state, writer.args.SidecarId); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrConfigWriterNotWriter, err)
	}
	head, _, _, err := writer.args.Heads.CurrentConfigHead(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if head == nil {
		return nil, nil, nil, errors.New("the config repo holds no head yet")
	}
	return writer, state, head, nil
}

// A save's plan on this device's config writer, for `ur acl push`'s preview. Reading only; any origin may ask.
func (self *Sidecar) PlanAclPolicy(ctx context.Context, source []byte) (*AclSavePlan, error) {
	_, state, head, err := self.aclSaveContext(ctx)
	if err != nil {
		return nil, err
	}
	return PlanAclSave(ctx, &AclSaveInput{Policy: source, Head: head, State: state, Now: time.Now()})
}

// Saves a policy as the person confirmed its preview (D-CORE-13): never from MCP, a hook or an unconfirmed call, and
// only when digest is the plan's made now, so the head signed is the one previewed. Answers the base's pin.
func (self *Sidecar) SaveAclPolicy(ctx context.Context, source []byte, digest [sha256.Size]byte, origin SidecarActOrigin) (*bridge.AuthPin, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	writer, state, head, err := self.aclSaveContext(ctx)
	if err != nil {
		return nil, err
	}
	plan, err := PlanAclSave(ctx, &AclSaveInput{Policy: source, Head: head, State: state, Now: time.Now()})
	if err != nil {
		return nil, err
	}
	if plan.Digest != digest {
		return nil, fmt.Errorf("%w: the plan now differs from the preview", ErrAclSaveUnconfirmed)
	}
	return AclSave(ctx, writer, plan)
}

// The document's tests over this device's last verified state, as `ur acl test` runs them with no network: a config
// writer's plan, validation included; elsewhere the base's head as this device last verified it, when it can read it,
// over the state; and with neither, the document's own world (AclPolicyTestOver). Reading only.
func (self *Sidecar) TestAclPolicy(ctx context.Context, source []byte) (*AclPolicyTestReport, error) {
	if _, state, head, err := self.aclSaveContext(ctx); err == nil {
		plan, err := PlanAclSave(ctx, &AclSaveInput{Policy: source, Head: head, State: state, Now: time.Now()})
		if err != nil {
			return nil, err
		}
		return plan.Tests, nil
	}
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok {
		return AclPolicyTestOver(source, nil, nil, time.Now())
	}
	state := authority.client.State()
	var head *ConfigHead
	if base := state.Base(); base != nil && authority.client.args.Heads != nil {
		if read, err := authority.client.args.Heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256()); err == nil {
			head = read
		}
	}
	return AclPolicyTestOver(source, head, state, time.Now())
}

// The change audit over this device's verified log (QD-555).
func (self *Sidecar) AclLog() ([]AclLogEntry, error) {
	state, err := self.configState()
	if err != nil {
		return nil, err
	}
	return AclLog(state), nil
}

// A document's tests over a head's tables and a state, either of which may be nil: a name the head does not hold takes
// a provisional id, so a test naming a user or a tag the state does not hold fails, and with no state the document's
// own world stands in, every user it names a member with no device, so its tests check the document against itself.
// Validation is the writer's (PlanAclSave): this runs the tests alone.
func AclPolicyTestOver(source []byte, head *ConfigHead, state *ConfigState, now time.Time) (*AclPolicyTestReport, error) {
	policy, err := ParseAclPolicy(source)
	if err != nil {
		return nil, err
	}
	names := aclSaveNamesOf(policy)
	provisional := func(kind string, name string) Id {
		return aclTestProbeId("provisional " + kind + " " + name)
	}
	previousTags, previousGroups := &protocol.ConfigAtomTable{}, &protocol.ConfigAtomTable{}
	previousRules, previousResolve := &protocol.ConfigRuleTable{}, &protocol.ConfigResolution{}
	input := &AclCompileInput{Policy: source, Labels: &protocol.ConfigLabelTable{}, HeadTimeMs: now.UnixMilli(), Statements: &protocol.AclRows{}}
	if head != nil {
		for path, message := range map[string]proto.Message{
			ConfigHeadTagsPath: previousTags, ConfigHeadGroupsPath: previousGroups, ConfigHeadRulesPath: previousRules,
			ConfigHeadResolvePath: previousResolve, ConfigHeadLabelsPath: input.Labels,
		} {
			if err := aclSaveDecode(head, path, message); err != nil {
				return nil, err
			}
		}
		if data := head.File(ConfigHeadSocketKeyPath); data != nil {
			input.SocketKey = &protocol.SocketKeyFile{}
			if err := proto.Unmarshal(data, input.SocketKey); err != nil {
				return nil, fmt.Errorf("%w: the head's socket key", ErrAclCompile)
			}
		}
	}
	atoms := func(previous *protocol.ConfigAtomTable, names map[string]bool, kind string) *protocol.ConfigAtomTable {
		held := map[string][]byte{}
		for _, row := range previous.GetAtoms() {
			held[row.GetName()] = row.GetAtomId()
		}
		table := &protocol.ConfigAtomTable{}
		for _, name := range slices.Sorted(maps.Keys(names)) {
			atomId := held[name]
			if atomId == nil {
				atomId = provisional(kind, name).Bytes()
			}
			table.Atoms = append(table.Atoms, &protocol.ConfigAtomName{Name: name, AtomId: bytes.Clone(atomId)})
		}
		return table
	}
	input.Tags, input.Groups = atoms(previousTags, names.tags, "tag"), atoms(previousGroups, names.groups, "group")
	heldRules := map[[sha256.Size]byte][]byte{}
	for _, row := range previousRules.GetRules() {
		if len(row.GetCanonicalSha256()) == sha256.Size {
			heldRules[[sha256.Size]byte(row.GetCanonicalSha256())] = row.GetRuleId()
		}
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		return nil, err
	}
	input.Rules = &protocol.ConfigRuleTable{}
	seen := map[[sha256.Size]byte]bool{}
	for _, key := range keys {
		if seen[key.CanonicalSha256] {
			continue
		}
		seen[key.CanonicalSha256] = true
		ruleId := heldRules[key.CanonicalSha256]
		if ruleId == nil {
			ruleId = provisional("rule", string(key.CanonicalSha256[:])).Bytes()
		}
		input.Rules.Rules = append(input.Rules.Rules, &protocol.ConfigRuleId{CanonicalSha256: bytes.Clone(key.CanonicalSha256[:]), RuleId: bytes.Clone(ruleId)})
	}
	heldMembers := map[string][]byte{}
	for _, row := range previousResolve.GetMembers() {
		heldMembers[row.GetEmail()] = row.GetMemberId()
	}
	input.Resolve = &protocol.ConfigResolution{}
	for _, email := range slices.Sorted(maps.Keys(names.users)) {
		memberId := heldMembers[email]
		if memberId == nil {
			memberId = provisional("user", email).Bytes()
		}
		input.Resolve.Members = append(input.Resolve.Members, &protocol.ConfigMemberResolution{Email: email, MemberId: bytes.Clone(memberId)})
	}
	heldNetworks := map[string][]byte{}
	for _, row := range previousResolve.GetNetworks() {
		heldNetworks[row.GetText()] = row.GetNetworkId()
	}
	for _, text := range slices.Sorted(maps.Keys(names.networks)) {
		networkId := heldNetworks[text]
		if networkId == nil {
			networkId = provisional("network", text).Bytes()
		}
		input.Resolve.Networks = append(input.Resolve.Networks, &protocol.ConfigNetworkResolution{Text: text, NetworkId: bytes.Clone(networkId)})
	}
	heldClients := map[Id][]byte{}
	for _, row := range previousResolve.GetClients() {
		if clientId, err := IdFromBytes(row.GetClientId()); err == nil {
			heldClients[clientId] = row.GetSidecarId()
		}
	}
	for _, clientId := range slices.SortedFunc(maps.Keys(names.clients), Id.Cmp) {
		input.Resolve.Clients = append(input.Resolve.Clients, &protocol.ConfigClientResolution{ClientId: clientId.Bytes(), SidecarId: bytes.Clone(heldClients[clientId])})
	}

	var view AclAuthView
	if state != nil {
		rows := ConfigCompileRowsOf(state)
		input.Members, input.Sidecars, input.Statements = rows.Members, rows.Sidecars, rows.AclStatements
		input.NetworkId = state.NetworkId()
		view = state
	} else {
		document := &aclDocumentTestView{members: map[Id]*bridge.MemberRow{}}
		for _, row := range input.Resolve.GetMembers() {
			member := &bridge.MemberRow{MemberId: bytes.Clone(row.GetMemberId()), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER}
			document.members[Id(row.GetMemberId())] = member
			input.Members = append(input.Members, member)
		}
		view = document
	}
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: input, View: view, Now: now})
	if err != nil {
		return nil, err
	}
	report.DocumentAlone = state == nil
	return report, nil
}

// The document's own world: a member for every user it names, with no device and no other admission.
type aclDocumentTestView struct {
	members map[Id]*bridge.MemberRow
}

func (self *aclDocumentTestView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 0, Chain: make([]byte, sha256.Size)}
}
func (self *aclDocumentTestView) Genesis() *bridge.Genesis                   { return nil }
func (self *aclDocumentTestView) SidecarIds() []Id                           { return nil }
func (self *aclDocumentTestView) Sidecar(sidecarId Id) *AclSidecar           { return nil }
func (self *aclDocumentTestView) Member(memberId Id) *bridge.MemberRow       { return self.members[memberId] }
func (self *aclDocumentTestView) IsConfigWriter(sidecarId Id) bool           { return false }
func (self *aclDocumentTestView) Parked(sidecarId Id) bool                   { return false }
func (self *aclDocumentTestView) Sponsor(sidecarId Id) (Id, bool)            { return Id{}, false }
func (self *aclDocumentTestView) CascadeVoids(signer []byte, at uint64) bool { return false }

// The network already holds a document: Team's starting one is saved only as a network's first.
var ErrAclTeamStartHasDocument = errors.New("acl: the network holds a document, so no starting document is saved")

// Saves Team's starting document as the network's first, on the first Owner's device after team-create (TEAM-M6-01):
// planned and saved through AclSave as the person confirmed the team, held to the tier's limits (GET /sidecar/limits'
// acl_* keys, nil for the format alone), and refused with ErrAclTeamStartHasDocument once the head holds any document,
// so a Team's own is never replaced. Answers the base's pin.
func (self *Sidecar) SaveAclTeamStart(ctx context.Context, limits *AclLimits, origin SidecarActOrigin) (*bridge.AuthPin, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	writer, state, head, err := self.aclSaveContext(ctx)
	if err != nil {
		return nil, err
	}
	if head.File(ConfigHeadPolicyPath) != nil {
		return nil, ErrAclTeamStartHasDocument
	}
	plan, err := PlanAclSave(ctx, &AclSaveInput{Policy: AclTeamStartDocument(), Head: head, State: state, Limits: limits, Now: time.Now()})
	if err != nil {
		return nil, err
	}
	return AclSave(ctx, writer, plan)
}
