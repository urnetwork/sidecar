//go:build !ios_extension

// The records this device writes to mailcfg (MAIL-M7-04; §15.8, §15.9, I-8, D-MCP-11, D-ACL-12).
//
//	create    CreateAddress and CreateBurnerRecord are outward actions (I-8), for `ur id`, the apps and §16's
//	          mail_alias_create alike: each builds its CanonicalAction (kind alias_create, the alias, a group's
//	          name) and hands the gate an effect, so the record is written only once Authorize reserved the use, or
//	          at once under a standing grant. The effect creates the record only if absent (IfVersion 0) and puts
//	          the use's effect_key in it. Before it writes, and again after any refusal, it reads the path: a
//	          record this sidecar created under the same key is the effect already done, and anything else standing
//	          there is the winner of a race, which the loser is answered with as ErrMailConfigAddressTaken. A
//	          burner's effect draws its labels from the key (MailBurnerLabelsFunction) and takes the first whose
//	          path never stood, so a retry draws the same label and a burned one is never reissued
//	delete    DeleteAddress is mail_alias_delete: the record's removal, held to the version read, its action
//	          naming the repo, the path and that version (§16.6's evs row)
//	lookup    Lookup is both kinds' SidecarEffectLookup, from the stored action and the key alone, so a restart
//	          reconciles a reserved use with no caller alive: a creation is done when the address's record, or one
//	          of the key's burner labels, was created by this sidecar under the key; not_done when another's record
//	          stands at the address; else uncertain, since an attempt the last run sent may still commit. A removal
//	          is done when the path's first version after its base is this sidecar's removal
//	local     a burn, a pause and a resume are local (owner decision 32), and so is a group's member list: a later
//	          version of the same path, written on the version read, by a device that may change the record
//	seats     every write first asks whether this device holds a key of the repo: an unseated device waits keyless
//	          and creates nothing (§8.12), before any approval is asked for
//
// A creation waits out evs's 412 PATH_EPOCH_DUE, which holds new names in a mailcfg while an immediate path epoch is
// due. evs's DIRECTORY_FULL is a refusal, never retried (mail_paths.go).
//
// With a label drawer installed, a stored alias_create whose address another's record holds reads uncertain rather
// than not_done: the kind is one for addresses and burners, and the action alone does not say which it made.
//
// On every leg but the extension's.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What an outward action carries to the gate beside what it does.
type MailConfigActionArgs struct {
	// What policy or the agent asked; unset is normal (CanonicalActionRisk).
	Risk SidecarRisk
	// The run and agent a decision binds, nil for a person's own command.
	RunId   *Id
	AgentId *Id
	// The agent's own words, shown to an approver as untrusted text.
	Summary string
	// A decision already in hand, nil for none.
	Decision *bridge.Signed
}

// What CreateAddress creates.
type MailCreateAddressArgs struct {
	// The name: <LocalPart>@<net>.<root>, or under the scope's zone. An admin record's is admin, or empty.
	LocalPart string
	// id, group, agent or admin.
	Kind protocol.MailAddressKind
	// The repo the address's mail goes to: the creator's mailbox, a sponsor's, or a group's repo. Unset with Group.
	MailboxRepoId Id
	// A group's first members.
	MemberIds []Id
	// mail_alias_create's group: the local part of a group address this mailcfg holds, whose repo the new alias
	// delivers to.
	Group  string
	Action MailConfigActionArgs
}

// What DeleteAddress deletes.
type MailDeleteAddressArgs struct {
	LocalPart string
	Action    MailConfigActionArgs
}

// What CreateBurnerRecord creates.
type MailCreateBurnerArgs struct {
	// The action's alias, which an approver sees: the local part the burner is made for.
	Alias string
	// The owner's mailbox.
	MailboxRepoId Id
	// Whether it has its own selector and records (§15.9).
	Replying bool
	Action   MailConfigActionArgs
}

// An effect reference of this file: the record's creating version, or a removal's, big-endian, then a burner's
// label.
func mailConfigEffectRef(version uint64, label string) []byte {
	return append(binary.BigEndian.AppendUint64(nil, version), label...)
}

// The version and label of a mailConfigEffectRef.
func parseMailConfigEffectRef(effectRef []byte) (uint64, string, bool) {
	if len(effectRef) < 8 {
		return 0, "", false
	}
	return binary.BigEndian.Uint64(effectRef[:8]), string(effectRef[8:]), true
}

// Runs one outward action through the gate and answers what its effect came to: the outcome when done; the gate's
// own error, a pending approval's among them; the effect's refusal when it proved nothing happened; and
// ErrMailConfigUncertain when it may have.
func (self *MailConfig) authorize(ctx context.Context, canonical *protocol.CanonicalAction, effect SidecarEffect, args *MailConfigActionArgs) (*SidecarOutcome, error) {
	if self.gate == nil {
		return nil, ErrMailConfigNoGate
	}
	stored, err := NewCanonicalAction(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailConfigInvalid, err)
	}
	action := &SidecarAction{
		Kind:      SidecarActionKind(canonical.GetKind()),
		Canonical: stored.Bytes,
		Risk:      CanonicalActionRisk(stored, SidecarRiskNormal, args.Risk),
		RunId:     args.RunId,
		AgentId:   args.AgentId,
		Summary:   args.Summary,
		Effect:    effect,
	}
	if err := self.gate.Authorize(ctx, action, args.Decision); err != nil {
		return nil, err
	}
	outcome := action.Outcome
	switch {
	case outcome == nil:
		return nil, fmt.Errorf("%w: the gate answered no outcome", ErrMailConfigUncertain)
	case outcome.State == ApprovalOutcomeDone:
		return outcome, nil
	case outcome.State == ApprovalOutcomeNotDone:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return nil, ErrSidecarEffectNotDone
	case outcome.Err != nil:
		return nil, fmt.Errorf("%w: %w", ErrMailConfigUncertain, outcome.Err)
	}
	return nil, ErrMailConfigUncertain
}

// Whether this device may change a record whose mailbox is mailboxRepoId.
func (self *MailConfig) mayChange(mailboxRepoId Id) bool {
	return self.authority != nil && self.authority.MayChangeRecord(self.sidecarId, mailboxRepoId)
}

// Creates name's record only if absent, under effectKey: the version that created it, this call's or an earlier
// run's under the same key. An error wrapping ErrSidecarEffectNotDone proves nothing was created, with
// ErrMailConfigAddressTaken where something else holds the path; any other error leaves it open.
func (self *MailConfig) createRecord(ctx context.Context, name *mailConfigName, effectKey []byte, content []byte) (uint64, error) {
	decode := func(content []byte) *mailConfigRecord { return self.decodeRecord(name, content) }
	notDone := func(err error) (uint64, error) {
		return 0, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	var openErr error
	conflictCount := 0
	epochWaitCount := 0
	for {
		// the path itself, judged with no record held: what stands there is taken, whoever a reader honors
		replay, err := self.replay(ctx, name, nil)
		if err != nil {
			if openErr != nil {
				return 0, openErr
			}
			return 0, err
		}
		if (replay.standing || name.burner) && replay.createdBy(self.sidecarId, effectKey, content, decode) {
			return replay.lifeVersion, nil
		}
		if replay.standing || (name.burner && replay.everStood) {
			return notDone(ErrMailConfigAddressTaken)
		}
		if openErr != nil {
			// an attempt whose answer was lost, and nothing stands yet: it may still commit
			return 0, openErr
		}
		testHookBarrier("mail.config.write.before", "")
		versions, err := self.store.Write(ctx, []*mailStoreWrite{{Path: name.path, Content: content}})
		testHookBarrier("mail.config.write.after", "")
		switch {
		case err == nil:
			return versions[0], nil
		case errors.Is(err, ErrMailStoreConflict):
			// a racing creation: the next read shows the winner
			if conflictCount += 1; self.settings.WriteRetryCount < conflictCount {
				return notDone(err)
			}
		case errors.Is(err, ErrEvsPathEpochDue):
			if epochWaitCount += 1; self.settings.EpochDueRetryCount < epochWaitCount {
				return notDone(err)
			}
			select {
			case <-ctx.Done():
				return notDone(ctx.Err())
			case <-self.clock.After(self.settings.EpochDueRetryInterval):
			}
		case IsMailDirectoryFull(err), evsWriteRefusedForGood(err):
			return notDone(err)
		default:
			openErr = err
		}
	}
}

// The alias_create effect of one address.
type mailConfigCreateAddressEffect struct {
	config  *MailConfig
	name    *mailConfigName
	address *protocol.MailAddress
}

// Creates the record under effectKey: see createRecord.
func (self *mailConfigCreateAddressEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	address := proto.Clone(self.address).(*protocol.MailAddress)
	address.EffectKey = bytes.Clone(effectKey)
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	version, err := self.config.createRecord(ctx, self.name, effectKey, content)
	if err != nil {
		return nil, err
	}
	return mailConfigEffectRef(version, ""), nil
}

// Creates an address (§15.8): an outward action, so the record is written only once Authorize passes, created only
// if absent. *ApprovalPendingError while a person's decision is awaited; ErrMailConfigAddressTaken where another
// record holds the address, the winner then in the table; ErrMailConfigUncertain where the write's answer was lost,
// which the same call again completes under the same use.
func (self *MailConfig) CreateAddress(ctx context.Context, args *MailCreateAddressArgs) (*MailAddressLookup, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no address", ErrMailConfigInvalid)
	}
	localPart := args.LocalPart
	switch args.Kind {
	case protocol.MailAddressKind_MAIL_ADDRESS_ADMIN:
		if localPart != "" && localPart != mailAdminLocalParts[0] {
			return nil, fmt.Errorf("%w: an admin record is admin's", ErrMailConfigInvalid)
		}
		localPart = mailAdminLocalParts[0]
	case protocol.MailAddressKind_MAIL_ADDRESS_ID, protocol.MailAddressKind_MAIL_ADDRESS_GROUP, protocol.MailAddressKind_MAIL_ADDRESS_AGENT:
		if err := ValidateNewMailLocalPart(localPart); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: a kind no command creates", ErrMailConfigInvalid)
	}
	zone, _, err := self.zone()
	if err != nil {
		return nil, err
	}
	name, ok := mailConfigAddressName(zone, localPart+"@"+zone.Domain())
	if !ok {
		return nil, fmt.Errorf("%w: no address of this zone", ErrMailConfigInvalid)
	}
	kind := args.Kind
	mailboxRepoId := args.MailboxRepoId
	if args.Group != "" {
		// an alias of a group this mailcfg holds: its repo is the alias's mailbox
		groupName, ok := mailConfigAddressName(zone, args.Group+"@"+zone.Domain())
		if !ok || args.Kind == protocol.MailAddressKind_MAIL_ADDRESS_ADMIN || 0 < len(args.MemberIds) {
			return nil, fmt.Errorf("%w: no group of this zone", ErrMailConfigInvalid)
		}
		replay, err := self.refresh(ctx, groupName)
		if err != nil {
			return nil, err
		}
		if replay.record == nil || replay.record.address.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_GROUP {
			return nil, fmt.Errorf("%w: the group", ErrMailConfigAddressAbsent)
		}
		kind = protocol.MailAddressKind_MAIL_ADDRESS_GROUP
		mailboxRepoId = replay.record.mailboxRepoId
	}
	if mailboxRepoId == (Id{}) {
		return nil, fmt.Errorf("%w: no mailbox", ErrMailConfigInvalid)
	}
	address := &protocol.MailAddress{Kind: kind, Mailbox: mailboxRepoId.Bytes(), Creator: self.sidecarId.Bytes()}
	if 0 < len(args.MemberIds) {
		if kind != protocol.MailAddressKind_MAIL_ADDRESS_GROUP && kind != protocol.MailAddressKind_MAIL_ADDRESS_ADMIN {
			return nil, fmt.Errorf("%w: members of no group", ErrMailConfigInvalid)
		}
		if max(self.settings.GroupMemberMaxCount, 0) < len(args.MemberIds) {
			return nil, ErrMailConfigGroupFull
		}
		memberIds := slices.Clone(args.MemberIds)
		slices.SortFunc(memberIds, Id.Cmp)
		for index, memberId := range memberIds {
			if memberId == (Id{}) || (0 < index && memberIds[index-1] == memberId) {
				return nil, fmt.Errorf("%w: a member named twice or not at all", ErrMailConfigInvalid)
			}
			address.Members = append(address.Members, memberId.Bytes())
		}
	}
	if err := self.store.Writable(ctx); err != nil {
		return nil, err
	}
	if self.authority == nil || !self.authority.HonorsRecord(self.sidecarId, name.alias, self.clock.Now()) {
		return nil, ErrMailConfigNoGrant
	}
	canonical := &protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: localPart, AliasGroup: args.Group}
	effect := &mailConfigCreateAddressEffect{config: self, name: name, address: address}
	if _, err := self.authorize(ctx, canonical, effect, &args.Action); err != nil {
		if errors.Is(err, ErrMailConfigAddressTaken) {
			// the loser sees the winner
			self.refresh(ctx, name)
		}
		return nil, err
	}
	replay, err := self.refresh(ctx, name)
	if err != nil {
		return nil, err
	}
	return self.lookupOf(name, replay.record), nil
}

// What the path's first version after baseVersion is: this sidecar's removal (found, with its version), anything
// else (other), or nothing yet (none). It reads the path's newest life, as EvsRepo.Lookup does.
func (self *MailConfig) removalLookup(ctx context.Context, name *mailConfigName, baseVersion uint64) (EvsLookupState, uint64, error) {
	versions, err := self.store.Versions(ctx, name.path, max(self.settings.ReplayVersionMaxCount, 1))
	if errors.Is(err, ErrEvsPathAbsent) {
		if baseVersion == 0 {
			return EvsLookupNone, 0, nil
		}
		return EvsLookupOther, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	var first *mailConfigVersion
	for _, version := range versions {
		if baseVersion < version.Version {
			first = version
		}
	}
	switch {
	case first == nil:
		if len(versions) == 0 || versions[0].Version != baseVersion {
			return EvsLookupOther, 0, nil
		}
		return EvsLookupNone, 0, nil
	case first.Removed && first.SignerSidecarId == self.sidecarId:
		return EvsLookupFound, first.Version, nil
	}
	return EvsLookupOther, first.Version, nil
}

// The alias_delete effect of one address.
type mailConfigDeleteAddressEffect struct {
	config      *MailConfig
	name        *mailConfigName
	baseVersion uint64
}

// Removes the record, held to the version the action read: found by the path's own versions, so a second run finds
// the first's removal.
func (self *mailConfigDeleteAddressEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	config := self.config
	state, version, err := config.removalLookup(ctx, self.name, self.baseVersion)
	if err != nil {
		return nil, err
	}
	switch state {
	case EvsLookupFound:
		return mailConfigEffectRef(version, ""), nil
	case EvsLookupOther:
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, ErrEvsPathMoved)
	}
	testHookBarrier("mail.config.remove.before", "")
	removeErr := config.store.Remove(ctx, self.name.path, self.baseVersion)
	testHookBarrier("mail.config.remove.after", "")
	state, version, err = config.removalLookup(ctx, self.name, self.baseVersion)
	if err != nil {
		if removeErr != nil {
			return nil, removeErr
		}
		return nil, err
	}
	switch {
	case state == EvsLookupFound:
		return mailConfigEffectRef(version, ""), nil
	case state == EvsLookupOther:
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, errors.Join(ErrEvsPathMoved, removeErr))
	case removeErr == nil:
		return nil, fmt.Errorf("%w: a removal the path's versions do not show", ErrEvsLookupUnknown)
	case errors.Is(removeErr, ErrMailStoreConflict), errors.Is(removeErr, ErrEvsPathAbsent), evsWriteRefusedForGood(removeErr):
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, removeErr)
	}
	return nil, removeErr
}

// Deletes an address (§16's mail_alias_delete, `ur id rm`): an outward action whose effect is the record's
// removal, by a device that may change it. ErrMailConfigAddressAbsent where no record a reader honors stands there.
func (self *MailConfig) DeleteAddress(ctx context.Context, args *MailDeleteAddressArgs) error {
	if args == nil {
		return fmt.Errorf("%w: no address", ErrMailConfigInvalid)
	}
	zone, _, err := self.zone()
	if err != nil {
		return err
	}
	name, ok := mailConfigAddressName(zone, args.LocalPart+"@"+zone.Domain())
	if !ok {
		return fmt.Errorf("%w: no address of this zone", ErrMailConfigInvalid)
	}
	replay, err := self.refresh(ctx, name)
	if err != nil {
		return err
	}
	if replay.record == nil || !replay.record.lifeHonored {
		return ErrMailConfigAddressAbsent
	}
	if !self.mayChange(replay.record.mailboxRepoId) {
		return ErrMailConfigNotOwner
	}
	if err := self.store.Writable(ctx); err != nil {
		return err
	}
	canonical := &protocol.CanonicalAction{
		Kind:        uint32(SidecarActionAliasDelete),
		RepoId:      self.store.RepoId().Bytes(),
		Path:        name.path,
		Alias:       name.alias,
		BaseVersion: replay.headVersion,
	}
	effect := &mailConfigDeleteAddressEffect{config: self, name: name, baseVersion: replay.headVersion}
	_, authorizeErr := self.authorize(ctx, canonical, effect, &args.Action)
	if _, err := self.refresh(ctx, name); err != nil && authorizeErr == nil {
		return err
	}
	return authorizeErr
}

// The alias_create effect of one burner label.
type mailConfigCreateBurnerEffect struct {
	config *MailConfig
	burner *protocol.MailBurner
}

// Takes the first of the key's labels whose path never stood, or the one an earlier run under the key took.
func (self *mailConfigCreateBurnerEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	config := self.config
	drawer := func() MailBurnerLabelsFunction {
		config.stateLock.Lock()
		defer config.stateLock.Unlock()
		return config.burnerLabels
	}()
	if drawer == nil {
		return nil, fmt.Errorf("%w: %w: no burner label drawer", ErrSidecarEffectNotDone, ErrMailConfigNoGate)
	}
	labels := drawer(effectKey)
	if maxCount := max(config.settings.BurnerCandidateMaxCount, 1); maxCount < len(labels) {
		labels = labels[:maxCount]
	}
	burner := proto.Clone(self.burner).(*protocol.MailBurner)
	burner.EffectKey = bytes.Clone(effectKey)
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(burner)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	names := []*mailConfigName{}
	for _, label := range labels {
		if name, ok := mailConfigBurnerName(label); ok {
			names = append(names, name)
		}
	}
	if 0 < len(effectKey) {
		// an earlier run under this key took one of these: found before any label is tried again
		for _, name := range names {
			replay, err := config.replay(ctx, name, nil)
			if err != nil {
				return nil, err
			}
			decode := func(content []byte) *mailConfigRecord { return config.decodeRecord(name, content) }
			if replay.createdBy(config.sidecarId, effectKey, nil, decode) {
				return mailConfigEffectRef(replay.lifeVersion, name.key), nil
			}
		}
	}
	refusal := fmt.Errorf("%w: no label", ErrMailConfigAddressTaken)
	for _, name := range names {
		if config.authority == nil || !config.authority.HonorsRecord(config.sidecarId, name.alias, config.clock.Now()) {
			refusal = ErrMailConfigNoGrant
			continue
		}
		version, err := config.createRecord(ctx, name, effectKey, content)
		switch {
		case err == nil:
			return mailConfigEffectRef(version, name.key), nil
		case errors.Is(err, ErrMailConfigAddressTaken):
			// a label in use, burned or removed: never reissued, and the next is tried
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, refusal)
}

// Creates a burner's record (§15.9) under a label its use draws: an outward action, as CreateAddress is, whose
// effect takes the first of the key's labels that never stood. The answer names the label. ErrMailConfigNoGate
// until a label drawer is installed.
func (self *MailConfig) CreateBurnerRecord(ctx context.Context, args *MailCreateBurnerArgs) (*MailBurnerInfo, error) {
	if args == nil || args.MailboxRepoId == (Id{}) {
		return nil, fmt.Errorf("%w: no mailbox", ErrMailConfigInvalid)
	}
	if !ValidMailLocalPart(args.Alias) {
		return nil, ErrMailLocalPartInvalid
	}
	hasDrawer := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.burnerLabels != nil
	}()
	if !hasDrawer {
		return nil, fmt.Errorf("%w: no burner label drawer", ErrMailConfigNoGate)
	}
	if err := self.store.Writable(ctx); err != nil {
		return nil, err
	}
	burner := &protocol.MailBurner{
		Mailbox:  args.MailboxRepoId.Bytes(),
		State:    protocol.MailBurnerState_MAIL_BURNER_LIVE,
		Replying: args.Replying,
		Created:  uint64(self.clock.Now().UnixMilli()),
	}
	canonical := &protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: args.Alias}
	outcome, err := self.authorize(ctx, canonical, &mailConfigCreateBurnerEffect{config: self, burner: burner}, &args.Action)
	if err != nil {
		return nil, err
	}
	_, label, ok := parseMailConfigEffectRef(outcome.EffectRef)
	name, nameOk := mailConfigBurnerName(label)
	if !ok || !nameOk {
		return nil, fmt.Errorf("%w: an effect reference that names no label", ErrMailConfigInvalid)
	}
	replay, err := self.refresh(ctx, name)
	if err != nil {
		return nil, err
	}
	if replay.record == nil || replay.record.burner == nil {
		return nil, ErrMailConfigAddressAbsent
	}
	record := replay.record
	return &MailBurnerInfo{
		Label:            label,
		State:            record.burner.GetState(),
		MailboxRepoId:    record.mailboxRepoId,
		Replying:         record.burner.GetReplying(),
		CreatedMillis:    record.burner.GetCreated(),
		CreatorSidecarId: record.creatorSidecarId,
		Granted:          self.authority != nil && self.authority.HonorsRecord(record.creatorSidecarId, record.alias, self.clock.Now()),
	}, nil
}

// Writes a later version of name's record on the version read: change answers the new record from the one that
// stands, nil for nothing to write. A racing writer's version is read and the change made again, at most
// WriteRetryCount times. A record whose file an unauthorized removal took is written again as a creation, which
// the readers that held it take from a device that may change it.
func (self *MailConfig) updateRecord(ctx context.Context, name *mailConfigName, change func(record *mailConfigRecord) (proto.Message, error)) error {
	if err := self.store.Writable(ctx); err != nil {
		return err
	}
	for attempt := 0; ; attempt += 1 {
		replay, err := self.refresh(ctx, name)
		if err != nil {
			return err
		}
		record := replay.record
		if record == nil {
			return ErrMailConfigAddressAbsent
		}
		if !self.mayChange(record.mailboxRepoId) {
			return ErrMailConfigNotOwner
		}
		next, err := change(record)
		if err != nil || next == nil {
			return err
		}
		if replay.standing && !record.lifeHonored {
			// a file no reader honors stands where the record's was: a later version of it would count for nothing
			return fmt.Errorf("%w: a record no reader honors stands at its path", ErrMailConfigAddressTaken)
		}
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(next)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrMailConfigInvalid, err)
		}
		write := &mailStoreWrite{Path: name.path, Content: content}
		if replay.standing {
			write.IfVersion = replay.headVersion
		}
		testHookBarrier("mail.config.write.before", "")
		_, err = self.store.Write(ctx, []*mailStoreWrite{write})
		testHookBarrier("mail.config.write.after", "")
		if err == nil {
			_, err = self.refresh(ctx, name)
			return err
		}
		if !errors.Is(err, ErrMailStoreConflict) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}

// Burns, pauses or resumes a label (§15.9): local, with no approval (owner decision 32), by a device that may
// change the record. Receivers answer 550 5.1.1 for a burned or paused label from the version's hint on. A burned
// label stays burned: ErrMailConfigBurned for any other state asked of it.
func (self *MailConfig) SetBurnerState(ctx context.Context, label string, state protocol.MailBurnerState) error {
	name, ok := mailConfigBurnerName(label)
	if !ok {
		return fmt.Errorf("%w: no burner label", ErrMailConfigInvalid)
	}
	switch state {
	case protocol.MailBurnerState_MAIL_BURNER_LIVE, protocol.MailBurnerState_MAIL_BURNER_PAUSED, protocol.MailBurnerState_MAIL_BURNER_BURNED:
	default:
		return fmt.Errorf("%w: no burner state", ErrMailConfigInvalid)
	}
	return self.updateRecord(ctx, name, func(record *mailConfigRecord) (proto.Message, error) {
		switch {
		case record.burner.GetState() == state:
			return nil, nil
		case record.burner.GetState() == protocol.MailBurnerState_MAIL_BURNER_BURNED:
			return nil, ErrMailConfigBurned
		}
		burner := proto.Clone(record.burner).(*protocol.MailBurner)
		burner.State = state
		return burner, nil
	})
}

// Marks a label as having its own selector and records, or not (§15.9): MAIL-M9-03's, when a burner first replies
// and when its last selector retires.
func (self *MailConfig) SetBurnerReplying(ctx context.Context, label string, replying bool) error {
	name, ok := mailConfigBurnerName(label)
	if !ok {
		return fmt.Errorf("%w: no burner label", ErrMailConfigInvalid)
	}
	return self.updateRecord(ctx, name, func(record *mailConfigRecord) (proto.Message, error) {
		if record.burner.GetReplying() == replying {
			return nil, nil
		}
		burner := proto.Clone(record.burner).(*protocol.MailBurner)
		burner.Replying = replying
		return burner, nil
	})
}

// Sets a group address's members to memberIds, in id order, within GroupMemberMaxCount: the mailcfg half of
// `ur id group-add`, whose RepoGrant MailRepos files beside it. ErrMailConfigGroupFull past the bound.
func (self *MailConfig) SetGroupMembers(ctx context.Context, localPart string, memberIds []Id) error {
	return self.changeGroupMembers(ctx, localPart, func(current []Id) ([]Id, error) {
		return memberIds, nil
	})
}

// Adds one member to a group address, a member it already holds changing nothing.
func (self *MailConfig) AddGroupMember(ctx context.Context, localPart string, memberId Id) error {
	return self.changeGroupMembers(ctx, localPart, func(current []Id) ([]Id, error) {
		if slices.Contains(current, memberId) {
			return current, nil
		}
		return append(slices.Clone(current), memberId), nil
	})
}

// Removes one member from a group address, a member it does not hold changing nothing.
func (self *MailConfig) RemoveGroupMember(ctx context.Context, localPart string, memberId Id) error {
	return self.changeGroupMembers(ctx, localPart, func(current []Id) ([]Id, error) {
		return slices.DeleteFunc(slices.Clone(current), func(held Id) bool { return held == memberId }), nil
	})
}

// A group address's members as mailcfg holds them, in id order. ErrMailConfigAddressAbsent for no group.
func (self *MailConfig) GroupMembers(ctx context.Context, localPart string) ([]Id, Id, error) {
	zone, _, err := self.zone()
	if err != nil {
		return nil, Id{}, err
	}
	name, ok := mailConfigAddressName(zone, localPart+"@"+zone.Domain())
	if !ok {
		return nil, Id{}, fmt.Errorf("%w: no address of this zone", ErrMailConfigInvalid)
	}
	replay, err := self.refresh(ctx, name)
	if err != nil {
		return nil, Id{}, err
	}
	if replay.record == nil || replay.record.address.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_GROUP {
		return nil, Id{}, ErrMailConfigAddressAbsent
	}
	memberIds := []Id{}
	for _, member := range replay.record.address.GetMembers() {
		memberId, _ := IdFromBytes(member)
		memberIds = append(memberIds, memberId)
	}
	return memberIds, replay.record.mailboxRepoId, nil
}

// One change of a group address's member list, written on the version read.
func (self *MailConfig) changeGroupMembers(ctx context.Context, localPart string, change func(current []Id) ([]Id, error)) error {
	zone, _, err := self.zone()
	if err != nil {
		return err
	}
	name, ok := mailConfigAddressName(zone, localPart+"@"+zone.Domain())
	if !ok {
		return fmt.Errorf("%w: no address of this zone", ErrMailConfigInvalid)
	}
	return self.updateRecord(ctx, name, func(record *mailConfigRecord) (proto.Message, error) {
		if record.address.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_GROUP {
			return nil, fmt.Errorf("%w: the group", ErrMailConfigAddressAbsent)
		}
		current := []Id{}
		for _, member := range record.address.GetMembers() {
			memberId, _ := IdFromBytes(member)
			current = append(current, memberId)
		}
		memberIds, err := change(current)
		if err != nil {
			return nil, err
		}
		memberIds = slices.Clone(memberIds)
		slices.SortFunc(memberIds, Id.Cmp)
		memberIds = slices.Compact(memberIds)
		if slices.Contains(memberIds, Id{}) {
			return nil, fmt.Errorf("%w: a member not named", ErrMailConfigInvalid)
		}
		if slices.Equal(memberIds, current) {
			return nil, nil
		}
		if max(self.settings.GroupMemberMaxCount, 0) < len(memberIds) && len(current) < len(memberIds) {
			return nil, ErrMailConfigGroupFull
		}
		address := proto.Clone(record.address).(*protocol.MailAddress)
		address.Members = nil
		for _, memberId := range memberIds {
			address.Members = append(address.Members, memberId.Bytes())
		}
		return address, nil
	})
}

// alias_create's and alias_delete's SidecarEffectLookup: see the file header. It reads only the stored action and
// the key.
func (self *MailConfig) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	stored, err := ParseStoredCanonicalAction(canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: a stored action that does not parse", ErrMailConfigInvalid)
	}
	action := stored.Action
	switch SidecarActionKind(action.GetKind()) {
	case SidecarActionAliasCreate:
		return self.lookupCreate(ctx, action, effectKey)
	case SidecarActionAliasDelete:
		return self.lookupDelete(ctx, action)
	}
	return nil, fmt.Errorf("%w: an action of kind %d", ErrMailConfigInvalid, action.GetKind())
}

// A stored alias_create's outcome.
func (self *MailConfig) lookupCreate(ctx context.Context, action *protocol.CanonicalAction, effectKey []byte) (*SidecarOutcome, error) {
	uncertain := &SidecarOutcome{State: ApprovalOutcomeUncertain}
	if len(effectKey) == 0 {
		// a standing grant's creation keeps no row to reconcile
		return uncertain, nil
	}
	drawer := func() MailBurnerLabelsFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.burnerLabels
	}()
	if drawer != nil {
		labels := drawer(effectKey)
		if maxCount := max(self.settings.BurnerCandidateMaxCount, 1); maxCount < len(labels) {
			labels = labels[:maxCount]
		}
		for _, label := range labels {
			name, ok := mailConfigBurnerName(label)
			if !ok {
				continue
			}
			replay, err := self.replay(ctx, name, nil)
			if err != nil {
				return nil, err
			}
			decode := func(content []byte) *mailConfigRecord { return self.decodeRecord(name, content) }
			if replay.createdBy(self.sidecarId, effectKey, nil, decode) {
				return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: mailConfigEffectRef(replay.lifeVersion, name.key)}, nil
			}
		}
	}
	zone, _, err := self.zone()
	if err != nil {
		return nil, err
	}
	name, ok := mailConfigAddressName(zone, action.GetAlias()+"@"+zone.Domain())
	if !ok {
		return uncertain, nil
	}
	replay, err := self.replay(ctx, name, nil)
	if err != nil {
		return nil, err
	}
	decode := func(content []byte) *mailConfigRecord { return self.decodeRecord(name, content) }
	switch {
	case replay.standing && replay.createdBy(self.sidecarId, effectKey, nil, decode):
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: mailConfigEffectRef(replay.lifeVersion, "")}, nil
	case replay.standing && drawer == nil:
		// another's record holds the address, which this use's create-only write can never take
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	return uncertain, nil
}

// A stored alias_delete's outcome.
func (self *MailConfig) lookupDelete(ctx context.Context, action *protocol.CanonicalAction) (*SidecarOutcome, error) {
	repoId, err := IdFromBytes(action.GetRepoId())
	if err != nil || repoId != self.store.RepoId() {
		return nil, fmt.Errorf("%w: an action of another repo", ErrMailConfigInvalid)
	}
	zone, _, err := self.zone()
	if err != nil {
		return nil, err
	}
	name, ok := mailConfigAddressName(zone, action.GetAlias()+"@"+zone.Domain())
	if !ok || name.path != action.GetPath() {
		return nil, fmt.Errorf("%w: an action whose path is not its alias's", ErrMailConfigInvalid)
	}
	state, version, err := self.removalLookup(ctx, name, action.GetBaseVersion())
	if err != nil {
		return nil, err
	}
	switch state {
	case EvsLookupFound:
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: mailConfigEffectRef(version, "")}, nil
	case EvsLookupOther:
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}
