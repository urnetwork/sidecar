//go:build !ios_extension

// How a reader takes mailcfg (MAIL-M7-04; I-4, D-ACL-12, reading 15 of plan-MAIL-small-readings, QD-106): the
// store seam, the replay that judges each version of a record, the Sync that keeps the table, and Resolve.
//
//	replay    one path's life, oldest first: its creation, the versions after it, and its removal if it ends in
//	          one. The creation counts only when it decodes as its path's record and, for an address, names its
//	          push's signer as creator; a burner's creator is that signer. Each later version counts only from a
//	          signer that may change the record (a consented device of the member who owns its mailbox, a group
//	          repo's admin) and only when it keeps the kind, the mailbox, the creator and the effect key; a burned
//	          label never changes again. An owner's removal ends an address and burns a label for good; another
//	          signer's removal is passed over and the record stands as it was. A versionless version counts for
//	          nothing. Every version passed over raises one alarm
//	lives     evs reads a path's standing life, or a removed path's last one: History stops at a creation, so a
//	          path removed and made again shows a fresh reader only its newest life (evs_history.go, evs_lookup.go's
//	          header). So a reader holds the record it honored across syncs: a life that replaces it without this
//	          reader having judged the removal between counts only when its creator may change the record it
//	          replaces, and is otherwise passed over with an alarm while this process lives. A reader that starts
//	          after such a re-creation cannot see the earlier life (question
//	          mail-m7-04-recreated-record-history)
//	sync      one fresh read of the ref, then addr/ and burner/ listed, each record's head read and the paths whose
//	          version moved replayed, then the paths that no longer stand; a name that is no address or label of
//	          this zone is passed over
//	resolve   a recipient of another network, another scope or a released label is unknown (I-14); an address,
//	          admin's aliases included, is known while its record stands and policy grants its creator the alias's
//	          listen; a burner while its label is live; a reverse alias never, until MAIL-M9-04 lands forwarding
//
// On every leg but the extension's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One version of a mailcfg path, as a reader replays it.
type mailConfigVersion struct {
	Version         uint64
	SignerSidecarId Id
	// The removal that ended the path at this version.
	Removed bool
	// 0 kept; anything else is passed over.
	Versioning uint32
}

// What MailConfig needs of the mailcfg's main ref beyond mailStore. Implementations are safe for concurrent use.
type mailConfigStore interface {
	mailStore
	// The mailcfg repo.
	RepoId() Id
	// Brings this device's view of the ref up to its newest committed head, so the reads after it are no older.
	Refresh(ctx context.Context) error
	// The versions of path's standing life, or of a removed path's last life with its removal, newest first;
	// ErrEvsPathAbsent where the path never stood, ErrMailConfigReplayBound past maxCount of them.
	Versions(ctx context.Context, path string, maxCount int) ([]*mailConfigVersion, error)
	// The content of one written version of path, refusing with ErrMailStoreTooLarge past maxByteCount bytes.
	ReadVersion(ctx context.Context, path string, version uint64, maxByteCount int) ([]byte, error)
	// Removes path, held to the version it stands at: a *MailStoreConflictError where it stands at another,
	// ErrEvsPathAbsent where it stands no more.
	Remove(ctx context.Context, path string, ifVersion uint64) error
	// Whether this device holds a key of the repo, so it may write: ErrMailConfigUnseated where it holds none.
	Writable(ctx context.Context) error
	// Calls changed, which must not block, at each change of addr/ or burner/ until stop.
	Follow(ctx context.Context, changed func()) (stop func(), err error)
}

// mailConfigStore over the mailcfg's EvsRepo: mailEvsStore's verified reads and path CAS writes, History for a
// path's versions and their signers, and the repo's subscription for changes.
type mailConfigEvsStore struct {
	*mailEvsStore
}

// The repo's id.
func (self *mailConfigEvsStore) RepoId() Id {
	return self.repo.RepoId()
}

// One fresh read of the root, which reads the cluster's head past evs's cache and pins it (§11.9's fresh): a read
// that asks for no freshness may be answered as of the head this device last pinned, so a Sync with no hint behind
// it would otherwise list the repo as it stood at the Sync before.
func (self *mailConfigEvsStore) Refresh(ctx context.Context) error {
	_, err := self.repo.List(ctx, &EvsReadArgs{RefName: self.refName, Fresh: true})
	return err
}

// History's walk, page by page: see mailConfigStore.
func (self *mailConfigEvsStore) Versions(ctx context.Context, path string, maxCount int) ([]*mailConfigVersion, error) {
	versions := []*mailConfigVersion{}
	pageCount := self.repo.client.settings.HistoryVersionCount
	for next := uint64(0); ; {
		history, err := self.repo.History(ctx, &EvsReadArgs{RefName: self.refName, Path: path, Version: next, Fresh: next == 0})
		if errors.Is(err, ErrEvsPathAbsent) && 0 < len(versions) {
			return versions, nil
		}
		if err != nil {
			return nil, err
		}
		descended := false
		for _, version := range history.Versions {
			if 0 < len(versions) && versions[len(versions)-1].Version <= version.Version {
				continue
			}
			versions = append(versions, &mailConfigVersion{
				Version:         version.Version,
				SignerSidecarId: version.SignerSidecarId,
				Removed:         version.Removed,
				Versioning:      version.Versioning,
			})
			descended = true
		}
		if maxCount < len(versions) {
			return nil, ErrMailConfigReplayBound
		}
		if !descended {
			return versions, nil
		}
		last := versions[len(versions)-1]
		if len(history.Versions) < pageCount || last.Version <= 1 {
			return versions, nil
		}
		next = last.Version - 1
	}
}

// ReadHead of that version, held to maxByteCount.
func (self *mailConfigEvsStore) ReadVersion(ctx context.Context, path string, version uint64, maxByteCount int) ([]byte, error) {
	out := &mailBoundedBuffer{maxByteCount: maxByteCount}
	if _, err := self.repo.ReadHead(ctx, &EvsReadArgs{RefName: self.refName, Path: path, Version: version}, out); err != nil {
		if errors.Is(err, ErrMailStoreTooLarge) {
			return nil, ErrMailStoreTooLarge
		}
		return nil, err
	}
	return out.buffer.Bytes(), nil
}

// A removal through evs, held to ifVersion.
func (self *mailConfigEvsStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	_, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: self.refName, Writes: []*EvsPathWrite{{Path: path, Remove: true, IfVersion: &ifVersion}}})
	if errors.Is(err, ErrEvsPathMoved) || evsCreationConflict(err) {
		return &MailStoreConflictError{Paths: []string{path}}
	}
	return err
}

// Whether gkm gives this device the repo's newest key: a device with no leaf and no wrap holds none (§8.12).
func (self *mailConfigEvsStore) Writable(ctx context.Context) error {
	gkm := self.repo.client.args.Gkm
	if gkm == nil {
		return ErrMailConfigUnseated
	}
	key, err := gkm.CurrentRepoKey(ctx, self.repo.RepoId())
	switch {
	case errors.Is(err, ErrGkmKeyMissing), errors.Is(err, ErrGkmUnavailable):
		return fmt.Errorf("%w: %w", ErrMailConfigUnseated, err)
	case err != nil:
		return err
	case key == nil:
		return ErrMailConfigUnseated
	}
	return nil
}

// A subscription to the two families on main.
func (self *mailConfigEvsStore) Follow(ctx context.Context, changed func()) (func(), error) {
	subscription, err := self.repo.Subscribe(ctx, &EvsSubscribeArgs{
		RefName: self.refName,
		Paths:   []string{mailAddressFamily, mailBurnerFamily},
		Changes: func(change *EvsRepoChange) { changed() },
	})
	if err != nil {
		return nil, err
	}
	return subscription.Close, nil
}

// What a table key and its family say of a path: the address or label it names, and the alias policy grants.
type mailConfigName struct {
	burner bool
	// the address or the label
	key   string
	alias string
	path  string
}

// The name of an addr/ record: address must be one of zone's own, spelled as MailRecipient.Address spells it, an
// admin's only as admin@. False for anything else.
func mailConfigAddressName(zone MailZone, address string) (*mailConfigName, bool) {
	recipient, err := ParseMailRecipient(zone.Root, address)
	if err != nil || recipient.Zone != zone || recipient.Address() != address {
		return nil, false
	}
	switch recipient.Kind {
	case MailAddressKindAdmin:
		if recipient.LocalPart != mailAdminLocalParts[0] {
			return nil, false
		}
	case MailAddressKindName, MailAddressKindBounce:
	default:
		return nil, false
	}
	path, err := MailAddressPath(address)
	if err != nil {
		return nil, false
	}
	return &mailConfigName{key: address, alias: recipient.LocalPart, path: path}, true
}

// The name of a burner/ record: label must be a word-number label. False for anything else.
func mailConfigBurnerName(label string) (*mailConfigName, bool) {
	path, err := MailBurnerPath(label)
	if err != nil {
		return nil, false
	}
	return &mailConfigName{burner: true, key: label, alias: label, path: path}, true
}

// A record decoded from one version's bytes and held to its path, nil where it is not that path's record.
func (self *MailConfig) decodeRecord(name *mailConfigName, content []byte) *mailConfigRecord {
	if max(self.settings.RecordMaxByteCount, 1) < len(content) {
		return nil
	}
	idOf := func(value []byte) (Id, bool) {
		id, err := IdFromBytes(value)
		return id, err == nil && id != (Id{})
	}
	if name.burner {
		burner := &protocol.MailBurner{}
		if err := proto.Unmarshal(content, burner); err != nil || len(burner.ProtoReflect().GetUnknown()) != 0 {
			return nil
		}
		mailboxRepoId, ok := idOf(burner.GetMailbox())
		switch burner.GetState() {
		case protocol.MailBurnerState_MAIL_BURNER_LIVE, protocol.MailBurnerState_MAIL_BURNER_PAUSED, protocol.MailBurnerState_MAIL_BURNER_BURNED:
		default:
			ok = false
		}
		if !ok || (len(burner.GetEffectKey()) != 0 && len(burner.GetEffectKey()) != mailEffectKeyByteCount) {
			return nil
		}
		return &mailConfigRecord{burner: burner, mailboxRepoId: mailboxRepoId, alias: name.alias}
	}
	address := &protocol.MailAddress{}
	if err := proto.Unmarshal(content, address); err != nil || len(address.ProtoReflect().GetUnknown()) != 0 {
		return nil
	}
	mailboxRepoId, ok := idOf(address.GetMailbox())
	if _, creatorOk := idOf(address.GetCreator()); !ok || !creatorOk {
		return nil
	}
	if len(address.GetEffectKey()) != 0 && len(address.GetEffectKey()) != mailEffectKeyByteCount {
		return nil
	}
	admin := name.alias == mailAdminLocalParts[0]
	bounce := strings.HasPrefix(name.alias, mailBouncePrefix)
	switch address.GetKind() {
	case protocol.MailAddressKind_MAIL_ADDRESS_ADMIN:
		ok = admin
	case protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE:
		ok = bounce
	case protocol.MailAddressKind_MAIL_ADDRESS_ID, protocol.MailAddressKind_MAIL_ADDRESS_GROUP, protocol.MailAddressKind_MAIL_ADDRESS_AGENT:
		ok = !admin && !bounce
	default:
		ok = false
	}
	if !ok {
		return nil
	}
	if address.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_GROUP && address.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_ADMIN && 0 < len(address.GetMembers()) {
		return nil
	}
	seen := map[Id]bool{}
	for _, member := range address.GetMembers() {
		memberId, memberOk := idOf(member)
		if !memberOk || seen[memberId] {
			return nil
		}
		seen[memberId] = true
	}
	return &mailConfigRecord{address: address, mailboxRepoId: mailboxRepoId, alias: name.alias}
}

// Whether a later version may follow record: it keeps what no version changes, and a burned label stays burned.
func mailConfigChangeAllowed(record *mailConfigRecord, next *mailConfigRecord) bool {
	if record.mailboxRepoId != next.mailboxRepoId {
		return false
	}
	if record.burner != nil {
		if next.burner == nil || record.burner.GetCreated() != next.burner.GetCreated() ||
			!bytes.Equal(record.burner.GetEffectKey(), next.burner.GetEffectKey()) {
			return false
		}
		return record.burner.GetState() != protocol.MailBurnerState_MAIL_BURNER_BURNED ||
			next.burner.GetState() == protocol.MailBurnerState_MAIL_BURNER_BURNED
	}
	return next.address != nil && record.address.GetKind() == next.address.GetKind() &&
		bytes.Equal(record.address.GetCreator(), next.address.GetCreator()) &&
		bytes.Equal(record.address.GetEffectKey(), next.address.GetEffectKey())
}

// What a replay of one path found: evs's view of it, and the record a reader honors there.
type mailConfigReplay struct {
	// Whether the path ever stood, whether a file stands now, and its newest version, a removal's included.
	everStood   bool
	standing    bool
	headVersion uint64
	// The life read: its creating version, that version's signer and content.
	lifeVersion  uint64
	lifeSignerId Id
	lifeContent  []byte
	// The honored record, nil for none.
	record *mailConfigRecord
}

// Whether the life read was created by sidecarId under effectKey: what a creation's retry and a restart's Lookup
// look for. An empty key matches only content equal to want, a standing grant's creation having no key to tell it
// by.
func (self *mailConfigReplay) createdBy(sidecarId Id, effectKey []byte, want []byte, decode func(content []byte) *mailConfigRecord) bool {
	if !self.everStood || self.lifeSignerId != sidecarId || self.lifeContent == nil {
		return false
	}
	if len(effectKey) == 0 {
		return want != nil && bytes.Equal(self.lifeContent, want)
	}
	record := decode(self.lifeContent)
	if record == nil {
		return false
	}
	if record.burner != nil {
		return bytes.Equal(record.burner.GetEffectKey(), effectKey)
	}
	return bytes.Equal(record.address.GetEffectKey(), effectKey)
}

// Reads and judges one path's life: see the file header. held is the record this reader honored there before, nil
// for none, which a life this reader did not see replace it must be allowed to change.
func (self *MailConfig) replay(ctx context.Context, name *mailConfigName, held *mailConfigRecord) (*mailConfigReplay, error) {
	versions, err := self.store.Versions(ctx, name.path, max(self.settings.ReplayVersionMaxCount, 1))
	if errors.Is(err, ErrEvsPathAbsent) {
		return &mailConfigReplay{record: held}, nil
	}
	if err != nil {
		return nil, err
	}
	slices.Reverse(versions)
	replay := &mailConfigReplay{everStood: 0 < len(versions)}
	if len(versions) == 0 {
		replay.record = held
		return replay, nil
	}
	alarm := func(version *mailConfigVersion, reason MailConfigAlarmReason) {
		self.alarm(name.path, &MailConfigAlarm{Reason: reason, SidecarId: version.SignerSidecarId, Version: version.Version, Burner: name.burner})
	}
	mayChange := func(signerSidecarId Id, record *mailConfigRecord) bool {
		return self.authority != nil && self.authority.MayChangeRecord(signerSidecarId, record.mailboxRepoId)
	}
	read := func(version *mailConfigVersion) (*mailConfigRecord, []byte, error) {
		content, err := self.store.ReadVersion(ctx, name.path, version.Version, max(self.settings.RecordMaxByteCount, 1))
		if errors.Is(err, ErrMailStoreTooLarge) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		return self.decodeRecord(name, content), content, nil
	}

	replay.headVersion = versions[len(versions)-1].Version
	replay.standing = !versions[len(versions)-1].Removed
	replay.lifeVersion = versions[0].Version
	replay.lifeSignerId = versions[0].SignerSidecarId

	// the record that stands as the replay goes, and whether the life being read is its own
	record := held
	if record != nil && record.createdVersion == replay.lifeVersion && record.creatorSidecarId == replay.lifeSignerId {
		// the same life this reader honored before: judged again from its creation
		record = nil
	}
	lifeHonored := false
	for index, version := range versions {
		if version.Removed {
			// a removal ends the life read; it ends the record only when that life is the record's own
			honored := lifeHonored
			lifeHonored = false
			switch {
			case !honored || record == nil:
			case !mayChange(version.SignerSidecarId, record):
				alarm(version, MailConfigAlarmSigner)
			case record.burner != nil:
				// an owner's removal of a label: burned for good, never reissued (§15.9)
				burned := proto.Clone(record.burner).(*protocol.MailBurner)
				burned.State = protocol.MailBurnerState_MAIL_BURNER_BURNED
				record = &mailConfigRecord{
					burner: burned, creatorSidecarId: record.creatorSidecarId, createdVersion: record.createdVersion,
					mailboxRepoId: record.mailboxRepoId, alias: record.alias, removedForever: true,
				}
			default:
				record = nil
			}
			continue
		}
		if version.Versioning != 0 {
			alarm(version, MailConfigAlarmVersioning)
			continue
		}
		next, content, err := read(version)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			replay.lifeContent = content
			if next == nil {
				alarm(version, MailConfigAlarmInvalid)
				continue
			}
			if next.address != nil {
				if creatorId, _ := IdFromBytes(next.address.GetCreator()); creatorId != version.SignerSidecarId {
					alarm(version, MailConfigAlarmCreator)
					continue
				}
			}
			if record != nil {
				// a life this reader did not see replace the record it holds: only a device that may change that
				// record replaces it, with what a later version of it could hold, and a label kept forever or
				// burned is never made again
				replaces := !record.removedForever && mayChange(version.SignerSidecarId, record) &&
					record.mailboxRepoId == next.mailboxRepoId && (record.address != nil) == (next.address != nil)
				if replaces && record.burner != nil {
					replaces = record.burner.GetState() != protocol.MailBurnerState_MAIL_BURNER_BURNED
				}
				if !replaces {
					alarm(version, MailConfigAlarmRecreated)
					continue
				}
			}
			next.creatorSidecarId = version.SignerSidecarId
			next.createdVersion = version.Version
			record = next
			lifeHonored = true
			continue
		}
		if !lifeHonored {
			// a change to a life no reader honors
			continue
		}
		if !mayChange(version.SignerSidecarId, record) {
			alarm(version, MailConfigAlarmSigner)
			continue
		}
		if next == nil {
			alarm(version, MailConfigAlarmInvalid)
			continue
		}
		if !mailConfigChangeAllowed(record, next) {
			alarm(version, MailConfigAlarmChange)
			continue
		}
		next.creatorSidecarId = record.creatorSidecarId
		next.createdVersion = record.createdVersion
		record = next
	}
	if record != nil {
		kept := *record
		kept.lifeHonored = lifeHonored && replay.standing
		record = &kept
	}
	replay.record = record
	return replay, nil
}

// The table entry a replay comes to, nil where nothing is worth keeping: a path that does not stand and holds no
// record.
func mailConfigEntryOf(name *mailConfigName, replay *mailConfigReplay) *mailConfigEntry {
	if !replay.standing && replay.record == nil {
		return nil
	}
	return &mailConfigEntry{path: name.path, headVersion: replay.headVersion, standing: replay.standing, record: replay.record}
}

// Reads the repo and brings the table up to it: see the file header. One Sync runs at a time, and a second waits
// for the first. A path that fails to read fails the Sync, leaving the table as it was.
func (self *MailConfig) Sync(ctx context.Context) error {
	select {
	case self.syncToken <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-self.syncToken }()

	zone, _, err := self.zone()
	if err != nil {
		return err
	}
	// copies, since a write of this device's own changes the tables while the Sync reads
	addressEntries, burnerEntries, syncedZone := func() (map[string]*mailConfigEntry, map[string]*mailConfigEntry, MailZone) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return maps.Clone(self.addressEntries), maps.Clone(self.burnerEntries), self.syncedZone
	}()
	if syncedZone != zone {
		// the network's label moved: no record read under the old spelling is this zone's
		addressEntries = map[string]*mailConfigEntry{}
	}
	if err := self.store.Refresh(ctx); err != nil {
		return err
	}
	nextAddressEntries, err := self.syncFamily(ctx, mailAddressFamily, addressEntries, func(name string) (*mailConfigName, bool) {
		return mailConfigAddressName(zone, name)
	})
	if err != nil {
		return err
	}
	nextBurnerEntries, err := self.syncFamily(ctx, mailBurnerFamily, burnerEntries, mailConfigBurnerName)
	if err != nil {
		return err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// a write of this device's own that landed while the Sync read is kept: its entry is at least as new
	keepNewer := func(next map[string]*mailConfigEntry, read map[string]*mailConfigEntry, current map[string]*mailConfigEntry) {
		for key, entry := range current {
			if read[key] != entry && (next[key] == nil || next[key].headVersion < entry.headVersion) {
				next[key] = entry
			}
		}
	}
	if syncedZone == zone {
		keepNewer(nextAddressEntries, addressEntries, self.addressEntries)
	}
	keepNewer(nextBurnerEntries, burnerEntries, self.burnerEntries)
	self.addressEntries = nextAddressEntries
	self.burnerEntries = nextBurnerEntries
	self.syncedZone = zone
	self.syncedTime = now
	self.synced = true
	self.missErr = nil
	return nil
}

// One family's table brought up to the repo, from the entries held: each listed path whose head moved is replayed,
// then each held path that no longer stands.
func (self *MailConfig) syncFamily(ctx context.Context, family string, held map[string]*mailConfigEntry, nameOf func(name string) (*mailConfigName, bool)) (map[string]*mailConfigEntry, error) {
	next := map[string]*mailConfigEntry{}
	shards, err := self.store.List(ctx, family)
	if err != nil && !errors.Is(err, ErrEvsPathAbsent) {
		return nil, err
	}
	for _, shard := range shards {
		children, err := self.store.List(ctx, family+"/"+shard)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			name, ok := nameOf(child)
			if !ok || name.path != family+"/"+shard+"/"+child {
				// no address or label of this zone, or one in another's shard: counted once, by its place alone
				self.alarm(family+"/"+shard+"/"+child, &MailConfigAlarm{Reason: MailConfigAlarmInvalid, Burner: family == mailBurnerFamily})
				continue
			}
			entry := held[name.key]
			_, headVersion, err := self.store.Read(ctx, name.path, max(self.settings.RecordMaxByteCount, 1))
			switch {
			case errors.Is(err, ErrEvsPathAbsent):
				// listed, then removed: read below as a path that no longer stands
				continue
			case errors.Is(err, ErrMailStoreTooLarge):
				headVersion = 0
			case err != nil:
				return nil, err
			}
			if entry != nil && entry.standing && headVersion != 0 && entry.headVersion == headVersion {
				next[name.key] = entry
				continue
			}
			replayed, err := self.replayEntry(ctx, name, entry)
			if err != nil {
				return nil, err
			}
			if replayed != nil {
				next[name.key] = replayed
			}
		}
	}
	for key, entry := range held {
		if _, listed := next[key]; listed {
			continue
		}
		if entry.record == nil {
			continue
		}
		if entry.record.removedForever {
			next[key] = entry
			continue
		}
		name, ok := nameOf(key)
		if !ok {
			continue
		}
		replayed, err := self.replayEntry(ctx, name, entry)
		if err != nil {
			return nil, err
		}
		if replayed != nil {
			next[key] = replayed
		}
	}
	return next, nil
}

// One path replayed into its table entry, nil for none; a path past the replay bound is kept as unreadable, so it
// is unknown and not read again until it moves.
func (self *MailConfig) replayEntry(ctx context.Context, name *mailConfigName, entry *mailConfigEntry) (*mailConfigEntry, error) {
	var held *mailConfigRecord
	if entry != nil {
		held = entry.record
	}
	replay, err := self.replay(ctx, name, held)
	if errors.Is(err, ErrMailConfigReplayBound) {
		_, headVersion, readErr := self.store.Read(ctx, name.path, max(self.settings.RecordMaxByteCount, 1))
		if readErr != nil && !errors.Is(readErr, ErrMailStoreTooLarge) && !errors.Is(readErr, ErrEvsPathAbsent) {
			return nil, readErr
		}
		return &mailConfigEntry{path: name.path, headVersion: headVersion, standing: readErr == nil, unreadable: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return mailConfigEntryOf(name, replay), nil
}

// Replays one path now and puts what it finds in the table: what a write of this device's does after it lands.
func (self *MailConfig) refresh(ctx context.Context, name *mailConfigName) (*mailConfigReplay, error) {
	held := func() *mailConfigRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry := self.entriesWithLock(name)[name.key]; entry != nil {
			return entry.record
		}
		return nil
	}()
	replay, err := self.replay(ctx, name, held)
	if err != nil {
		return nil, err
	}
	entry := mailConfigEntryOf(name, replay)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := self.entriesWithLock(name)
	if entry == nil {
		delete(entries, name.key)
	} else if current := entries[name.key]; current == nil || current.headVersion <= entry.headVersion {
		entries[name.key] = entry
	}
	return replay, nil
}

// The table name's family lives in.
func (self *MailConfig) entriesWithLock(name *mailConfigName) map[string]*mailConfigEntry {
	if name.burner {
		return self.burnerEntries
	}
	return self.addressEntries
}

// The table name a recipient's mail is looked up by, false for one that is no recipient of this mailcfg: another
// root, network or scope, a label the network no longer holds, or a reverse alias.
func (self *MailConfig) recipientName(recipient MailRecipient) (*mailConfigName, bool) {
	zone, row, err := self.zone()
	if err != nil || recipient.Zone.Root != zone.Root || recipient.Zone.Scope != zone.Scope || !recipient.Zone.OfNetwork(row) {
		return nil, false
	}
	spelled := recipient
	spelled.Zone = zone
	switch recipient.Kind {
	case MailAddressKindAdmin:
		spelled.LocalPart = mailAdminLocalParts[0]
		return mailConfigAddressName(zone, spelled.Address())
	case MailAddressKindName, MailAddressKindBounce:
		return mailConfigAddressName(zone, spelled.Address())
	case MailAddressKindBurner:
		return mailConfigBurnerName(recipient.BurnerLabel)
	}
	return nil, false
}

// The record the table holds for name, nil for none.
func (self *MailConfig) heldRecord(name *mailConfigName) (*mailConfigRecord, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry := self.entriesWithLock(name)[name.key]
	if entry == nil || entry.unreadable {
		return nil, self.synced
	}
	return entry.record, self.synced
}

// What a held record answers a lookup with at now: known while policy grants its creator the alias's listen and,
// for a burner, while its label is live.
func (self *MailConfig) lookupOf(name *mailConfigName, record *mailConfigRecord) *MailAddressLookup {
	unknown := &MailAddressLookup{}
	if record == nil || self.authority == nil || !self.authority.HonorsRecord(record.creatorSidecarId, record.alias, self.clock.Now()) {
		return unknown
	}
	if record.burner != nil {
		if record.burner.GetState() != protocol.MailBurnerState_MAIL_BURNER_LIVE {
			return unknown
		}
		return &MailAddressLookup{
			Known: true, Kind: protocol.MailAddressKind_MAIL_ADDRESS_BURNER, BurnerLabel: name.key,
			MailboxRepoId: record.mailboxRepoId, CreatorSidecarId: record.creatorSidecarId, Replying: record.burner.GetReplying(),
		}
	}
	lookup := &MailAddressLookup{
		Known: true, Kind: record.address.GetKind(), Address: name.key,
		MailboxRepoId: record.mailboxRepoId, CreatorSidecarId: record.creatorSidecarId,
	}
	for _, member := range record.address.GetMembers() {
		memberId, _ := IdFromBytes(member)
		lookup.MemberIds = append(lookup.MemberIds, memberId)
	}
	return lookup
}

// Where a recipient's mail goes (§15.8): Known with the mailbox's repo, or unknown, which burned and paused labels,
// records policy no longer grants, and recipients of another zone all are. A miss asks for one more Sync when the
// last is older than MissRefreshInterval; an error is that Sync's, or ErrMailConfigNotSynced before the first, and
// a receiver answers it as a temporary failure.
func (self *MailConfig) Resolve(ctx context.Context, recipient MailRecipient) (*MailAddressLookup, error) {
	name, ok := self.recipientName(recipient)
	record, synced := (*mailConfigRecord)(nil), false
	if ok {
		record, synced = self.heldRecord(name)
	} else {
		synced = func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.synced
		}()
	}
	lookup := &MailAddressLookup{}
	if record != nil {
		lookup = self.lookupOf(name, record)
	}
	if lookup.Known || !ok && synced {
		return lookup, nil
	}
	// one Sync for the misses of an interval: the rest take the table as it is, and that Sync's error while it failed
	due, missErr := func() (bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		now := self.clock.Now()
		last := self.syncedTime
		if last.Before(self.missTime) {
			last = self.missTime
		}
		if (self.synced || !self.missTime.IsZero()) && 0 < self.settings.MissRefreshInterval && now.Sub(last) < self.settings.MissRefreshInterval {
			return false, self.missErr
		}
		self.missTime = now
		return true, nil
	}()
	if !due {
		return lookup, missErr
	}
	if err := self.Sync(ctx); err != nil {
		if !synced {
			err = fmt.Errorf("%w: %w", ErrMailConfigNotSynced, err)
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.missErr = err
		}()
		return lookup, err
	}
	if name, ok = self.recipientName(recipient); !ok {
		return lookup, nil
	}
	record, _ = self.heldRecord(name)
	return self.lookupOf(name, record), nil
}

// Every address record a reader honors, by address, each Known only while policy grants its creator: what
// mail_aliases and `ur id ls` list. ErrMailConfigNotSynced before the first Sync.
func (self *MailConfig) Addresses() ([]*MailAddressLookup, error) {
	names, records, err := self.snapshot(false)
	if err != nil {
		return nil, err
	}
	lookups := make([]*MailAddressLookup, 0, len(names))
	for index, name := range names {
		lookup := self.lookupOf(name, records[index])
		if !lookup.Known {
			// listed all the same, as a record policy does not grant
			lookup = &MailAddressLookup{
				Kind: records[index].address.GetKind(), Address: name.key,
				MailboxRepoId: records[index].mailboxRepoId, CreatorSidecarId: records[index].creatorSidecarId,
			}
		}
		lookups = append(lookups, lookup)
	}
	return lookups, nil
}

// Every burner label a reader honors, by label, burned and paused ones included, since a label is kept forever:
// what a label drawer skips and the burner limits count. ErrMailConfigNotSynced before the first Sync.
func (self *MailConfig) Burners() ([]*MailBurnerInfo, error) {
	names, records, err := self.snapshot(true)
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	burners := make([]*MailBurnerInfo, 0, len(names))
	for index, name := range names {
		record := records[index]
		burners = append(burners, &MailBurnerInfo{
			Label:            name.key,
			State:            record.burner.GetState(),
			MailboxRepoId:    record.mailboxRepoId,
			Replying:         record.burner.GetReplying(),
			CreatedMillis:    record.burner.GetCreated(),
			CreatorSidecarId: record.creatorSidecarId,
			Granted:          self.authority != nil && self.authority.HonorsRecord(record.creatorSidecarId, record.alias, now),
		})
	}
	return burners, nil
}

// One family's honored records, sorted by key.
func (self *MailConfig) snapshot(burner bool) ([]*mailConfigName, []*mailConfigRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.synced {
		return nil, nil, ErrMailConfigNotSynced
	}
	entries := self.addressEntries
	if burner {
		entries = self.burnerEntries
	}
	keys := make([]string, 0, len(entries))
	for key, entry := range entries {
		if entry.record != nil && !entry.unreadable {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	names := make([]*mailConfigName, 0, len(keys))
	records := make([]*mailConfigRecord, 0, len(keys))
	for _, key := range keys {
		entry := entries[key]
		names = append(names, &mailConfigName{burner: burner, key: key, alias: entry.record.alias, path: entry.path})
		records = append(records, entry.record)
	}
	return names, records, nil
}
