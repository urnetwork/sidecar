//go:build !ios_extension

// §15.8's vault entries (R-MAIL-4, R-MAIL-6, R-CTX-25, D-MAIL-5; owner decision 61; MAIL-M8-02): vault/<h>/<entry_id>
// in a member's mailbox holds one VaultEntry, the title, username, password and its history, RFC 6238 one-time auth
// (mail_totp.go), URLs, notes and Used at of an id, a group or a burner.
//
//	readers   only the owner's consented devices (§8.5) read or write an entry or its Used at: every call first asks
//	          the authority whether this sidecar is consented for the mailbox's owner (SidecarAuthority.Consented,
//	          ACL's one predicate) and refuses otherwise, an absent authority included; no daemon method, ur command
//	          or MCP tool reaches a MailVault, so agents reach entries by no path here (question
//	          mail-m8-02-vault-readers holds what keeps a mailbox's other readers out)
//	slots     the mailbox is record-class, so each chain of an entry's file keeps its key in a slot of its own
//	          (evs_plan.go): a diff seals under its chain's slot key and a checkpoint draws a new slot, whose one key
//	          sits at index 0 (evs_upload.go)
//	put       PutVaultEntry writes the caller's fields over the newest version, keeping created, Used at and the
//	          earlier passwords, the replaced password joining password_history, oldest first; a burned entry stays
//	          burned, since its label is never reissued (§15.9); a write is a path CAS on the version read, so a
//	          racing device's write makes it read and apply again; an entry with no id is new, under 16 random bytes
//	used at   NoteUsedAt, ingest's call when mail for a burner arrives on a consented device, keeps each sender's
//	          registrable domain (the public suffix list's eTLD+1) with its first and last times, earliest and latest
//	          kept across devices, restarts and any order of arrival; a use within UsedAtRefreshInterval of the last
//	          writes nothing, since every write keeps a version for the entry's life (format 1)
//	delete    DeleteVaultEntry shreds every version (owner decision 61): History names each retained version's
//	          slots, one ERASE under one erasure id destroys every key they hold, complete, its note the entry's path,
//	          then the path is removed, held to the version it stands at; a version a racing writer committed in
//	          between is named by another ERASE of the same erasure before the removal goes again; the ERASE goes
//	          first, so a crash between leaves no version openable and only the removal to finish, which
//	          ResumeVaultDeletions, or the delete called again, finishes from evs's erasures on any of the owner's
//	          devices (§11.12's reconcile row); a path no slot or walk reaches, a general repo's or one removed
//	          without this ERASE (question mail-m8-02-history-of-a-removed-path), is refused, never answered shredded
//	erased    an entry a committed vault ERASE names is never read again, since a version whose slot key is gone
//	          reads as tamper; its id never takes a new entry
//	never     no index covers vault/ (D-MAIL-16, D-EVS-43), since a mailbox's other readers may not read it, and this
//	          writes nothing outside vault/; a password or secret reaches no log or error (I-7, I-13), only the store
//	          and testHookSecret, at every open and write and at each code (mail_totp.go)
//
// The note an ERASE of this file carries (the caller's part of evs_erase.go's note) is the erased entry's path, one
// per line: each path whose every key the ERASE destroys, so a reader tells a vault erasure from mail's by the path.
//
// mailVaultEvsStore is the store over the mailbox's EvsRepo. It writes, where mailEvsStore holds every write (question
// mail-m7-06-evs-path-precondition): an update names evs's EvsPathWrite.IfVersion, the CAS from the caller's read to
// the commit, and a creation is of a path whose last name is an id its writer drew at random, which no other writer
// creates, read first and created only while it stands absent.
//
// On every leg but the extension's: a page Worker reads its owner's entries as a phone does. MailVault is safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// This sidecar is not a consented device of the mailbox's owner (§8.5), or no authority says it is: nothing is
	// read or written.
	ErrMailVaultNotConsented = errors.New("mail vault: not a consented device of the mailbox's owner")
	// No entry stands at that id, or none for that address.
	ErrMailVaultEntryAbsent = errors.New("mail vault: no such entry")
	// A committed ERASE shredded the entry at that id, which takes no new entry.
	ErrMailVaultEntryDeleted = errors.New("mail vault: the entry was deleted")
	// An entry no vault holds: an id that is not 16 bytes, a field out of shape, or past EntryMaxByteCount. The error
	// names no value.
	ErrMailVaultEntryInvalid = errors.New("mail vault: entry invalid")
	// A version whose keys ride no slot, as a general repo's do, which no per-entry erasure reaches: nothing erased.
	ErrMailVaultNotShreddable = errors.New("mail vault: a version whose keys no slot holds")
	// A sender's domain with no registrable domain: not a host name, or a public suffix itself.
	ErrMailVaultDomainInvalid = errors.New("mail vault: no registrable domain")
)

// The key a record-class chain's slot holds, at the one index evs_upload.go draws.
const mailVaultSlotKeyIndex = 0

// What MailVault is tuned by (MAIL-M8-02).
type MailVaultSettings struct {
	// The most one entry's bytes take, encoded: a reader refuses past it and a writer writes nothing past it.
	// Phones mirror vault/ in full (§18.4), so an entry stays small; 64 KiB holds pages of notes. Non-positive takes 1.
	EntryMaxByteCount int
	// The earlier passwords an entry keeps, the oldest dropped first: 32, past any rotation a person keeps track of.
	// Non-positive keeps none.
	PasswordHistoryMaxCount int
	// The registrable domains Used at keeps per entry, the one used longest ago dropped first: 64, past what a burner
	// made for one site meets. Non-positive keeps none, so a use writes nothing.
	UsedAtMaxCount int
	// A use of a domain within this of its recorded last time writes nothing: every write keeps a version for the
	// entry's life (format 1), and Used at says when, not how often, so an hour bounds a busy burner's versions to
	// 24 a day a domain. Non-positive writes every later use.
	UsedAtRefreshInterval time.Duration
	// How long NoteUsedAt keeps the address index it read before an address it does not hold reads every entry
	// again: an entry another device made is found on the next read, and a run of mail to an address no entry holds
	// reads the vault once a minute at most. Non-positive reads again at every miss.
	AddressIndexRefreshInterval time.Duration
	// How many times a writer reads again after a conflict on its entry, or a deletion after a version a racing
	// writer committed, before it gives the conflict back: 8, past the few devices one member has. Non-positive
	// tries once.
	WriteRetryCount int
}

// The one default.
func DefaultMailVaultSettings() *MailVaultSettings {
	return &MailVaultSettings{
		EntryMaxByteCount:           64 * 1024,
		PasswordHistoryMaxCount:     32,
		UsedAtMaxCount:              64,
		UsedAtRefreshInterval:       time.Hour,
		AddressIndexRefreshInterval: time.Minute,
		WriteRetryCount:             8,
	}
}

// What MailVault asks of the authorization log: §8.5's consented(d, M), which SidecarAuthority answers.
type MailVaultAuthority interface {
	// Whether sidecarId is a consented device of memberId.
	Consented(sidecarId Id, memberId Id) bool
}

// What MailVault needs of the mailbox's main ref beyond mailStore. Implementations are safe for concurrent use.
type mailVaultStore interface {
	mailStore
	// Every retained version of path, newest first, a removal at the head included, each with the slots its records
	// name; ErrEvsPathAbsent where the path never stood.
	Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error)
	// Removes path, held to the version it stands at: a *MailStoreConflictError where it stands at another,
	// ErrEvsPathAbsent where it stands no more.
	Remove(ctx context.Context, path string, ifVersion uint64) error
	// One ERASE (evs_erase.go); one naming only keys gone already counts done.
	Erase(ctx context.Context, args *EvsEraseArgs) error
	// The committed ERASEs after afterVersion of the repo's erasure ref, oldest first, each with its note.
	Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
}

// What NewMailVault builds on.
type MailVaultArgs struct {
	// The member's mailbox (§15.7): record-class and owner-bound.
	Repo *EvsRepo
	// The mailbox's owner, whose consented devices alone read and write its vault.
	OwnerMemberId Id
	// This sidecar.
	SidecarId Id
	// Nil refuses every call.
	Authority MailVaultAuthority
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailVaultSettings.
	Settings *MailVaultSettings
}

// One member's vault entries in its mailbox. See the file header. Safe for concurrent use.
type MailVault struct {
	store         mailVaultStore
	ownerMemberId Id
	sidecarId     Id
	authority     MailVaultAuthority
	clock         Clock
	log           Logger
	settings      *MailVaultSettings

	stateLock sync.Mutex
	// Each vault path a committed ERASE named, with that erasure's id, read through erasuresThrough of the erasure ref.
	erasedPathIds   map[string]Id
	erasuresThrough uint64
	// Each address's entries, from the newest whole read and this vault's own writes since; read at addressIndexTime,
	// zero before the first.
	addressEntryIds  map[string][]Id
	addressIndexTime time.Time
}

// The vault of args.Repo's mailbox.
func NewMailVault(args *MailVaultArgs) (*MailVault, error) {
	if args == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: no mailbox", ErrMailVaultEntryInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailVaultSettings()
	}
	store := &mailVaultEvsStore{mailEvsStore: newMailEvsStore(args.Repo, nil), settings: settings}
	return newMailVault(store, args.OwnerMemberId, args.SidecarId, args.Authority, args.Clock, args.Log, settings), nil
}

// A vault over store.
func newMailVault(store mailVaultStore, ownerMemberId Id, sidecarId Id, authority MailVaultAuthority, clock Clock, log Logger, settings *MailVaultSettings) *MailVault {
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailVault{
		store:           store,
		ownerMemberId:   ownerMemberId,
		sidecarId:       sidecarId,
		authority:       authority,
		clock:           clockOrReal(clock),
		log:             log,
		settings:        settings,
		erasedPathIds:   map[string]Id{},
		addressEntryIds: map[string][]Id{},
	}
}

// Every entry that stands, by creation time, then id. An entry that does not decode as its path's is passed over, its
// id logged; one a committed ERASE named is never read.
func (self *MailVault) VaultEntries(ctx context.Context) ([]*protocol.VaultEntry, error) {
	if err := self.consented(); err != nil {
		return nil, err
	}
	erased, err := self.refreshErasures(ctx)
	if err != nil {
		return nil, err
	}
	entryIds, err := self.listEntryIds(ctx)
	if err != nil {
		return nil, err
	}
	readTime := self.clock.Now()
	entries := []*protocol.VaultEntry{}
	addressEntryIds := map[string][]Id{}
	for _, entryId := range entryIds {
		path := MailVaultPath(entryId)
		if _, ok := erased[path]; ok {
			continue
		}
		entry, _, err := self.readEntry(ctx, entryId)
		switch {
		case errors.Is(err, ErrEvsPathAbsent):
			// listed, then removed
			continue
		case errors.Is(err, ErrMailVaultEntryInvalid):
			self.log.Infof("[mail] vault entry %s does not decode as its path's, passed over", entryId)
			continue
		case err != nil:
			return nil, err
		}
		entries = append(entries, entry)
		if address := entry.GetAddress(); address != "" {
			addressEntryIds[address] = append(addressEntryIds[address], entryId)
		}
	}
	slices.SortFunc(entries, func(a *protocol.VaultEntry, b *protocol.VaultEntry) int {
		if a.GetCreated() != b.GetCreated() {
			return mailCompareUint64(a.GetCreated(), b.GetCreated())
		}
		return bytes.Compare(a.GetEntryId(), b.GetEntryId())
	})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.addressEntryIds = addressEntryIds
		self.addressIndexTime = readTime
	}()
	return entries, nil
}

// The entry at entryId: ErrMailVaultEntryAbsent where none stands, ErrMailVaultEntryDeleted where an ERASE took it.
func (self *MailVault) VaultEntry(ctx context.Context, entryId Id) (*protocol.VaultEntry, error) {
	if err := self.consented(); err != nil {
		return nil, err
	}
	entry, _, err := self.openEntry(ctx, entryId)
	return entry, err
}

// The entry's Used at, the most recently used domain first, then by domain.
func (self *MailVault) UsedAt(ctx context.Context, entryId Id) ([]*protocol.VaultUsedAt, error) {
	entry, err := self.VaultEntry(ctx, entryId)
	if err != nil {
		return nil, err
	}
	usedAts := []*protocol.VaultUsedAt{}
	for _, usedAt := range entry.GetUsedAt() {
		usedAts = append(usedAts, proto.Clone(usedAt).(*protocol.VaultUsedAt))
	}
	slices.SortFunc(usedAts, func(a *protocol.VaultUsedAt, b *protocol.VaultUsedAt) int {
		if a.GetLast() != b.GetLast() {
			return mailCompareUint64(b.GetLast(), a.GetLast())
		}
		return strings.Compare(a.GetRegistrableDomain(), b.GetRegistrableDomain())
	})
	return usedAts, nil
}

// Writes entry's fields: a new entry when its entry_id is empty, under 16 random bytes, else the entry at that id,
// created there if none stands. See the file header's put row for what a write keeps. password_history, used_at,
// created and updated are the vault's, and what the caller gives of them is not read. The entry as written.
func (self *MailVault) PutVaultEntry(ctx context.Context, entry *protocol.VaultEntry) (*protocol.VaultEntry, error) {
	if err := self.consented(); err != nil {
		return nil, err
	}
	update, err := mailVaultCheckedUpdate(entry)
	if err != nil {
		return nil, err
	}
	var entryId Id
	if len(update.GetEntryId()) == 0 {
		// never fails: since Go 1.24 a broken system generator crashes the program instead
		cryptorand.Read(entryId[:])
		update.EntryId = entryId.Bytes()
	} else {
		entryId, _ = IdFromBytes(update.GetEntryId())
	}
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current, version, err := self.openEntry(ctx, entryId)
		switch {
		case errors.Is(err, ErrMailVaultEntryAbsent):
			current, version = nil, 0
		case err != nil:
			return nil, err
		}
		next := self.merge(current, update)
		if current != nil && mailVaultSameButUpdated(current, next) {
			return current, nil
		}
		_, err = self.writeEntry(ctx, next, version)
		if err == nil {
			self.indexEntry(current, next)
			return next, nil
		}
		if !mailStoreConflictOn(err, MailVaultPath(entryId)) || self.settings.WriteRetryCount <= attempt {
			return nil, err
		}
	}
}

// Notes a use of the burner or id at address by the sender at domain, at: each standing entry for address keeps
// domain's registrable domain with its first and last times (the file header's used at row). ErrMailVaultEntryAbsent
// when no entry holds address; ErrMailVaultDomainInvalid for a domain with no registrable domain.
func (self *MailVault) NoteUsedAt(ctx context.Context, address string, domain string, at time.Time) error {
	if err := self.consented(); err != nil {
		return err
	}
	registrableDomain, ok := mailRegistrableDomain(domain)
	if !ok {
		return ErrMailVaultDomainInvalid
	}
	atMillis := at.UnixMilli()
	if atMillis <= 0 {
		return fmt.Errorf("%w: a use before the epoch", ErrMailVaultEntryInvalid)
	}
	address = dnsAsciiLower(address)
	if address == "" {
		return ErrMailVaultEntryAbsent
	}
	entryIds, err := self.entryIdsOf(ctx, address)
	if err != nil {
		return err
	}
	noted := false
	for _, entryId := range entryIds {
		err := self.noteUsedAt(ctx, entryId, address, registrableDomain, uint64(atMillis))
		switch {
		case err == nil:
			noted = true
		case errors.Is(err, ErrMailVaultEntryAbsent), errors.Is(err, ErrMailVaultEntryDeleted):
			// the index was older than a deletion or a change of address
		default:
			return err
		}
	}
	if !noted {
		return ErrMailVaultEntryAbsent
	}
	return nil
}

// Shreds every version of the entry at entryId (the file header's delete row). nil for an entry deleted already.
func (self *MailVault) DeleteVaultEntry(ctx context.Context, entryId Id) error {
	if err := self.consented(); err != nil {
		return err
	}
	erased, err := self.refreshErasures(ctx)
	if err != nil {
		return err
	}
	path := MailVaultPath(entryId)
	erasureId, resumed := erased[path]
	if !resumed {
		erasureId = NewId()
	} else {
		// erased already: done unless the path still stands, as a crash before the removal leaves it
		stands, err := self.stands(ctx, entryId)
		if err != nil {
			return err
		}
		if !stands {
			self.forgetEntry(path)
			return nil
		}
	}
	return self.shred(ctx, path, erasureId, resumed)
}

// Finishes each deletion a crash left between its ERASE and its removal, on whichever of the owner's devices runs it:
// every entry a committed vault ERASE named that still stands is shredded again under that erasure and removed.
func (self *MailVault) ResumeVaultDeletions(ctx context.Context) error {
	if err := self.consented(); err != nil {
		return err
	}
	erased, err := self.refreshErasures(ctx)
	if err != nil || len(erased) == 0 {
		return err
	}
	entryIds, err := self.listEntryIds(ctx)
	if err != nil {
		return err
	}
	for _, entryId := range entryIds {
		path := MailVaultPath(entryId)
		erasureId, ok := erased[path]
		if !ok {
			continue
		}
		if err := self.shred(ctx, path, erasureId, true); err != nil {
			return err
		}
	}
	return nil
}

// ErrMailVaultNotConsented unless the authority holds this sidecar a consented device of the mailbox's owner.
func (self *MailVault) consented() error {
	if self.authority == nil || !self.authority.Consented(self.sidecarId, self.ownerMemberId) {
		return ErrMailVaultNotConsented
	}
	return nil
}

// The entry at entryId and its version, never read where an ERASE took it.
func (self *MailVault) openEntry(ctx context.Context, entryId Id) (*protocol.VaultEntry, uint64, error) {
	erased, err := self.refreshErasures(ctx)
	if err != nil {
		return nil, 0, err
	}
	if _, ok := erased[MailVaultPath(entryId)]; ok {
		return nil, 0, ErrMailVaultEntryDeleted
	}
	entry, version, err := self.readEntry(ctx, entryId)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, 0, ErrMailVaultEntryAbsent
	}
	return entry, version, err
}

// The newest version of the entry at entryId, checked against its path: ErrEvsPathAbsent where none stands.
func (self *MailVault) readEntry(ctx context.Context, entryId Id) (*protocol.VaultEntry, uint64, error) {
	content, version, err := self.store.Read(ctx, MailVaultPath(entryId), max(1, self.settings.EntryMaxByteCount))
	if errors.Is(err, ErrMailStoreTooLarge) {
		return nil, 0, fmt.Errorf("%w: past its bound", ErrMailVaultEntryInvalid)
	}
	if err != nil {
		return nil, 0, err
	}
	entry := &protocol.VaultEntry{}
	if err := proto.Unmarshal(content, entry); err != nil {
		return nil, 0, fmt.Errorf("%w: does not decode", ErrMailVaultEntryInvalid)
	}
	if !bytes.Equal(entry.GetEntryId(), entryId[:]) {
		return nil, 0, fmt.Errorf("%w: another path's", ErrMailVaultEntryInvalid)
	}
	mailVaultHookSecrets(entry)
	return entry, version, nil
}

// Writes entry held to ifVersion, 0 creating it: its new version.
func (self *MailVault) writeEntry(ctx context.Context, entry *protocol.VaultEntry, ifVersion uint64) (uint64, error) {
	content, err := mailVaultEncode(entry, self.settings)
	if err != nil {
		return 0, err
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	mailVaultHookSecrets(entry)
	testHookBarrier("mail.vault.write.before", "")
	versions, err := self.store.Write(ctx, []*mailStoreWrite{{Path: MailVaultPath(entryId), Content: content, IfVersion: ifVersion}})
	testHookBarrier("mail.vault.write.after", "")
	if err != nil {
		return 0, err
	}
	return versions[0], nil
}

// What a Put writes over current, nil for a new entry: see the file header's put row.
func (self *MailVault) merge(current *protocol.VaultEntry, update *protocol.VaultEntry) *protocol.VaultEntry {
	next := proto.Clone(update).(*protocol.VaultEntry)
	nowMillis := uint64(max(1, self.clock.Now().UnixMilli()))
	next.UsedAt = nil
	next.PasswordHistory = nil
	if current == nil {
		next.Created, next.Updated = nowMillis, nowMillis
		if next.GetState() == protocol.VaultEntryState_VAULT_ENTRY_STATE_UNSPECIFIED {
			next.State = protocol.VaultEntryState_VAULT_ENTRY_LIVE
		}
		return next
	}
	next.Created = current.GetCreated()
	next.Updated = max(nowMillis, current.GetUpdated())
	for _, usedAt := range current.GetUsedAt() {
		next.UsedAt = append(next.UsedAt, proto.Clone(usedAt).(*protocol.VaultUsedAt))
	}
	history := slices.Clone(current.GetPasswordHistory())
	if current.GetPassword() != "" && current.GetPassword() != next.GetPassword() {
		history = append(history, current.GetPassword())
	}
	if keep := max(0, self.settings.PasswordHistoryMaxCount); keep < len(history) {
		history = history[len(history)-keep:]
	}
	next.PasswordHistory = history
	switch {
	case current.GetState() == protocol.VaultEntryState_VAULT_ENTRY_BURNED:
		next.State = protocol.VaultEntryState_VAULT_ENTRY_BURNED
	case next.GetState() == protocol.VaultEntryState_VAULT_ENTRY_STATE_UNSPECIFIED:
		next.State = current.GetState()
	}
	return next
}

// One entry's use, read and written again until it lands or a conflict outlasts the retries.
func (self *MailVault) noteUsedAt(ctx context.Context, entryId Id, address string, registrableDomain string, atMillis uint64) error {
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, version, err := self.openEntry(ctx, entryId)
		if err != nil {
			return err
		}
		if current.GetAddress() != address {
			return ErrMailVaultEntryAbsent
		}
		next := proto.Clone(current).(*protocol.VaultEntry)
		if !mailVaultNoteUse(next, registrableDomain, atMillis, self.settings) {
			return nil
		}
		_, err = self.writeEntry(ctx, next, version)
		if err == nil {
			return nil
		}
		if !mailStoreConflictOn(err, MailVaultPath(entryId)) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}

// Every retained version's keys erased under erasureId, then the path removed (the file header's delete row). erased
// says a committed ERASE named the path already, so a path that no longer stands is done.
func (self *MailVault) shred(ctx context.Context, path string, erasureId Id, erased bool) error {
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		versions, err := self.store.Versions(ctx, path)
		if errors.Is(err, ErrEvsPathAbsent) || (err == nil && len(versions) == 0) {
			if erased {
				return nil
			}
			return ErrMailVaultEntryAbsent
		}
		if err != nil {
			return err
		}
		keys := []*EvsErasedKey{}
		for _, version := range versions {
			if version.Removed {
				continue
			}
			if len(version.SlotIds) == 0 {
				return ErrMailVaultNotShreddable
			}
			for _, slotId := range version.SlotIds {
				if !slices.ContainsFunc(keys, func(key *EvsErasedKey) bool { return key.SlotId == slotId }) {
					keys = append(keys, &EvsErasedKey{SlotId: slotId, KeyIndex: mailVaultSlotKeyIndex})
				}
			}
		}
		newest := versions[0]
		if len(keys) == 0 {
			// only a removal: done when this vault's ERASE went before it, else versions no walk reached, which no
			// erasure named and none can, so nothing claims them shredded
			if newest.Removed && erased {
				self.forgetEntry(path)
				return nil
			}
			return ErrMailVaultNotShreddable
		}
		testHookBarrier("mail.vault.erase.before", "")
		err = self.store.Erase(ctx, &EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true, Note: []byte(path)})
		testHookBarrier("mail.vault.erase.after", "")
		if err != nil {
			return err
		}
		erased = true
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.erasedPathIds[path] = erasureId
		}()
		if newest.Removed {
			self.forgetEntry(path)
			return nil
		}
		testHookBarrier("mail.vault.remove.before", "")
		err = self.store.Remove(ctx, path, newest.Version)
		testHookBarrier("mail.vault.remove.after", "")
		switch {
		case err == nil, errors.Is(err, ErrEvsPathAbsent):
			self.forgetEntry(path)
			return nil
		case mailStoreConflictOn(err, path) && attempt < self.settings.WriteRetryCount:
			// a version written since History read: the next round names its slots too
		default:
			return err
		}
	}
}

// The vault's view of the erasure ref, read on from where it last read: each vault path a committed ERASE named, with
// that erasure's id.
func (self *MailVault) refreshErasures(ctx context.Context) (map[string]Id, error) {
	through := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.erasuresThrough
	}()
	erasures, err := self.store.Erasures(ctx, through)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, erasure := range erasures {
		for _, path := range mailVaultErasedPaths(erasure.Note) {
			self.erasedPathIds[path] = erasure.ErasureId
		}
		self.erasuresThrough = max(self.erasuresThrough, erasure.Version)
	}
	erased := make(map[string]Id, len(self.erasedPathIds))
	for path, erasureId := range self.erasedPathIds {
		erased[path] = erasureId
	}
	return erased, nil
}

// The ids of every entry vault/ lists, in shard then name order: a name that is not an entry id in its own shard is
// passed over.
func (self *MailVault) listEntryIds(ctx context.Context) ([]Id, error) {
	shards, err := self.store.List(ctx, mailVaultFamily)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	slices.Sort(shards)
	entryIds := []Id{}
	for _, shard := range shards {
		if len(shard) != 2 || !isDnsLowerBytes(shard, "") {
			continue
		}
		names, err := self.store.List(ctx, mailVaultFamily+"/"+shard)
		if errors.Is(err, ErrEvsPathAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		slices.Sort(names)
		for _, name := range names {
			entryId, ok := parseMailVaultEntryName(name)
			if ok && MailShard(name) == shard {
				entryIds = append(entryIds, entryId)
			}
		}
	}
	return entryIds, nil
}

// Whether the entry's path still stands, by its shard's listing, which opens no version.
func (self *MailVault) stands(ctx context.Context, entryId Id) (bool, error) {
	name := mailBinaryName(entryId[:])
	names, err := self.store.List(ctx, mailVaultFamily+"/"+MailShard(name))
	if errors.Is(err, ErrEvsPathAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return slices.Contains(names, name), nil
}

// The entries the index holds for address, read again where it holds none and is older than
// AddressIndexRefreshInterval.
func (self *MailVault) entryIdsOf(ctx context.Context, address string) ([]Id, error) {
	entryIds, stale := func() ([]Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entryIds := slices.Clone(self.addressEntryIds[address])
		stale := self.addressIndexTime.IsZero() || self.addressIndexTime.Add(self.settings.AddressIndexRefreshInterval).Compare(self.clock.Now()) <= 0
		return entryIds, stale
	}()
	if 0 < len(entryIds) || !stale {
		return entryIds, nil
	}
	if _, err := self.VaultEntries(ctx); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.addressEntryIds[address]), nil
}

// Keeps the index current with a write of next over current, nil for a new entry.
func (self *MailVault) indexEntry(current *protocol.VaultEntry, next *protocol.VaultEntry) {
	entryId, _ := IdFromBytes(next.GetEntryId())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if current != nil && current.GetAddress() != next.GetAddress() {
		self.addressEntryIds[current.GetAddress()] = slices.DeleteFunc(self.addressEntryIds[current.GetAddress()], func(other Id) bool { return other == entryId })
	}
	if address := next.GetAddress(); address != "" && !slices.Contains(self.addressEntryIds[address], entryId) {
		self.addressEntryIds[address] = append(self.addressEntryIds[address], entryId)
	}
}

// Drops a shredded entry from the index.
func (self *MailVault) forgetEntry(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for address, entryIds := range self.addressEntryIds {
		self.addressEntryIds[address] = slices.DeleteFunc(entryIds, func(entryId Id) bool { return MailVaultPath(entryId) == path })
	}
}

// The caller's entry as a Put takes it, checked and with its address in lowercase: ErrMailVaultEntryInvalid, naming
// no value, for one no vault holds.
func mailVaultCheckedUpdate(entry *protocol.VaultEntry) (*protocol.VaultEntry, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: no entry", ErrMailVaultEntryInvalid)
	}
	update := proto.Clone(entry).(*protocol.VaultEntry)
	if entryId := update.GetEntryId(); len(entryId) != 0 && len(entryId) != len(Id{}) {
		return nil, fmt.Errorf("%w: an id of %d bytes", ErrMailVaultEntryInvalid, len(entryId))
	}
	update.Address = dnsAsciiLower(update.GetAddress())
	if MailAddressMaxByteCount < len(update.GetAddress()) || strings.ContainsAny(update.GetAddress(), " \x00/") {
		return nil, fmt.Errorf("%w: an address out of shape", ErrMailVaultEntryInvalid)
	}
	switch update.GetState() {
	case protocol.VaultEntryState_VAULT_ENTRY_STATE_UNSPECIFIED, protocol.VaultEntryState_VAULT_ENTRY_LIVE, protocol.VaultEntryState_VAULT_ENTRY_BURNED:
	default:
		return nil, fmt.Errorf("%w: state %d", ErrMailVaultEntryInvalid, update.GetState())
	}
	if totp := update.GetTotp(); totp != nil {
		if err := mailTotpCheck(totp); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMailVaultEntryInvalid, err)
		}
	}
	texts := append([]string{update.GetAddress(), update.GetTitle(), update.GetUsername(), update.GetPassword(), update.GetNotes()}, update.GetUrls()...)
	for _, text := range texts {
		if !utf8.ValidString(text) {
			return nil, fmt.Errorf("%w: a field that is not UTF-8", ErrMailVaultEntryInvalid)
		}
	}
	return update, nil
}

// entry's bytes as MAIL-FORMAT.md writes every value, deterministic: ErrMailVaultEntryInvalid past EntryMaxByteCount.
func mailVaultEncode(entry *protocol.VaultEntry, settings *MailVaultSettings) ([]byte, error) {
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("%w: does not encode", ErrMailVaultEntryInvalid)
	}
	if max(1, settings.EntryMaxByteCount) < len(content) {
		return nil, fmt.Errorf("%w: %d bytes", ErrMailVaultEntryInvalid, len(content))
	}
	return content, nil
}

// Whether next differs from current in nothing but updated, so a Put has nothing to write.
func mailVaultSameButUpdated(current *protocol.VaultEntry, next *protocol.VaultEntry) bool {
	unchanged := proto.Clone(next).(*protocol.VaultEntry)
	unchanged.Updated = current.GetUpdated()
	return proto.Equal(unchanged, current)
}

// Adds a use of registrableDomain at atMillis to entry's Used at: false when it changes nothing worth a version (the
// file header's used at row).
func mailVaultNoteUse(entry *protocol.VaultEntry, registrableDomain string, atMillis uint64, settings *MailVaultSettings) bool {
	if settings.UsedAtMaxCount <= 0 {
		return false
	}
	for _, usedAt := range entry.GetUsedAt() {
		if usedAt.GetRegistrableDomain() != registrableDomain {
			continue
		}
		changed := false
		if atMillis < usedAt.GetFirst() {
			usedAt.First = atMillis
			changed = true
		}
		if usedAt.GetLast() < atMillis && (settings.UsedAtRefreshInterval <= 0 || uint64(settings.UsedAtRefreshInterval.Milliseconds()) <= atMillis-usedAt.GetLast()) {
			usedAt.Last = atMillis
			changed = true
		}
		return changed
	}
	entry.UsedAt = append(entry.UsedAt, &protocol.VaultUsedAt{RegistrableDomain: registrableDomain, First: atMillis, Last: atMillis})
	for settings.UsedAtMaxCount < len(entry.GetUsedAt()) {
		oldest := 0
		for index, usedAt := range entry.GetUsedAt() {
			if usedAt.GetLast() < entry.GetUsedAt()[oldest].GetLast() {
				oldest = index
			}
		}
		entry.UsedAt = slices.Delete(entry.UsedAt, oldest, oldest+1)
	}
	return true
}

// The registrable domain of a sender's domain, the public suffix list's eTLD+1, in lowercase: false for a name that is
// not an LDH host name, ends in a numeric label, or is a public suffix itself.
func mailRegistrableDomain(domain string) (string, bool) {
	domain = strings.TrimSuffix(dnsAsciiLower(domain), ".")
	if domain == "" || dnsDomainMaxByteCount < len(domain) {
		return "", false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if !isDnsLowerLdhLabel(label) {
			return "", false
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		// an address, not a name
		return "", false
	}
	registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", false
	}
	return registrableDomain, true
}

// Each vault path note names, one per line, as this file's ERASEs write it: none for a note of another shape.
func mailVaultErasedPaths(note []byte) []string {
	paths := []string{}
	for _, line := range strings.Split(string(note), "\n") {
		if _, ok := parseMailVaultPath(line); !ok {
			return nil
		}
		paths = append(paths, line)
	}
	return paths
}

// The entry id of a vault/<h>/<entry_id> path as MailVaultPath spells it, false for any other.
func parseMailVaultPath(path string) (Id, bool) {
	rest, ok := strings.CutPrefix(path, mailVaultFamily+"/")
	if !ok {
		return Id{}, false
	}
	_, name, ok := strings.Cut(rest, "/")
	if !ok {
		return Id{}, false
	}
	entryId, ok := parseMailVaultEntryName(name)
	if !ok || MailVaultPath(entryId) != path {
		return Id{}, false
	}
	return entryId, true
}

// An entry id from the name MailVaultPath spells it by, false for a name of any other spelling.
func parseMailVaultEntryName(name string) (Id, bool) {
	decoded, err := evsTokenEncoding.DecodeString(name)
	if err != nil || len(decoded) != len(Id{}) {
		return Id{}, false
	}
	entryId := Id(decoded)
	if mailBinaryName(entryId[:]) != name {
		return Id{}, false
	}
	return entryId, true
}

// Reports an entry's secrets to the privacy harness, which scans every capture for them.
func mailVaultHookSecrets(entry *protocol.VaultEntry) {
	if password := entry.GetPassword(); password != "" {
		testHookSecret("vault_password", []byte(password))
	}
	for _, password := range entry.GetPasswordHistory() {
		if password != "" {
			testHookSecret("vault_password", []byte(password))
		}
	}
	if secret := entry.GetTotp().GetSecret(); len(secret) != 0 {
		testHookSecret("vault_totp_secret", secret)
	}
}

// -1, 0 or 1 as a is below, at or above b.
func mailCompareUint64(a uint64, b uint64) int {
	switch {
	case a < b:
		return -1
	case b < a:
		return 1
	}
	return 0
}

// The vault's store over the mailbox's EvsRepo: see the file header. Safe for concurrent use.
type mailVaultEvsStore struct {
	*mailEvsStore
	settings *MailVaultSettings
}

// Writes every path in one push through evs, each held to its IfVersion: an update by EvsPathWrite.IfVersion, a
// creation read first and created only while it stands absent (the file header).
func (self *mailVaultEvsStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	paths := []string{}
	pathWrites := []*EvsPathWrite{}
	for _, write := range writes {
		paths = append(paths, write.Path)
		if write.IfVersion == 0 {
			_, _, err := self.mailEvsStore.Read(ctx, write.Path, max(1, self.settings.EntryMaxByteCount))
			switch {
			case err == nil, errors.Is(err, ErrMailStoreTooLarge):
				return nil, &MailStoreConflictError{Paths: []string{write.Path}}
			case !errors.Is(err, ErrEvsPathAbsent):
				return nil, err
			}
		}
		pathWrites = append(pathWrites, &EvsPathWrite{Path: write.Path, Content: bytes.NewReader(write.Content), IfVersion: write.IfVersion})
	}
	result, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: self.refName, Writes: pathWrites})
	if errors.Is(err, ErrEvsPathMoved) || evsCreationConflict(err) {
		return nil, &MailStoreConflictError{Paths: paths}
	}
	if err != nil {
		return nil, err
	}
	return result.PathVersions, nil
}

// History's walk, page after page of HistoryVersionCount, to the path's first version, each version below the one
// before it. A walk that stops descending ends there: evs answers a read by number of a removed path's older version
// with the removal again, so History of a removed path repeats its removal and reaches none of the versions before
// it (question mail-m8-02-history-of-a-removed-path), which shred then refuses unless the vault erased them first.
func (self *mailVaultEvsStore) Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error) {
	versions := []*EvsHistoryVersion{}
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
			versions = append(versions, version)
			descended = true
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

// A removal through evs, held to ifVersion.
func (self *mailVaultEvsStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	_, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: self.refName, Writes: []*EvsPathWrite{{Path: path, Remove: true, IfVersion: ifVersion}}})
	if errors.Is(err, ErrEvsPathMoved) || evsCreationConflict(err) {
		return &MailStoreConflictError{Paths: []string{path}}
	}
	return err
}

// EvsRepo.Erase.
func (self *mailVaultEvsStore) Erase(ctx context.Context, args *EvsEraseArgs) error {
	_, err := self.repo.Erase(ctx, args)
	return err
}

// EvsRepo.ReadErasures.
func (self *mailVaultEvsStore) Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error) {
	return self.repo.ReadErasures(ctx, afterVersion)
}
