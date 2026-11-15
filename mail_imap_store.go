//go:build !ios_extension

// What IMAP sees of a member's mailbox (R-MAIL-1, R-MAIL-13, D-MAIL-5, D-MAIL-11, §2.18; MAIL-M8-06): the folders
// INBOX, Sent, Trash, Spam and one a label, each a snapshot of MailView's list with local UIDs (mail_imap_uid.go),
// each message's flags, size and date, its raw bytes on FETCH, and STORE as f/ ops through MailFlagWriter, so a
// client's \Seen reaches every device. It decides nothing: every flag and label is what f/ holds and every entry
// what ingest sealed.
//
//	INBOX    MailFolderInbox: not spam, not sent, not in trash
//	Sent     MailFolderSent, \Sent
//	Trash    MailFolderTrash, \Trash
//	Spam     MailFolderSpam, \Junk
//	<label>  MailFolderLabel for each label a message carries, under its own name; one that would read as one of
//	         the four above, or that holds the hierarchy delimiter or a control character, is not shown
//	flags    \Seen is MAIL_FLAG_SEEN and \Flagged MAIL_FLAG_FLAGGED; \Deleted is MAIL_FLAG_TRASH outside Trash, so
//	         deleting a message moves it to Trash, where §15.7's 30-day shred applies, and inside Trash clearing it
//	         restores the message. Nothing here erases: ERASE is erasure's own (§15.7), and its hint reaches the
//	         store through MailLocalPurge
//
// Erasure (MailLocalPurge): PurgeMail tombstones each message in the UID store, so no folder shows it or gives it a
// UID again, and wakes every selected session to expunge it. A read of a purged message's bytes refuses, as the
// mailbox's own reads do: its keys are gone, and the store never holds a copy of its own, so it can resurrect
// nothing (§2.18). A copy a client made before is beyond recall, which §2.18 discloses.
//
// The store holds no message: each folder's snapshot is its keys, entries and flags, read again at each Select,
// Poll and Idle wake. Safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// No folder by that name.
	ErrMailImapFolderAbsent = errors.New("mail imap: no such folder")
	// A folder holds more messages than MailImapSettings.FolderMaxMessageCount, or the UIDs ran out.
	ErrMailImapFolderTooLarge = errors.New("mail imap: the folder holds more than the store lists")
	ErrMailImapUidsExhausted  = errors.New("mail imap: the folder's UIDs are exhausted")
	// The message was purged here: its keys are gone.
	ErrMailImapMessagePurged = errors.New("mail imap: the message was erased")
	// A flag change the store does not make.
	ErrMailImapFlagRefused = errors.New("mail imap: that flag is not stored")
)

// The four folders every mailbox has.
const (
	MailImapFolderInbox = "INBOX"
	MailImapFolderSent  = "Sent"
	MailImapFolderTrash = "Trash"
	MailImapFolderSpam  = "Spam"
	// The hierarchy delimiter IMAP's LIST names; no folder here nests.
	MailImapDelimiter = '/'
)

// The flags IMAP clients see.
const (
	MailImapFlagSeen    = `\Seen`
	MailImapFlagFlagged = `\Flagged`
	MailImapFlagDeleted = `\Deleted`
)

// The store's tunables.
type MailImapSettings struct {
	// The most messages one folder lists: 100,000, a mailbox of §18.4's size. A larger folder refuses Select
	// rather than showing part of itself.
	FolderMaxMessageCount int
	// The most bytes a message's raw read takes: 64 MiB, past every tier's mail_inbound_message_bytes.
	BodyMaxByteCount int
	// Tombstones kept, the oldest going first: 65,536.
	TombstoneMaxCount int
	// The most bytes a UID file decodes: 32 MiB, room for a folder at FolderMaxMessageCount.
	UidFileMaxByteCount int
	// The most label folders listed: 1,000.
	LabelFolderMaxCount int
}

func DefaultMailImapSettings() *MailImapSettings {
	return &MailImapSettings{
		FolderMaxMessageCount: 100000,
		BodyMaxByteCount:      64 * 1024 * 1024,
		TombstoneMaxCount:     64 * 1024,
		UidFileMaxByteCount:   32 * 1024 * 1024,
		LabelFolderMaxCount:   1000,
	}
}

// One folder as LIST shows it.
type MailImapFolder struct {
	Name string
	// \Sent, \Trash or \Junk, or "" for INBOX and a label.
	SpecialUse string
}

// One message as a folder's snapshot holds it.
type MailImapMessage struct {
	Uid   uint32
	Key   MailImapKey
	Entry *protocol.IndexEntry
	Flags *MailFlags
	Spam  bool
}

// The message's IMAP flags, sorted: \Seen, \Flagged, and \Deleted for a message in trash.
func (self *MailImapMessage) ImapFlags() []string {
	flags := []string{}
	if self.Flags != nil {
		if self.Flags.Seen {
			flags = append(flags, MailImapFlagSeen)
		}
		if self.Flags.Flagged {
			flags = append(flags, MailImapFlagFlagged)
		}
		if self.Flags.Trash {
			flags = append(flags, MailImapFlagDeleted)
		}
	}
	slices.Sort(flags)
	return flags
}

// The message's INTERNALDATE: its reception, as its entry holds it.
func (self *MailImapMessage) InternalDate() time.Time {
	return time.UnixMilli(int64(self.Entry.GetTime())).UTC()
}

// The message's RFC822.SIZE, as its entry holds it.
func (self *MailImapMessage) Size() uint64 {
	return self.Entry.GetSize()
}

// One folder's snapshot: its messages in UID order.
type MailImapSnapshot struct {
	Folder   string
	Validity uint32
	Next     uint32
	Messages []*MailImapMessage
}

// What NewMailImapStore builds on.
type MailImapStoreArgs struct {
	// The member's mailbox and its store.
	MailboxId Id
	Mailbox   mailStore
	// A group repo's store, by id, where an r/ reference's message is. nil hides group messages.
	Groups func(ctx context.Context, repoId Id) (mailStore, error)
	// The mailbox's clock on this device, which every flag op is clocked by.
	Hlc *MailHlc
	// This device, which signs every flag op it writes.
	SidecarId Id
	// The mail component's sealed directory: the UID state goes under its imap/.
	State SidecarStore
	// Nil: real time.
	Clock Clock
	// Nil: DefaultMailStoreSettings.
	StoreSettings *MailStoreSettings
	// Nil: DefaultMailImapSettings.
	Settings *MailImapSettings
}

// See the file header.
type MailImapStore struct {
	mailboxId Id
	mailbox   mailStore
	groups    func(ctx context.Context, repoId Id) (mailStore, error)
	view      *MailView
	flags     *MailFlagWriter
	uids      *mailImapUids
	settings  *MailImapSettings
	// rises at each purge and each flag write here, so a selected session's wait wakes to expunge or to fetch
	// the change
	revision *MonitorValue[uint64]
}

var _ MailLocalPurge = (*MailImapStore)(nil)

// A store over args' mailbox.
func NewMailImapStore(args *MailImapStoreArgs) (*MailImapStore, error) {
	if args == nil || args.Mailbox == nil || args.State == nil || args.Hlc == nil || args.MailboxId == (Id{}) || args.SidecarId == (Id{}) {
		return nil, errors.New("mail imap: a store needs its mailbox, its sealed directory, its clock and its sidecar")
	}
	storeSettings := args.StoreSettings
	if storeSettings == nil {
		storeSettings = DefaultMailStoreSettings()
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailImapSettings()
	}
	state, err := args.State.Directory("imap", "")
	if err != nil {
		return nil, err
	}
	return &MailImapStore{
		mailboxId: args.MailboxId,
		mailbox:   args.Mailbox,
		groups:    args.Groups,
		view: NewMailView(&MailViewArgs{
			MailboxId: args.MailboxId,
			Mailbox:   args.Mailbox,
			Groups:    args.Groups,
			Hlc:       args.Hlc,
			Settings:  storeSettings,
		}),
		flags:    NewMailFlagWriter(args.Mailbox, args.Hlc, args.SidecarId, storeSettings),
		uids:     newMailImapUids(state, clockOrReal(args.Clock), settings),
		settings: settings,
		revision: NewMonitorValue(uint64(0)),
	}, nil
}

// The list a folder name reads, false for a name no folder has.
func (self *MailImapStore) folderArgs(name string) (*MailListArgs, bool) {
	switch {
	case strings.EqualFold(name, MailImapFolderInbox):
		return &MailListArgs{Folder: MailFolderInbox}, true
	case name == MailImapFolderSent:
		return &MailListArgs{Folder: MailFolderSent}, true
	case name == MailImapFolderTrash:
		return &MailListArgs{Folder: MailFolderTrash}, true
	case name == MailImapFolderSpam:
		return &MailListArgs{Folder: MailFolderSpam}, true
	case mailImapLabelFolderValid(name):
		return &MailListArgs{Folder: MailFolderLabel, Label: name}, true
	}
	return nil, false
}

// Whether a label may be a folder: not one of the four, nor INBOX in any case, with no delimiter or control
// character.
func mailImapLabelFolderValid(label string) bool {
	if label == "" || strings.EqualFold(label, MailImapFolderInbox) || label == MailImapFolderSent ||
		label == MailImapFolderTrash || label == MailImapFolderSpam || strings.ContainsRune(label, MailImapDelimiter) {
		return false
	}
	for _, r := range label {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// Every message of a list, newest first, bounded by FolderMaxMessageCount.
func (self *MailImapStore) listAll(ctx context.Context, args *MailListArgs) ([]*MailViewEntry, error) {
	entries := []*MailViewEntry{}
	page := &MailListArgs{Folder: args.Folder, Label: args.Label}
	for {
		listed, err := self.view.List(ctx, page)
		if err != nil {
			return nil, err
		}
		entries = append(entries, listed.Entries...)
		if self.settings.FolderMaxMessageCount < len(entries) {
			return nil, ErrMailImapFolderTooLarge
		}
		if listed.Next == nil {
			return entries, nil
		}
		page.After = listed.Next
	}
}

// The folders LIST shows: the four, then every label a message carries, sorted.
func (self *MailImapStore) Folders(ctx context.Context) ([]*MailImapFolder, error) {
	folders := []*MailImapFolder{
		{Name: MailImapFolderInbox},
		{Name: MailImapFolderSent, SpecialUse: `\Sent`},
		{Name: MailImapFolderTrash, SpecialUse: `\Trash`},
		{Name: MailImapFolderSpam, SpecialUse: `\Junk`},
	}
	self.view.Invalidate()
	entries, err := self.listAll(ctx, &MailListArgs{Folder: MailFolderAll})
	if err != nil {
		return nil, err
	}
	labels := []string{}
	for _, entry := range entries {
		for _, label := range entry.Flags.Labels {
			if mailImapLabelFolderValid(label) && !slices.Contains(labels, label) && len(labels) < self.settings.LabelFolderMaxCount {
				labels = append(labels, label)
			}
		}
	}
	slices.Sort(labels)
	for _, label := range labels {
		folders = append(folders, &MailImapFolder{Name: label})
	}
	return folders, nil
}

// The folder's snapshot as the mailbox stands now: every message it lists with its UID, a message new to the
// folder taking the next, oldest first, and one that left giving its UID up. A purged message is never shown.
func (self *MailImapStore) Select(ctx context.Context, folder string) (*MailImapSnapshot, error) {
	args, ok := self.folderArgs(folder)
	if !ok {
		return nil, ErrMailImapFolderAbsent
	}
	if strings.EqualFold(folder, MailImapFolderInbox) {
		folder = MailImapFolderInbox
	}
	self.view.Invalidate()
	entries, err := self.listAll(ctx, args)
	if err != nil {
		return nil, err
	}
	// oldest first, so new messages take rising UIDs in arrival order
	slices.Reverse(entries)
	keys := make([]MailImapKey, len(entries))
	for index, entry := range entries {
		keys[index] = MailImapKey{RepoId: entry.RepoId, Month: MailYearMonthOf(entry.Entry.GetTime()), Id: mailEntryId(entry.Entry)}
	}
	assignment, err := self.uids.Assign(folder, keys)
	if err != nil {
		return nil, err
	}
	snapshot := &MailImapSnapshot{Folder: folder, Validity: assignment.Validity, Next: assignment.Next}
	for index, entry := range entries {
		uid := assignment.Uids[index]
		if uid == 0 {
			continue
		}
		snapshot.Messages = append(snapshot.Messages, &MailImapMessage{Uid: uid, Key: keys[index], Entry: entry.Entry, Flags: entry.Flags, Spam: entry.Spam})
	}
	slices.SortFunc(snapshot.Messages, func(a *MailImapMessage, b *MailImapMessage) int { return cmp.Compare(a.Uid, b.Uid) })
	return snapshot, nil
}

// The message's raw bytes, as received, bounded by BodyMaxByteCount. A purged message refuses, and so does one
// whose keys the mailbox no longer holds.
func (self *MailImapStore) Body(ctx context.Context, message *MailImapMessage) ([]byte, error) {
	tombstoned, err := self.uids.Tombstoned(message.Key)
	if err != nil {
		return nil, err
	}
	if tombstoned {
		return nil, ErrMailImapMessagePurged
	}
	store := self.mailbox
	if message.Key.RepoId != self.mailboxId {
		if self.groups == nil {
			return nil, ErrMailImapMessagePurged
		}
		if store, err = self.groups(ctx, message.Key.RepoId); err != nil {
			return nil, err
		}
	}
	raw, _, err := store.Read(ctx, MailMessagePath(message.Key.Month, message.Key.Id), self.settings.BodyMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, ErrMailImapMessagePurged
	}
	return raw, err
}

// One flag change a client stores.
type MailImapFlagChange struct {
	// \Seen, \Flagged or \Deleted.
	Flag string
	Set  bool
}

// Stores changes on messages of folder as f/ ops, one push for them all: \Seen and \Flagged as themselves,
// \Deleted as trash outside Trash and its clearing inside Trash. Setting \Deleted in Trash refuses, since nothing
// here erases. Any other flag refuses with ErrMailImapFlagRefused, and nothing is written.
func (self *MailImapStore) SetFlags(ctx context.Context, folder string, messages []*MailImapMessage, changes []*MailImapFlagChange) error {
	writes := []*MailFlagChange{}
	for _, change := range changes {
		var kind protocol.MailFlagKind
		switch change.Flag {
		case MailImapFlagSeen:
			kind = protocol.MailFlagKind_MAIL_FLAG_SEEN
		case MailImapFlagFlagged:
			kind = protocol.MailFlagKind_MAIL_FLAG_FLAGGED
		case MailImapFlagDeleted:
			if folder == MailImapFolderTrash && change.Set {
				return fmt.Errorf("%w: a message in Trash is erased by erasure alone", ErrMailImapFlagRefused)
			}
			kind = protocol.MailFlagKind_MAIL_FLAG_TRASH
		default:
			return fmt.Errorf("%w: %s", ErrMailImapFlagRefused, change.Flag)
		}
		for _, message := range messages {
			writes = append(writes, &MailFlagChange{Month: message.Key.Month, MessageId: message.Key.Id, Kind: kind, Set: change.Set})
		}
	}
	if len(writes) == 0 {
		return nil
	}
	if _, err := self.flags.Apply(ctx, writes); err != nil {
		return err
	}
	self.revision.Update(func(revision uint64) uint64 { return revision + 1 })
	return nil
}

// See MailLocalPurge: tombstones the messages, so no folder shows them or gives them a UID again, and wakes every
// selected session to expunge them. Idempotent.
func (self *MailImapStore) PurgeMail(ctx context.Context, repoId Id, messageIds []Id) error {
	keys := make([]MailImapKey, 0, len(messageIds))
	for _, id := range messageIds {
		keys = append(keys, MailImapKey{RepoId: repoId, Id: id})
	}
	if err := self.uids.Purge(keys); err != nil {
		return err
	}
	self.revision.Update(func(revision uint64) uint64 { return revision + 1 })
	return nil
}

// The store's revision and a channel that closes at the next purge or flag write here: what a selected
// session waits on between its polls, beside the mailbox's own hints.
func (self *MailImapStore) Revision() (uint64, chan struct{}) {
	return self.revision.Get()
}
