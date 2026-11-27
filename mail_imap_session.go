//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// One IMAP session (MAIL-M8-07): go-imap's imapserver.Session on the MailImapStore of the network whose credential
// its LOGIN matched, keeping the selected folder's snapshot as the client last saw it, so its sequence numbers hold
// between commands. Poll and Idle read the folder again and tell the client what moved: EXPUNGE for each message
// gone, highest first, EXISTS for new ones, FETCH FLAGS for flags changed.
//
//	refused   CREATE, DELETE, RENAME, APPEND and COPY: folders follow the mailbox and its labels, and mail enters only
//	          by deposit (§15.7). STORE under EXAMINE, which go-imap leaves to the session
//	flags     \Seen, \Flagged and \Deleted, as MailImapStore keeps them; a FETCH of BODY[] sets \Seen as RFC 9051
//	          §6.4.5 says, BODY.PEEK[] and EXAMINE never
//	erased    a message whose keys are gone answers no byte of its body (§2.18): FETCH leaves it out, never a copy
//
// Safe for concurrent use, which go-imap needs: it drives a session from one goroutine, but when a client ends IDLE
// with anything but DONE, or the connection drops, it moves on without waiting for the session's Idle to return, so
// IDLE's poll can meet the next command or Close. Commands hold commandLock throughout; IDLE's poll holds it only to
// read the session and to apply what it read, never across the read, and applies nothing once its IDLE has stopped
// or the snapshot it read against was replaced. A command that changes the snapshot replaces it, never edits it.

package sidecar

import (
	"bufio"
	"bytes"
	"errors"
	"slices"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	gomessagetextproto "github.com/emersion/go-message/textproto"
)

// What a refused command answers.
var (
	errMailImapNotSupported = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "Folders follow the mailbox; mail arrives only by deposit"}
	errMailImapNoFolder     = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such folder"}
	errMailImapUnavailable  = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "The mailbox cannot be read now"}
	errMailImapFlagRefused  = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "Only \\Seen, \\Flagged and \\Deleted are kept, and nothing here erases"}
	errMailImapReadOnly     = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "The folder was opened read-only"}
)

// The flags every folder offers and keeps.
var mailImapFlags = []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted}

// One connection's session: see the file header.
type mailImapSession struct {
	server *MailImapServer
	conn   *imapserver.Conn
	// held across each command, and by IDLE's poll while it reads the session and applies what it read, so neither
	// meets the other halfway; a lock of its own, never stateLock, since a command holds it across its store calls
	commandLock sync.Mutex
	// the account LOGIN matched, and its store once built; nil before
	account *MailImapAccount
	store   *MailImapStore
	// the selected folder's snapshot as the client last saw it; nil when none is selected
	snapshot *MailImapSnapshot
	// the folder was opened with EXAMINE
	readOnly bool
}

// A session for conn on server.
func newMailImapSession(server *MailImapServer, conn *imapserver.Conn) *mailImapSession {
	return &mailImapSession{server: server, conn: conn}
}

// See imapserver.Session: called once, at the connection's end.
func (self *mailImapSession) Close() error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	self.snapshot = nil
	self.server.sessionClosed()
	return nil
}

// LOGIN against every account's credential, a refusal's cost waited before it answers.
func (self *mailImapSession) Login(username string, password string) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	ctx, done := self.server.commandContext()
	defer done()
	client := mailImapClient(nil)
	if self.conn != nil {
		client = mailImapClient(self.conn.NetConn())
	}
	accounts := self.server.accounts()
	credentials := make([]*MailLocalCredential, len(accounts))
	for index, account := range accounts {
		credentials[index] = account.Credential
	}
	index := self.server.login.Check(ctx, client, username, password, credentials)
	if index < 0 {
		return imapserver.ErrAuthFailed
	}
	self.account = accounts[index]
	return nil
}

// The account's store, built at its first use.
func (self *mailImapSession) mailboxWithLock() (*MailImapStore, error) {
	if self.store != nil {
		return self.store, nil
	}
	if self.account == nil || self.account.Store == nil {
		return nil, errMailImapUnavailable
	}
	store, err := self.account.Store()
	if err != nil {
		return nil, errMailImapUnavailable
	}
	self.store = store
	return store, nil
}

// A store error as the client reads it.
func mailImapError(err error) error {
	var imapErr *imap.Error
	switch {
	case errors.As(err, &imapErr):
		return err
	case errors.Is(err, ErrMailImapFolderAbsent):
		return errMailImapNoFolder
	case errors.Is(err, ErrMailImapFlagRefused):
		return errMailImapFlagRefused
	}
	return errMailImapUnavailable
}

// The folder as the mailbox stands now.
func (self *mailImapSession) readWithLock(folder string) (*MailImapSnapshot, error) {
	store, err := self.mailboxWithLock()
	if err != nil {
		return nil, err
	}
	ctx, done := self.server.commandContext()
	defer done()
	snapshot, err := store.Select(ctx, folder)
	if err != nil {
		return nil, mailImapError(err)
	}
	return snapshot, nil
}

// See imapserver.Session.
func (self *mailImapSession) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	snapshot, err := self.readWithLock(mailbox)
	if err != nil {
		return nil, err
	}
	self.snapshot = snapshot
	self.readOnly = options != nil && options.ReadOnly
	return &imap.SelectData{
		Flags:          mailImapFlags,
		PermanentFlags: mailImapFlags,
		NumMessages:    uint32(len(snapshot.Messages)),
		UIDNext:        imap.UID(snapshot.Next),
		UIDValidity:    snapshot.Validity,
	}, nil
}

// See imapserver.Session.
func (self *mailImapSession) Create(mailbox string, options *imap.CreateOptions) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return errMailImapNotSupported
}

// See imapserver.Session.
func (self *mailImapSession) Delete(mailbox string) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return errMailImapNotSupported
}

// See imapserver.Session.
func (self *mailImapSession) Rename(mailbox string, newName string, options *imap.RenameOptions) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return errMailImapNotSupported
}

// Every folder counts as subscribed, so a subscription changes nothing.
func (self *mailImapSession) Subscribe(mailbox string) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return nil
}

// See Subscribe.
func (self *mailImapSession) Unsubscribe(mailbox string) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return nil
}

// See imapserver.Session.
func (self *mailImapSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	if len(patterns) == 0 {
		// RFC 9051 §6.3.9: an empty pattern asks only for the delimiter
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: MailImapDelimiter})
	}
	store, err := self.mailboxWithLock()
	if err != nil {
		return err
	}
	ctx, done := self.server.commandContext()
	defer done()
	folders, err := store.Folders(ctx)
	if err != nil {
		return mailImapError(err)
	}
	for _, folder := range folders {
		if !slices.ContainsFunc(patterns, func(pattern string) bool {
			return imapserver.MatchList(folder.Name, MailImapDelimiter, ref, pattern)
		}) {
			continue
		}
		data := &imap.ListData{Delim: MailImapDelimiter, Mailbox: folder.Name}
		if folder.SpecialUse != "" {
			data.Attrs = append(data.Attrs, imap.MailboxAttr(folder.SpecialUse))
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

// See imapserver.Session.
func (self *mailImapSession) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	snapshot, err := self.readWithLock(mailbox)
	if err != nil {
		return nil, err
	}
	count := uint32(len(snapshot.Messages))
	unseen := uint32(0)
	for _, message := range snapshot.Messages {
		if message.Flags == nil || !message.Flags.Seen {
			unseen += 1
		}
	}
	return &imap.StatusData{
		Mailbox:     snapshot.Folder,
		NumMessages: &count,
		UIDNext:     imap.UID(snapshot.Next),
		UIDValidity: snapshot.Validity,
		NumUnseen:   &unseen,
	}, nil
}

// See imapserver.Session.
func (self *mailImapSession) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return nil, errMailImapNotSupported
}

// Reads the selected folder again and writes what moved since the client last saw it: what go-imap calls after each
// command, on the command's goroutine.
func (self *mailImapSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	if self.snapshot == nil {
		return nil
	}
	next, err := self.readWithLock(self.snapshot.Folder)
	if err != nil {
		return err
	}
	return self.applyWithLock(w, next, allowExpunge)
}

// Writes what moved between the snapshot the client last saw and next, the folder read again, and keeps next as the
// client's. With allowExpunge false a message gone stays in the snapshot until a poll may expunge it. A folder whose
// UIDs were reset ends the connection with BYE, since the client must select it again under the new UIDVALIDITY.
func (self *mailImapSession) applyWithLock(w *imapserver.UpdateWriter, next *MailImapSnapshot, allowExpunge bool) error {
	if next.Validity != self.snapshot.Validity {
		if self.conn != nil {
			self.conn.Bye("The folder's UIDs were reset; select it again")
		}
		return errMailImapUnavailable
	}
	nextByUid := map[uint32]*MailImapMessage{}
	for _, message := range next.Messages {
		nextByUid[message.Uid] = message
	}
	kept := []*MailImapMessage{}
	gone := []uint32{}
	for index, message := range self.snapshot.Messages {
		if _, ok := nextByUid[message.Uid]; ok || !allowExpunge {
			kept = append(kept, message)
			continue
		}
		gone = append(gone, uint32(index+1))
	}
	// highest first, so each sequence number is the client's at the moment it reads it
	for i := len(gone) - 1; 0 <= i; i -= 1 {
		if err := w.WriteExpunge(gone[i]); err != nil {
			return err
		}
	}
	lastUid := uint32(0)
	if 0 < len(self.snapshot.Messages) {
		lastUid = self.snapshot.Messages[len(self.snapshot.Messages)-1].Uid
	}
	for index, message := range kept {
		current, ok := nextByUid[message.Uid]
		if !ok {
			continue
		}
		if !slices.Equal(current.ImapFlags(), message.ImapFlags()) {
			if err := w.WriteMessageFlags(uint32(index+1), imap.UID(current.Uid), mailImapFlagList(current)); err != nil {
				return err
			}
		}
		kept[index] = current
	}
	added := 0
	for _, message := range next.Messages {
		if lastUid < message.Uid {
			kept = append(kept, message)
			added += 1
		}
	}
	if 0 < added {
		if err := w.WriteNumMessages(uint32(len(kept))); err != nil {
			return err
		}
	}
	self.snapshot = &MailImapSnapshot{Folder: next.Folder, Validity: next.Validity, Next: next.Next, Messages: kept}
	return nil
}

// Polls, then waits for the mailbox's hint, a change through the store, or IdlePollInterval, and polls again, until
// stop. Each wait subscribes just before the poll it follows, so a change between the two wakes it. No poll starts
// once the server has ended, a hint, a change or a timer taken as it ended included, so nothing more is written to the
// client past the end, and an ended server asks the clock for nothing.
func (self *mailImapSession) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	// select takes any of its ready cases at random: a case taken as the server ended reads as the end
	for self.server.ctx.Err() == nil {
		select {
		case <-stop:
			// go-imap may have moved on already, so a stopped IDLE polls no more
			return nil
		default:
		}
		revised, hinted, err := self.idlePoll(w, stop)
		if err != nil {
			return err
		}
		if self.server.ctx.Err() != nil {
			// a server that ended as the poll ran asks the clock for nothing
			return nil
		}
		select {
		case <-stop:
			return nil
		case <-self.server.ctx.Done():
		case <-revised:
		case <-hinted:
		case <-self.server.clock.After(self.server.settings.IdlePollInterval):
		}
	}
	return nil
}

// One of IDLE's polls: the session read under commandLock, the folder read without it, and what moved applied under it
// again only while stop is open and the snapshot is the one read against, so a command or Close that ran meanwhile
// wins and the poll applies nothing. Answers the channels the next wait takes, subscribed before the read.
func (self *mailImapSession) idlePoll(w *imapserver.UpdateWriter, stop <-chan struct{}) (chan struct{}, chan struct{}, error) {
	var revised chan struct{}
	var hinted chan struct{}
	var snapshot *MailImapSnapshot
	var store *MailImapStore
	func() {
		self.commandLock.Lock()
		defer self.commandLock.Unlock()
		if self.store != nil {
			_, revised = self.store.Revision()
		}
		if self.account != nil && self.account.Hints != nil {
			_, hinted = self.account.Hints()
		}
		snapshot = self.snapshot
		if snapshot != nil {
			store, _ = self.mailboxWithLock()
		}
	}()
	if snapshot == nil || store == nil {
		return revised, hinted, nil
	}
	ctx, done := self.server.commandContext()
	next, err := store.Select(ctx, snapshot.Folder)
	done()
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	select {
	case <-stop:
		return revised, hinted, nil
	default:
	}
	if self.snapshot != snapshot {
		return revised, hinted, nil
	}
	if err != nil {
		return revised, hinted, mailImapError(err)
	}
	return revised, hinted, self.applyWithLock(w, next, true)
}

// See imapserver.Session.
func (self *mailImapSession) Unselect() error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	self.snapshot = nil
	self.readOnly = false
	return nil
}

// \Deleted already moved each message it was set on to Trash (MailImapStore.SetFlags), so EXPUNGE reads the folder
// again and expunges what left it, of uids alone for UID EXPUNGE.
func (self *mailImapSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	if self.snapshot == nil {
		return nil
	}
	next, err := self.readWithLock(self.snapshot.Folder)
	if err != nil {
		return err
	}
	if next.Validity != self.snapshot.Validity {
		if self.conn != nil {
			self.conn.Bye("The folder's UIDs were reset; select it again")
		}
		return errMailImapUnavailable
	}
	present := map[uint32]bool{}
	for _, message := range next.Messages {
		present[message.Uid] = true
	}
	kept := []*MailImapMessage{}
	for index := len(self.snapshot.Messages) - 1; 0 <= index; index -= 1 {
		message := self.snapshot.Messages[index]
		if !present[message.Uid] && (uids == nil || uids.Contains(imap.UID(message.Uid))) {
			if err := w.WriteExpunge(uint32(index + 1)); err != nil {
				return err
			}
			continue
		}
		kept = append(kept, message)
	}
	slices.Reverse(kept)
	self.snapshot = &MailImapSnapshot{Folder: self.snapshot.Folder, Validity: self.snapshot.Validity, Next: next.Next, Messages: kept}
	return nil
}

// The messages of numSet in the snapshot, with their sequence numbers, "*" resolved against it as RFC 9051 §9 says:
// the last sequence number, or the last message's UID.
func (self *mailImapSession) selectedWithLock(numSet imap.NumSet) ([]uint32, []*MailImapMessage) {
	seqNums := []uint32{}
	messages := []*MailImapMessage{}
	if self.snapshot == nil || numSet == nil || imap.IsSearchRes(numSet) {
		// no SEARCHRES is offered, so "$" names nothing
		return seqNums, messages
	}
	count := uint32(len(self.snapshot.Messages))
	lastUid := uint32(0)
	if 0 < count {
		lastUid = self.snapshot.Messages[count-1].Uid
	}
	resolve := func(start uint32, stop uint32, max uint32) (uint32, uint32) {
		dynamic := false
		if start == 0 {
			start, dynamic = max, true
		}
		if stop == 0 {
			stop, dynamic = max, true
		}
		if dynamic && stop < start {
			start, stop = stop, start
		}
		return start, stop
	}
	for index, message := range self.snapshot.Messages {
		seqNum := uint32(index + 1)
		taken := false
		switch set := numSet.(type) {
		case imap.SeqSet:
			for _, r := range set {
				start, stop := resolve(r.Start, r.Stop, count)
				taken = taken || (start <= seqNum && seqNum <= stop)
			}
		case imap.UIDSet:
			for _, r := range set {
				start, stop := resolve(uint32(r.Start), uint32(r.Stop), lastUid)
				taken = taken || (start <= message.Uid && message.Uid <= stop)
			}
		}
		if taken {
			seqNums = append(seqNums, seqNum)
			messages = append(messages, message)
		}
	}
	return seqNums, messages
}

// The message's IMAP flags as go-imap's.
func mailImapFlagList(message *MailImapMessage) []imap.Flag {
	flags := []imap.Flag{}
	for _, flag := range message.ImapFlags() {
		flags = append(flags, imap.Flag(flag))
	}
	return flags
}

// Sets \Seen on the messages a FETCH of BODY[] reads, in one push, and answers them with the flag set; nil when the
// folder is read-only or every one is seen already.
func (self *mailImapSession) markSeenWithLock(messages []*MailImapMessage, options *imap.FetchOptions) (map[uint32]*MailImapMessage, error) {
	if self.readOnly || !slices.ContainsFunc(options.BodySection, func(section *imap.FetchItemBodySection) bool { return !section.Peek }) {
		return nil, nil
	}
	unseen := []*MailImapMessage{}
	for _, message := range messages {
		if message.Flags == nil || !message.Flags.Seen {
			unseen = append(unseen, message)
		}
	}
	if len(unseen) == 0 {
		return nil, nil
	}
	store, err := self.mailboxWithLock()
	if err != nil {
		return nil, err
	}
	ctx, done := self.server.commandContext()
	defer done()
	if err := store.SetFlags(ctx, self.snapshot.Folder, unseen, []*MailImapFlagChange{{Flag: MailImapFlagSeen, Set: true}}); err != nil {
		return nil, mailImapError(err)
	}
	seen := map[uint32]*MailImapMessage{}
	for _, message := range unseen {
		flags := &MailFlags{}
		if message.Flags != nil {
			copied := *message.Flags
			flags = &copied
		}
		flags.Seen = true
		copied := *message
		copied.Flags = flags
		seen[message.Uid] = &copied
	}
	return seen, nil
}

// See imapserver.Session. A message whose bytes cannot be read, its keys gone among the reasons, is left out of the
// answer rather than answered from anything kept (§2.18).
func (self *mailImapSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	seqNums, messages := self.selectedWithLock(numSet)
	if len(messages) == 0 {
		return nil
	}
	seen, err := self.markSeenWithLock(messages, options)
	if err != nil {
		return err
	}
	if 0 < len(seen) {
		// a new snapshot, never an edit of the one an IDLE poll may hold
		kept := slices.Clone(self.snapshot.Messages)
		for index, message := range messages {
			if changed := seen[message.Uid]; changed != nil {
				kept[seqNums[index]-1] = changed
			}
		}
		self.snapshot = &MailImapSnapshot{Folder: self.snapshot.Folder, Validity: self.snapshot.Validity, Next: self.snapshot.Next, Messages: kept}
	}
	needBody := options.Envelope || options.BodyStructure != nil || 0 < len(options.BodySection)
	for index, message := range messages {
		if changed := seen[message.Uid]; changed != nil {
			message = changed
		}
		var raw []byte
		if needBody {
			store, err := self.mailboxWithLock()
			if err != nil {
				return err
			}
			ctx, done := self.server.commandContext()
			raw, err = store.Body(ctx, message)
			done()
			if err != nil {
				continue
			}
		}
		response := w.CreateMessage(seqNums[index])
		if options.UID {
			response.WriteUID(imap.UID(message.Uid))
		}
		if options.Flags || seen[message.Uid] != nil {
			response.WriteFlags(mailImapFlagList(message))
		}
		if options.InternalDate {
			response.WriteInternalDate(message.InternalDate())
		}
		if options.RFC822Size {
			response.WriteRFC822Size(int64(message.Size()))
		}
		if options.Envelope {
			header, err := gomessagetextproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
			if err == nil {
				response.WriteEnvelope(imapserver.ExtractEnvelope(header))
			}
		}
		if options.BodyStructure != nil {
			response.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
		}
		for _, section := range options.BodySection {
			data := imapserver.ExtractBodySection(bytes.NewReader(raw), section)
			writer := response.WriteBodySection(section, int64(len(data)))
			writer.Write(data)
			writer.Close()
		}
		if err := response.Close(); err != nil {
			return err
		}
	}
	return nil
}

// STORE as f/ ops: +FLAGS sets, -FLAGS clears, FLAGS sets what it names and clears the rest the store keeps. Refused
// under EXAMINE.
func (self *mailImapSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	if self.snapshot == nil {
		return errMailImapNoFolder
	}
	if self.readOnly {
		return errMailImapReadOnly
	}
	seqNums, messages := self.selectedWithLock(numSet)
	changes := []*MailImapFlagChange{}
	named := map[string]bool{}
	for _, flag := range flags.Flags {
		named[string(flag)] = true
		switch flags.Op {
		case imap.StoreFlagsAdd, imap.StoreFlagsSet:
			changes = append(changes, &MailImapFlagChange{Flag: string(flag), Set: true})
		case imap.StoreFlagsDel:
			changes = append(changes, &MailImapFlagChange{Flag: string(flag), Set: false})
		}
	}
	if flags.Op == imap.StoreFlagsSet {
		for _, flag := range []string{MailImapFlagSeen, MailImapFlagFlagged} {
			if !named[flag] {
				changes = append(changes, &MailImapFlagChange{Flag: flag, Set: false})
			}
		}
	}
	store, err := self.mailboxWithLock()
	if err != nil {
		return err
	}
	ctx, done := self.server.commandContext()
	defer done()
	if err := store.SetFlags(ctx, self.snapshot.Folder, messages, changes); err != nil {
		return mailImapError(err)
	}
	if flags.Silent {
		return nil
	}
	// the flags as the folder now reads them
	next, err := store.Select(ctx, self.snapshot.Folder)
	if err != nil {
		return mailImapError(err)
	}
	nextByUid := map[uint32]*MailImapMessage{}
	for _, message := range next.Messages {
		nextByUid[message.Uid] = message
	}
	// the client is told these flags now, so no poll tells it them again: a new snapshot, never an edit of the one an
	// IDLE poll may hold
	kept := slices.Clone(self.snapshot.Messages)
	self.snapshot = &MailImapSnapshot{Folder: self.snapshot.Folder, Validity: self.snapshot.Validity, Next: self.snapshot.Next, Messages: kept}
	for index, message := range messages {
		current, ok := nextByUid[message.Uid]
		if !ok {
			// it left the folder, a \Deleted outside Trash among the reasons: the next poll expunges it
			continue
		}
		kept[seqNums[index]-1] = current
		response := w.CreateMessage(seqNums[index])
		response.WriteUID(imap.UID(current.Uid))
		response.WriteFlags(mailImapFlagList(current))
		if err := response.Close(); err != nil {
			return err
		}
	}
	return nil
}

// See imapserver.Session.
func (self *mailImapSession) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	self.commandLock.Lock()
	defer self.commandLock.Unlock()
	return nil, errMailImapNotSupported
}
