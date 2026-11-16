//go:build !ios_extension

// §15.9's one-time codes and the vault on MailClient (R-MAIL-4, R-MAIL-6, R-MAIL-13, I-7; MAIL-M8-03, with MAIL-M8-02's
// surface): what SidecarMail's GetOneTimeCodes, GetVaultEntries and GetUsedAt wrap (SDK-M8-04).
//
//	vault   this device's member's MailVault over its mailbox (mail_vault.go), built once a binding: only the owner's
//	        consented devices read or write it, which MailVault asks §8's verified state at every call, so the
//	        methods here add no rule of their own. MailClient.VaultEntries, UsedAt, PutVaultEntry and
//	        DeleteVaultEntry are MailVault's of those names
//	codes   OneTimeCodes(since) merges the vault's TOTP, each entry's code for now with when it stops, and the
//	        mailbox's i/ rows' one_time_code (MAIL-M7-12's MailExtractOneTimeCode at ingest), each message received
//	        at or after since, newest first. A device that may not read the vault gets the mail codes alone, since the
//	        vault's readership is the narrower one (§8.5, QD-673); a code is never logged (I-7)
//
// Nothing here logs a code, a secret, an address or a site (I-7, I-13). On every leg but the extension's: a page Worker
// reads its owner's codes as a phone does.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Where a one-time code came from.
type MailOneTimeCodeSource string

const (
	// A vault entry's RFC 6238 one-time auth.
	MailOneTimeCodeTotp MailOneTimeCodeSource = "totp"
	// A message's code, as ingest found it.
	MailOneTimeCodeMail MailOneTimeCodeSource = "mail"
)

// One one-time code.
type MailOneTimeCode struct {
	Code   string
	Source MailOneTimeCodeSource
	// The address it belongs to: the vault entry's, or the message's recipient.
	Address string
	// The vault entry, for a TOTP code; the message and its month, for a mail code.
	EntryId   Id
	MessageId Id
	Month     MailYearMonth
	// A TOTP code's period start, a mail code's receive time.
	Time time.Time
	// When a TOTP code stops being the code; zero for a mail code.
	Until time.Time
}

// What OneTimeCodes reads. Every value must be positive.
type MailCodeSettings struct {
	// The most i/ rows one call reads, newest first, before it stops: codes are recent mail's, and a bounded read
	// keeps a call cheap on a large mailbox.
	ScanMaxCount int
}

// The one default.
func DefaultMailCodeSettings() *MailCodeSettings {
	return &MailCodeSettings{
		ScanMaxCount: 1000,
	}
}

// Whether every value is in range.
func (self *MailCodeSettings) valid() bool {
	return self != nil && 0 < self.ScanMaxCount
}

// MailVaultAuthority over the installed AclEngine: §8.5's consented(d, M).
type mailVaultAclAuthority struct {
	engine *AclEngine
}

// AclState.ConsentedFor at the installed state; false with none.
func (self *mailVaultAclAuthority) Consented(sidecarId Id, memberId Id) bool {
	if self == nil || self.engine == nil {
		return false
	}
	state := self.engine.State()
	return state != nil && state.ConsentedFor(sidecarId, memberId)
}

// How a MailClient reaches its member's vault where a test's parts stand in.
type mailVaultParts interface {
	vault(mailboxId Id, ownerMemberId Id, args *MailVaultArgs) *MailVault
}

// This device's member's vault over its mailbox, built once a binding: ErrMailNoMailbox for a tagged device or a
// member with none.
func (self *MailClient) Vault() (*MailVault, error) {
	binding, parts, state, err := self.state()
	if err != nil {
		return nil, err
	}
	memberId, ok := mailMemberOf(state, self.sidecarId)
	if !ok {
		return nil, ErrMailNoMailbox
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	held := func() *MailVault {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.vaults[mailboxId]
	}()
	if held != nil {
		return held, nil
	}
	args := &MailVaultArgs{
		OwnerMemberId: memberId,
		SidecarId:     self.sidecarId,
		Authority:     &mailVaultAclAuthority{engine: binding.Engine},
		Clock:         self.clock,
		Log:           self.log,
		Settings:      self.settings.Vault,
	}
	var vault *MailVault
	if vaultParts, ok := parts.(mailVaultParts); ok {
		vault = vaultParts.vault(mailboxId, memberId, args)
	} else {
		if binding.Evs == nil {
			return nil, ErrMailUnbound
		}
		args.Repo = binding.Evs.Repo(mailboxId)
		if vault, err = NewMailVault(args); err != nil {
			return nil, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if winner := self.vaults[mailboxId]; winner != nil {
		return winner, nil
	}
	self.vaults[mailboxId] = vault
	return vault, nil
}

// Every vault entry that stands (MailVault.VaultEntries).
func (self *MailClient) VaultEntries(ctx context.Context) ([]*protocol.VaultEntry, error) {
	vault, err := self.Vault()
	if err != nil {
		return nil, err
	}
	return vault.VaultEntries(ctx)
}

// An entry's Used at (MailVault.UsedAt).
func (self *MailClient) UsedAt(ctx context.Context, entryId Id) ([]*protocol.VaultUsedAt, error) {
	vault, err := self.Vault()
	if err != nil {
		return nil, err
	}
	return vault.UsedAt(ctx, entryId)
}

// Writes an entry's fields (MailVault.PutVaultEntry).
func (self *MailClient) PutVaultEntry(ctx context.Context, entry *protocol.VaultEntry) (*protocol.VaultEntry, error) {
	vault, err := self.Vault()
	if err != nil {
		return nil, err
	}
	return vault.PutVaultEntry(ctx, entry)
}

// Shreds an entry's every version (MailVault.DeleteVaultEntry).
func (self *MailClient) DeleteVaultEntry(ctx context.Context, entryId Id) error {
	vault, err := self.Vault()
	if err != nil {
		return err
	}
	return vault.DeleteVaultEntry(ctx, entryId)
}

// The codes for since on, newest first (the file header's codes row).
func (self *MailClient) OneTimeCodes(ctx context.Context, since time.Time) ([]*MailOneTimeCode, error) {
	settings := self.settings.Codes
	if settings == nil {
		settings = DefaultMailCodeSettings()
	}
	codes, err := self.mailOneTimeCodes(ctx, since, settings)
	if err != nil {
		return nil, err
	}
	totpCodes, err := self.totpOneTimeCodes(ctx, since)
	switch {
	case err == nil:
		codes = append(codes, totpCodes...)
	case errors.Is(err, ErrMailVaultNotConsented), errors.Is(err, ErrMailNoMailbox):
		// the vault's readers are the narrower set: this device gets the mail codes alone
	default:
		return nil, err
	}
	slices.SortStableFunc(codes, func(a *MailOneTimeCode, b *MailOneTimeCode) int {
		if c := b.Time.Compare(a.Time); c != 0 {
			return c
		}
		return cmp.Compare(a.Source, b.Source)
	})
	return codes, nil
}

// The mailbox's codes received at or after since, newest first, within ScanMaxCount rows.
func (self *MailClient) mailOneTimeCodes(ctx context.Context, since time.Time, settings *MailCodeSettings) ([]*MailOneTimeCode, error) {
	view, err := self.view()
	if err != nil {
		return nil, err
	}
	sinceMillis := uint64(max(since.UnixMilli(), 0))
	codes := []*MailOneTimeCode{}
	scanned := 0
	var cursor *MailListCursor
	for scanned < settings.ScanMaxCount {
		page, err := view.List(ctx, &MailListArgs{Folder: MailFolderAll, After: cursor, Limit: settings.ScanMaxCount - scanned})
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Entries {
			scanned += 1
			if entry.Entry.GetTime() < sinceMillis {
				// the list is newest first: everything after is older still
				return codes, nil
			}
			if code := entry.Entry.GetOneTimeCode(); code != "" {
				codes = append(codes, &MailOneTimeCode{
					Code: code, Source: MailOneTimeCodeMail, Address: entry.Entry.GetAddress(), MessageId: mailEntryId(entry.Entry),
					Month: MailYearMonthOf(entry.Entry.GetTime()), Time: time.UnixMilli(int64(min(entry.Entry.GetTime(), mailLastMillis))).UTC(),
				})
			}
		}
		if page.Next == nil || len(page.Entries) == 0 {
			break
		}
		cursor = page.Next
	}
	return codes, nil
}

// Each live vault entry's TOTP code for now, where now is at or after since.
func (self *MailClient) totpOneTimeCodes(ctx context.Context, since time.Time) ([]*MailOneTimeCode, error) {
	now := self.clock.Now()
	if now.Before(since) {
		return []*MailOneTimeCode{}, nil
	}
	vault, err := self.Vault()
	if err != nil {
		return nil, err
	}
	entries, err := vault.VaultEntries(ctx)
	if err != nil {
		return nil, err
	}
	codes := []*MailOneTimeCode{}
	for _, entry := range entries {
		totp := entry.GetTotp()
		if totp == nil || len(totp.GetSecret()) == 0 || entry.GetState() == protocol.VaultEntryState_VAULT_ENTRY_BURNED {
			continue
		}
		code, until, err := MailTotpCode(totp, now)
		if err != nil {
			// an entry whose one-time auth does not compute shows no code; its secret is never named
			continue
		}
		entryId, err := IdFromBytes(entry.GetEntryId())
		if err != nil {
			continue
		}
		period := time.Duration(totp.GetPeriod()) * time.Second
		codes = append(codes, &MailOneTimeCode{
			Code: code, Source: MailOneTimeCodeTotp, Address: entry.GetAddress(), EntryId: entryId,
			Time: until.Add(-period), Until: until,
		})
	}
	return codes, nil
}
