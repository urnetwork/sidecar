//go:build !sidecar_http && !ios_extension

// §15.9's burners on a device (R-MAIL-6, R-MAIL-7, R-MAIL-11, D-MAIL-7, I-8, I-14, R-CTX-25; MAIL-M8-01): a burner is
// <name>@<blabel>.<net>.<root> under the network's wildcard MX, so a receive-only burner has no record, key or server
// state of its own: only its burner/<h>/<blabel> record in mailcfg, which receivers resolve (D-MAIL-7).
//
//	create   CreateBurner(site) is an I-8 outward action: mailcfg writes the record only once Authorize passes,
//	         created only if absent and carrying the use's effect_key, whose DRBG draws the label
//	         (mail_burner_labels.go), so a retry or a restart's Lookup finds its own burner and burns no second label
//	         (MailConfig.CreateBurnerRecord). <name> is the site's name, its registrable domain's first label, else
//	         "mail"; any local part reaches the label (§15.9). Then a vault entry for the site, at an id the label
//	         names, so a retry finds the entry it made (MailVault.PutVaultEntry); only the owner's consented devices
//	         write one, and a burner another device creates has none
//	limits   with no server burner state, mail_burners_active and mail_burner_creates_per_day apply here, from GET
//	         /sidecar/limits (§20.4), over the network's burner records: those not burned, and those created within
//	         BurnerSettings.CreatesWindow. A limit not there to read refuses, never an unbounded creation; -1 is none,
//	         as both read while the answer's enforced is false, so their refusals ship dark as api's do (§20.5;
//	         owner decision 520), the limits still read so that an answer that does not come still refuses
//	copy     before this member's first burner, CreateBurner answers §15.9's foreground-only copy while coverage is
//	         foreground-only or none (mail_coverage.go). It never refuses for coverage (owner decision 12)
//	burn     local, with no approval (owner decision 32): the record's next version marks the label burned, so
//	         receivers answer 550 5.1.1 from its hint on and the label is never reissued, and its vault entries read
//	         burned. Pause answers the same, reversibly. Neither changes DNS or the server: a replying burner's
//	         selector retiring does, which is MAIL-M9-03's, and the receiver's listener and certificate are shared
//	never    a burner is linkable through <net>, and an alias names the network (R-MAIL-7): an address here is spelled
//	         under the network's label, never its alias, and product copy says the rest
//
// Nothing here logs an address, a label or a site (I-13). Off the page Worker's leg, which writes no mailcfg.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// GET /sidecar/limits' burner keys (§20.4).
const (
	mailLimitBurnersActive        = "mail_burners_active"
	mailLimitBurnerCreatesPerDay  = "mail_burner_creates_per_day"
	mailBurnerVaultEntryIdLabel   = "urnetwork-sidecar-v1/burner-vault-entry"
	mailBurnerDefaultLocalPart    = "mail"
	mailBurnerLimitUnboundedValue = -1
)

var (
	// What CreateBurner, Burn or PauseBurner was given is out of shape: no site, or no burner's address or label.
	// Names no site or address.
	ErrMailBurnerInvalid = errors.New("mail burner: invalid")
	// A local burner limit refused the creation: the network is at mail_burners_active or mail_burner_creates_per_day,
	// or the limit is not there to read. errors.As finds *MailBurnerLimitError naming which.
	ErrMailBurnerLimit = errors.New("mail burner: at a limit")
	// The burner was made but its vault entry was not written: the answer still names the burner, and Burn or the
	// vault takes it from there.
	ErrMailBurnerNoVaultEntry = errors.New("mail burner: made, but its vault entry was not written")
)

// Which local limit refused a creation.
type MailBurnerLimitError struct {
	// The limit's key: mail_burners_active or mail_burner_creates_per_day.
	Limit string
	// Its value, 0 where it was not there to read, and the count it was held against.
	Value int64
	Count int
}

// Names the limit, never a label.
func (self *MailBurnerLimitError) Error() string {
	return fmt.Sprintf("%s: %s %d, at %d", ErrMailBurnerLimit, self.Limit, self.Value, self.Count)
}

// ErrMailBurnerLimit, which every limit refusal is.
func (self *MailBurnerLimitError) Unwrap() error {
	return ErrMailBurnerLimit
}

// What CreateBurner makes.
type MailBurnerCreateArgs struct {
	// The site the burner is for: a host name or URL, which its vault entry titles and lists.
	Site string
	// What the outward action carries to the gate (I-8).
	Action MailConfigActionArgs
}

// What CreateBurner made.
type MailBurnerCreated struct {
	// <name>@<blabel>.<net>.<root>.
	Address string
	Label   string
	// The vault entry for its site; zero where none was written.
	EntryId Id
	// §15.9's foreground-only copy for this member's first burner while coverage is foreground-only or none, else
	// empty. It never stopped the burner (owner decision 12).
	CoverageCopy string
	Info         *MailBurnerInfo
}

// Makes a burner for args.Site (see the file header's create, limits and copy rows). An outward action, which may
// answer *ApprovalPendingError. ErrMailBurnerNoVaultEntry comes with a non-nil answer: the burner stands.
func (self *MailClient) CreateBurner(ctx context.Context, args *MailBurnerCreateArgs) (*MailBurnerCreated, error) {
	settings := self.burnerSettings()
	if args == nil {
		return nil, fmt.Errorf("%w: no site", ErrMailBurnerInvalid)
	}
	site := strings.TrimSpace(args.Site)
	if site == "" || settings.SiteMaxByteCount < len(site) || !utf8.ValidString(site) || strings.ContainsAny(site, "\x00\r\n") {
		return nil, fmt.Errorf("%w: a site out of shape", ErrMailBurnerInvalid)
	}
	binding, _, err := self.bound()
	if err != nil {
		return nil, err
	}
	if binding.Api == nil {
		return nil, fmt.Errorf("%w: no api to read the burner limits through", ErrMailUnbound)
	}
	row := self.networkRow()
	if binding.Network != nil {
		row = binding.Network()
	}
	if row.Root == "" || row.Label == "" {
		return nil, ErrMailConfigNoZone
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	burners, err := config.Burners()
	if err != nil {
		return nil, err
	}
	if err := self.checkBurnerLimits(ctx, binding.Api, burners, settings); err != nil {
		return nil, err
	}
	firstBurner := true
	for _, burner := range burners {
		if burner.MailboxRepoId == mailboxId {
			firstBurner = false
			break
		}
	}
	coverageCopy := ""
	if firstBurner {
		coverage, err := self.ReceiverCoverage(ctx)
		if err != nil {
			coverage = MailCoverageNone
		}
		coverageCopy = MailCoverageCopy(coverage)
	}

	localPart := mailBurnerLocalPart(site)
	info, err := config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: localPart, MailboxRepoId: mailboxId, Action: args.Action})
	if err != nil {
		return nil, err
	}
	if info.State == protocol.MailBurnerState_MAIL_BURNER_BURNED {
		// the use's burner was made and burned since: a use makes one burner, and a burned one is no answer
		return nil, ErrMailConfigBurned
	}
	zone := MailZone{Root: strings.TrimSuffix(dnsAsciiLower(row.Root), "."), Net: dnsAsciiLower(row.Label)}
	created := &MailBurnerCreated{
		Address:      localPart + "@" + info.Label + "." + zone.Domain(),
		Label:        info.Label,
		CoverageCopy: coverageCopy,
		Info:         info,
	}
	entryId := mailBurnerVaultEntryId(info.Label)
	if _, err := self.PutVaultEntry(ctx, &protocol.VaultEntry{
		EntryId: entryId.Bytes(), Address: created.Address, Title: site, Urls: []string{site}, State: protocol.VaultEntryState_VAULT_ENTRY_LIVE,
	}); err != nil {
		return created, fmt.Errorf("%w: %w", ErrMailBurnerNoVaultEntry, err)
	}
	created.EntryId = entryId
	return created, nil
}

// Holds a creation to the network's local burner limits (the file header's limits row).
func (self *MailClient) checkBurnerLimits(ctx context.Context, api MailApi, burners []*MailBurnerInfo, settings *MailBurnerSettings) error {
	limits, err := api.Limits(ctx)
	if err != nil {
		return fmt.Errorf("%w: the limits were not read: %w", ErrMailBurnerLimit, err)
	}
	active := 0
	createdRecently := 0
	windowStartMillis := self.clock.Now().Add(-settings.CreatesWindow).UnixMilli()
	for _, burner := range burners {
		if burner.State != protocol.MailBurnerState_MAIL_BURNER_BURNED {
			active += 1
		}
		if windowStartMillis <= int64(burner.CreatedMillis) {
			createdRecently += 1
		}
	}
	for _, limit := range []struct {
		key   string
		count int
	}{{key: mailLimitBurnersActive, count: active}, {key: mailLimitBurnerCreatesPerDay, count: createdRecently}} {
		// none while the limits are dark
		value := quotaLocalLimit(limits, limit.key)
		switch {
		case value == mailBurnerLimitUnboundedValue:
		case value <= 0 || value <= int64(limit.count):
			// a key an enforced answer lacks reads 0, not included: refused, never unbounded
			return &MailBurnerLimitError{Limit: limit.key, Value: value, Count: limit.count}
		}
	}
	return nil
}

// The vault entry id of a burner's site entry: SHA-256's first 16 bytes over the label, so a retry writes the entry
// its first run made.
func mailBurnerVaultEntryId(label string) Id {
	sum := sha256.Sum256([]byte(mailBurnerVaultEntryIdLabel + "\x00" + label))
	var entryId Id
	copy(entryId[:], sum[:len(entryId)])
	return entryId
}

// The local part a burner for site takes: the first label of its host's registrable domain, letters and digits
// only, else mail.
func mailBurnerLocalPart(site string) string {
	host := site
	if parsed, err := url.Parse(site); err == nil && parsed.Host != "" {
		host = parsed.Host
	} else if parsed, err := url.Parse("https://" + site); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	host = strings.TrimSuffix(dnsAsciiLower(host), ".")
	if index := strings.LastIndex(host, ":"); 0 <= index && !strings.Contains(host[index:], "]") {
		host = host[:index]
	}
	name := host
	if registrable, ok := mailRegistrableDomain(host); ok {
		name = registrable
	}
	if label, _, ok := strings.Cut(name, "."); ok {
		name = label
	}
	cleaned := strings.Builder{}
	for _, character := range name {
		if ('a' <= character && character <= 'z') || ('0' <= character && character <= '9') {
			cleaned.WriteRune(character)
		}
	}
	localPart := cleaned.String()
	if mailLocalPartMaxByteCount < len(localPart) {
		localPart = localPart[:mailLocalPartMaxByteCount]
	}
	if ValidateNewMailLocalPart(localPart) != nil {
		return mailBurnerDefaultLocalPart
	}
	return localPart
}

// The label of a burner named by its address or by its label alone.
func (self *MailClient) burnerLabelOf(addressOrLabel string) (string, error) {
	addressOrLabel = dnsAsciiLower(strings.TrimSpace(addressOrLabel))
	if !strings.Contains(addressOrLabel, "@") {
		if _, err := MailBurnerPath(addressOrLabel); err != nil {
			return "", fmt.Errorf("%w: no burner label", ErrMailBurnerInvalid)
		}
		return addressOrLabel, nil
	}
	row := self.networkRow()
	if binding, _, err := self.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	recipient, err := ParseMailRecipient(row.Root, addressOrLabel)
	if err != nil || recipient.Kind != MailAddressKindBurner || !recipient.Zone.OfNetwork(row) {
		return "", fmt.Errorf("%w: no burner of this network", ErrMailBurnerInvalid)
	}
	return recipient.BurnerLabel, nil
}

// Burns a burner, named by its address or label (the file header's burn row): local, with no approval, and for
// good. Its vault entries read burned; one this device may not write is left as it was.
func (self *MailClient) Burn(ctx context.Context, addressOrLabel string) error {
	label, err := self.burnerLabelOf(addressOrLabel)
	if err != nil {
		return err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return err
	}
	if err := config.SetBurnerState(ctx, label, protocol.MailBurnerState_MAIL_BURNER_BURNED); err != nil {
		return err
	}
	return self.burnVaultEntries(ctx, label)
}

// Marks burned each vault entry of an address at label. A device that may not read the vault leaves them.
func (self *MailClient) burnVaultEntries(ctx context.Context, label string) error {
	entries, err := self.VaultEntries(ctx)
	if errors.Is(err, ErrMailVaultNotConsented) || errors.Is(err, ErrMailNoMailbox) {
		return nil
	}
	if err != nil {
		return err
	}
	row := self.networkRow()
	if binding, _, err := self.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	for _, entry := range entries {
		recipient, err := ParseMailRecipient(row.Root, entry.GetAddress())
		if err != nil || recipient.Kind != MailAddressKindBurner || recipient.BurnerLabel != label ||
			entry.GetState() == protocol.VaultEntryState_VAULT_ENTRY_BURNED {
			continue
		}
		burned := proto.Clone(entry).(*protocol.VaultEntry)
		burned.State = protocol.VaultEntryState_VAULT_ENTRY_BURNED
		if _, err := self.PutVaultEntry(ctx, burned); err != nil {
			return err
		}
	}
	return nil
}

// Pauses a burner, or resumes it with paused false (the file header's burn row): receivers answer a paused label as
// a burned one, until it is resumed.
func (self *MailClient) PauseBurner(ctx context.Context, addressOrLabel string, paused bool) error {
	label, err := self.burnerLabelOf(addressOrLabel)
	if err != nil {
		return err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return err
	}
	state := protocol.MailBurnerState_MAIL_BURNER_LIVE
	if paused {
		state = protocol.MailBurnerState_MAIL_BURNER_PAUSED
	}
	return config.SetBurnerState(ctx, label, state)
}

// This member's burners, burned and paused ones included, by label (`ur burner ls`, the apps).
func (self *MailClient) Burners(ctx context.Context) ([]*MailBurnerInfo, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	burners, err := config.Burners()
	if err != nil {
		return nil, err
	}
	mine := []*MailBurnerInfo{}
	for _, burner := range burners {
		if burner.MailboxRepoId == mailboxId {
			mine = append(mine, burner)
		}
	}
	return mine, nil
}
