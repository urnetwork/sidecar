//go:build !ios_extension

// Approved recipients (§15.10, §15.7's rcpt/, owner decision 280; I-8, I-9; MAIL-M9-01): a (sending alias, recipient)
// pair with an approval record in the repo that holds that alias's mail, so mail_send to it is W. mail_send is W only
// when every non-member recipient has a record and the run is untainted; a tainted run ignores records (mail_send.go).
//
//	record   rcpt/<h>/<name>, <name> the lowercase base32 of SHA-256(alias ‖ 0x00 ‖ recipient), holding
//	         MailRecipientApproval{alias, recipient, decision, action} (QD-1094): the stored Signed of one
//	         ApprovalDecision on channel device or presence and the stored CanonicalAction of kind mail_send it approved,
//	         which lists the recipient. The send's effect writes one a recipient once the gate passed it on such a
//	         decision, created only if absent; a harness decision sends its one message and makes no record
//	verify   each use re-verifies the record under this device's current P (the binding's SpendState): the decision's
//	         signature under the key its channel names, its verdict approve, its payload the action's, its pin on P's
//	         chain, a device signer approval-capable for the approver, and the approver and channel under the rule
//	         that governs the action now (spendUnderRule), so a file an agent wrote, or one whose approver was revoked,
//	         approves nothing. The decision's own not_after bounds its use, not the record, which lasts until a person
//	         removes it. With no SpendState bound nothing is approved, the closed direction
//	remove   a person removes a record with `ur mail recipients rm` on /dev/tty or in an app (Remove). §15.10 has
//	         MCP's evs tools refuse rcpt/, which mcp's guard does not do yet (question mail-m9-01-mcp-rcpt-guard): a
//	         record an agent writes approves nothing, but until that row lands an agent that kept a removed record's
//	         bytes could write them back, and they would verify again
//
// On every leg but the extension's. Nothing here logs an address (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A record that does not approve its pair at this use. Names no address.
var ErrMailRecipientApproval = errors.New("mail approved recipients: no record approves it")

// The approval records of one network's mail: see the file header.
type MailApprovedRecipients struct {
	client *MailClient
}

// This network's approved recipients.
func (self *MailClient) ApprovedRecipients() *MailApprovedRecipients {
	return &MailApprovedRecipients{client: self}
}

// The store of the repo holding alias's mail, the mailbox or group repo its record names.
func (self *MailApprovedRecipients) store(ctx context.Context, alias string) (mailStore, error) {
	client := self.client
	_, parts, err := client.bound()
	if err != nil {
		return nil, err
	}
	row := client.networkRow()
	if binding, _, err := client.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	recipient, own := mailSendOwnRecipient(row, alias)
	if !own {
		return nil, ErrMailRecipientApproval
	}
	config, err := client.syncedConfig(ctx)
	if err != nil {
		return nil, err
	}
	lookup, err := config.Resolve(ctx, recipient)
	if err != nil {
		return nil, err
	}
	if !lookup.Known {
		return nil, ErrMailRecipientApproval
	}
	return parts.store(lookup.MailboxRepoId), nil
}

// Whether every recipient has a record approving it for alias, a send's From in its one form, at this use (the file
// header's verify row). False for an empty list, where no SpendState is bound, and where any record fails.
func (self *MailApprovedRecipients) ApprovedAll(ctx context.Context, alias string, recipients []string) bool {
	if len(recipients) == 0 {
		return false
	}
	binding, _, err := self.client.bound()
	if err != nil || binding.SpendState == nil {
		return false
	}
	state, err := binding.SpendState()
	if err != nil || state == nil {
		return false
	}
	store, err := self.store(ctx, alias)
	if err != nil {
		return false
	}
	now := self.client.clock.Now()
	for _, recipient := range recipients {
		record, _, err := mailRecipientApprovalRead(ctx, store, alias, recipient, self.settings())
		if err != nil {
			return false
		}
		if err := mailRecipientApprovalVerify(record, alias, recipient, state, self.client.sidecarId, now); err != nil {
			return false
		}
	}
	return true
}

// Records each recipient of a done use as approved for alias, under the first of decisions, each a decision's stored
// Signed, on channel device or presence, and action, the use's stored CanonicalAction: what a gated send's effect does
// once its delivery is done (the file header's record row). A use with no such decision, a harness one's, writes
// nothing. A record that cannot be written is logged, naming no address, and the next send takes the gate.
func (self *MailApprovedRecipients) Record(ctx context.Context, alias string, recipients []string, decisions [][]byte, action []byte) {
	stored, err := ParseStoredCanonicalAction(action)
	if err != nil || stored.Action.GetKind() != uint32(SidecarActionMail) || stored.Action.GetScope() || stored.Action.GetAlias() != alias || len(recipients) == 0 {
		// A template spends a bounded number of uses in its run. Only a decision on a full message can stand for a pair.
		return
	}
	payload := stored.PayloadSha256()
	var chosen []byte
	for _, storedSigned := range decisions {
		decision, err := ParseStoredApprovalDecision(storedSigned)
		if err != nil || decision.Decision == nil || !bytes.Equal(decision.Decision.GetPayloadSha256(), payload[:]) {
			continue
		}
		switch protocol.ApprovalChannel(decision.Decision.GetChannel()) {
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
			chosen = storedSigned
		}
		if chosen != nil {
			break
		}
	}
	if chosen == nil {
		return
	}
	store, err := self.store(ctx, alias)
	if err != nil {
		self.client.log.Warningf("[mail]no approval records were written: %v", err)
		return
	}
	for _, recipient := range recipients {
		if !slices.Contains(stored.Action.GetRecipients(), recipient) {
			continue
		}
		held, version, err := mailRecipientApprovalRead(ctx, store, alias, recipient, self.settings())
		if err == nil {
			// An older sender could have stored a bounded template here. A new approval over this exact
			// message can replace that row at the version read. Every standing single-message approval is kept.
			previous, err := ParseStoredCanonicalAction(held.GetAction())
			if err != nil || held.GetAlias() != alias || held.GetRecipient() != recipient || previous.Action.GetKind() != uint32(SidecarActionMail) || !previous.Action.GetScope() {
				continue
			}
		} else if !errors.Is(err, ErrEvsPathAbsent) {
			self.client.log.Warningf("[mail]an approval record could not be read: %v", err)
			continue
		}
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailRecipientApproval{
			Alias: alias, Recipient: recipient, Decision: bytes.Clone(chosen), Action: bytes.Clone(action),
		})
		if err != nil {
			continue
		}
		path := MailRecipientApprovalPath(alias, recipient)
		testHookBarrier("mail.approved.record.before", "")
		_, err = store.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: version}})
		testHookBarrier("mail.approved.record.after", "")
		if err != nil && !mailStoreConflictOn(err, path) {
			self.client.log.Warningf("[mail]an approval record was not written: %v", err)
		}
	}
}

// Removes the record approving recipient for alias, as `ur mail recipients rm` asks, and says whether one stood. alias
// and recipient are as a person types them: each is put in the one form a send records it under, the alias this
// network's address and the recipient with its canonical domain. ErrMailRecipientApproval for an alias that has no mailbox in this
// network, or a recipient that is no address.
func (self *MailApprovedRecipients) Remove(ctx context.Context, alias string, recipient string) (bool, error) {
	client := self.client
	row := client.networkRow()
	if binding, _, err := client.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	from, own := mailSendOwnRecipient(row, strings.TrimSpace(alias))
	if !own {
		return false, ErrMailRecipientApproval
	}
	recipients, err := mailSendAddressList(row, client.sendSettings(), []string{recipient})
	if err != nil || len(recipients) != 1 {
		return false, ErrMailRecipientApproval
	}
	alias, recipient = from.Address(), recipients[0]
	store, err := self.store(ctx, alias)
	if err != nil {
		return false, err
	}
	settings := self.settings()
	path := MailRecipientApprovalPath(alias, recipient)
	for attempt := 0; ; attempt += 1 {
		_, version, err := store.Read(ctx, path, settings.OutcomeRecordMaxByteCount)
		if errors.Is(err, ErrEvsPathAbsent) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		testHookBarrier("mail.approved.remove.before", "")
		_, err = store.Write(ctx, []*mailStoreWrite{{Path: path, Remove: true, IfVersion: version}})
		testHookBarrier("mail.approved.remove.after", "")
		if err == nil {
			return true, nil
		}
		if !mailStoreConflictOn(err, path) || settings.WriteRetryCount <= attempt {
			return false, err
		}
	}
}

// The bounds a record is read within: the outbox's.
func (self *MailApprovedRecipients) settings() *MailOutboxSettings {
	if self.client.settings.Outbox != nil {
		return self.client.settings.Outbox
	}
	return DefaultMailOutboxSettings()
}

// The record approving recipient for alias in store.
func mailRecipientApprovalRead(ctx context.Context, store mailStore, alias string, recipient string, settings *MailOutboxSettings) (*protocol.MailRecipientApproval, uint64, error) {
	content, version, err := store.Read(ctx, MailRecipientApprovalPath(alias, recipient), settings.OutcomeRecordMaxByteCount)
	if err != nil {
		return nil, 0, err
	}
	record := &protocol.MailRecipientApproval{}
	if err := proto.Unmarshal(content, record); err != nil {
		return nil, 0, ErrMailRecipientApproval
	}
	return record, version, nil
}

// Whether record approves (alias, recipient) for spender at P at now (the file header's verify row).
func mailRecipientApprovalVerify(record *protocol.MailRecipientApproval, alias string, recipient string, state SpendState, spender Id, now time.Time) error {
	refused := func(why string) error {
		return fmt.Errorf("%w: %s", ErrMailRecipientApproval, why)
	}
	if record == nil || record.GetAlias() != alias || record.GetRecipient() != recipient {
		return refused("another pair's record")
	}
	decision, err := ParseStoredApprovalDecision(record.GetDecision())
	if err != nil || decision.Decision == nil {
		return refused("no decision")
	}
	action, err := ParseStoredCanonicalAction(record.GetAction())
	if err != nil || action.Action == nil {
		return refused("no action")
	}
	if SidecarActionKind(action.Action.GetKind()) != SidecarActionMail || action.Action.GetScope() || action.Action.GetAlias() != alias ||
		!slices.Contains(action.Action.GetRecipients(), recipient) {
		return refused("an action that does not send to the pair")
	}
	body := decision.Decision
	channel := protocol.ApprovalChannel(body.GetChannel())
	if channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE && channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
		return refused("a decision on neither device nor presence")
	}
	if refusal := spendVerifyDecision(decision, state); refusal != nil {
		return refused("a decision that does not verify at P")
	}
	if protocol.ApprovalVerdict(body.GetDecision()) != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE {
		return refused("no approval")
	}
	payload := action.PayloadSha256()
	if !bytes.Equal(body.GetPayloadSha256(), payload[:]) {
		return refused("a decision over another action")
	}
	approver := recordIdOf(body.GetApproverMemberId())
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE {
		signerId, err := IdFromBytes(decision.Signed.GetSignerId())
		if err != nil || !state.ApprovalCapable(signerId, approver) {
			return refused("a signer no longer approval-capable")
		}
	}
	pin := body.GetAuthPin()
	current := state.Pin()
	if pin == nil || current == nil || current.GetVersion() < pin.GetVersion() {
		return refused("a pin ahead of P")
	}
	if chain, retained := state.ChainAt(pin.GetVersion()); retained && !bytes.Equal(chain[:], pin.GetChain()) {
		return refused("a pin off P's chain")
	}
	rule, err := state.Govern(action, spender, now)
	if err != nil {
		return refused("no rule takes the action now")
	}
	if refusal := spendUnderRule(decision, rule); refusal != nil {
		return refused("an approver or channel the rule no longer takes")
	}
	return nil
}
