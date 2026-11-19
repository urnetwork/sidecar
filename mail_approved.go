//go:build !ios_extension

// Approved recipients (§15.10, §15.7's rcpt/, owner decision 280; I-8, I-9; MAIL-M9-01): a (sending alias, recipient)
// pair with an approval record in the repo that holds that alias's mail, rcpt/<h>/<address>, whose body
// MailRecipientApproval{alias, recipient, decision, action} carries the stored bytes of one ApprovalDecision on channel
// device or presence and of the mail_send CanonicalAction listing that recipient. mail_send is W only when every
// non-member recipient has a record and the run is untainted; a tainted run ignores records.
//
//	format    MailRecipientApproval has no bytes: no message in protocol/mail.proto and no field numbers in §15.7
//	          (question mail-m9-01-recipient-approval-bytes). Until it does, nothing is written and nothing is read:
//	          ApprovedAll answers false for any recipient and Record writes no record, plan-MCP-approved-recipients'
//	          interim (QD-034), so every non-member recipient takes the gate, the closed direction. A person then
//	          approves each send to an outside address, which a multi-use template decision eases (§16.6)
//	verify    once the bytes stand, each use re-verifies the embedded decision under this device's current pin, its
//	          signer eligible and its channel device or presence in the governing list, so a file an agent wrote, or
//	          one whose approver was revoked, approves nothing; a harness decision sends its one message and makes no
//	          record
//
// On every leg but the extension's. Nothing here logs an address (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
)

// The approval records of one network's mail: see the file header.
type MailApprovedRecipients struct {
	client *MailClient
}

// This network's approved recipients.
func (self *MailClient) ApprovedRecipients() *MailApprovedRecipients {
	return &MailApprovedRecipients{client: self}
}

// Whether every recipient has a record approving it for alias, a send's From in its one form. False for an empty
// list, and false for every recipient until rcpt/'s bytes are settled (the file header's format row).
func (self *MailApprovedRecipients) ApprovedAll(ctx context.Context, alias string, recipients []string) bool {
	return false
}

// Records each recipient of a done use as approved for alias, under decision and action as stored: what the daemon
// does once a mail_send use on channel device or presence is done. Writes nothing until rcpt/'s bytes are settled, so
// the next send to them takes the gate again (the file header's format row); never an error, since a record unwritten
// approves nothing.
func (self *MailApprovedRecipients) Record(ctx context.Context, alias string, recipients []string, decision []byte, action []byte) {
}
