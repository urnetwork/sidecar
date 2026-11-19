//go:build !sidecar_http && !ios_extension

// §16.8's reach receipts for internet mail (owner decision 25; §14.9's "a ReachReceipt per send, recipients with
// BCC"; SMTP-M9-08): SmtpSender is the endpoint enforcing the send's mail_send grant, so each recipient an MX took
// is one note to RecordReach, kind send, under the grant SmtpSenderArgs.ReachGrant names for the message. Bcc
// recipients are noted as every other, since a receipt lists every recipient, while the header block names none
// of them. RecordReach coalesces the notes per (grant, peer) per window and writes them to the vault or the team
// record (record_reach.go).
//
// A peer is the recipient, as two ids that together name it: its local part and its domain, each of which RecordReach
// bounds at PeerIdByteCount (64 octets). SPEC.md 4.2 holds a local part to 64, so only a domain past 64 octets is
// refused there, logged with no name and dropped, and the send goes on (a reading: §16.8 names no peer form for a
// recipient). The relay is the MX host the edge dialed. Nothing here is server-visible: the record is sealed in evs.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

// The mail_send grant a send's receipts name, as the gate judged it (§16.8's grant_id, policy_version, owner,
// approver and action_id).
type SmtpReachGrant struct {
	// 32 bytes, ACL's AclGrantId.
	GrantId       []byte
	PolicyVersion uint64
	Owner         []byte
	Approver      []byte
	// The approval's action_id, 32 bytes, or empty.
	ActionId []byte
}

// One note a recipient the MX took, kind send, its bytes the message's on the wire.
func smtpReachNotes(grant *SmtpReachGrant, recipients []string, byteCount uint64, mxHost string) []*RecordReachNote {
	if grant == nil {
		return nil
	}
	notes := make([]*RecordReachNote, 0, len(recipients))
	for _, recipient := range recipients {
		local, domain, ok := SplitSmtpEnvelopeAddress(recipient)
		if !ok {
			continue
		}
		notes = append(notes, &RecordReachNote{
			Kind:          RecordReachKindSend,
			GrantId:       grant.GrantId,
			PolicyVersion: grant.PolicyVersion,
			Owner:         grant.Owner,
			Approver:      grant.Approver,
			ActionId:      grant.ActionId,
			Peers:         [][]byte{[]byte(local), []byte(domain)},
			StreamCount:   1,
			ByteCount:     byteCount,
			Relays:        []RecordReachRelay{{Host: mxHost}},
		})
	}
	return notes
}
