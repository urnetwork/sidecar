//go:build !sidecar_http && !ios_extension

// The sender's one way into a member's mailbox (§15.7): the outbox o/, the outcomes or/, the prover
// records p/, and DSN deposits. MAIL implements it on its formats (MAIL-M9-02's mailSmtpMailbox) and
// sidecartest.FakeSmtpMailbox in memory, and sidecartest.RunSmtpMailboxSuite holds both to the same
// promises. Methods take effect keys and sidecar ids, never paths: SMTP builds no mailbox path itself,
// and a path's <h> shard and its sealing stay MAIL's.
//
// MAIL writes o/ (§15.10's step 4), so there is no method here to add an entry. The sent copy is MAIL's
// too, stored at step 2; its I-11 label is the tls_level of its or/ outcomes, so WriteOutcomes is how a
// send labels it, and no second write can disagree with what or/ says.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	"errors"
)

// No such entry. A caller that lists and then reads may meet it when another host removed the entry
// in between, and treats it as gone.
var ErrSmtpMailboxNotFound = errors.New("smtp mailbox entry not found")

// One o/<h>/<effect_key> entry as MAIL stored it (plan-SMTP-wire-gaps#4): u32be(length) ‖ Signed ‖
// message bytes, taken apart and not verified. The reader checks the Signed's signature against an
// admitted device of the member, and that its body names this effect key and the message's hash,
// before it trusts anything here (SMTP-M9-09).
type SmtpOutboxFile struct {
	EffectKey []byte
	// The bridge.Signed bytes, SIGNED_SMTP_OUTBOX over SmtpOutboxEntry, as written.
	Signed []byte
	// The RFC 5322 bytes after the Signed.
	Message []byte
}

// A member's mailbox, as the sender reaches it. Safe for concurrent use. A method fails with the
// mailbox's own error, such as a Locked keychain, and the caller holds the send.
type SmtpMailbox interface {
	// The effect key of every o/ entry, in no promised order.
	ListOutbox(ctx context.Context) ([][]byte, error)
	// One o/ entry, or ErrSmtpMailboxNotFound.
	ReadOutbox(ctx context.Context, effectKey []byte) (*SmtpOutboxFile, error)
	// Removes one o/ entry once it is sent and past its approval's retry window, which the caller
	// decides (§15.7). Removing an entry that is gone is no error, so two hosts may both try.
	RemoveOutbox(ctx context.Context, effectKey []byte) error

	// Replaces or/<h>/<effect_key> with one outcome per recipient domain. The record is kept 30 days
	// (§15.7), and each outcome's tls_level is the sent copy's I-11 label for that domain.
	WriteOutcomes(ctx context.Context, effectKey []byte, outcomes []*SmtpDomainOutcome) error
	// The effect keys of every or/ record still kept, in no promised order.
	ListOutcomes(ctx context.Context) ([][]byte, error)
	// One or/ record's outcomes, or ErrSmtpMailboxNotFound.
	ReadOutcomes(ctx context.Context, effectKey []byte) ([]*SmtpDomainOutcome, error)

	// Rewrites p/<sidecar_id> with a prover host's latest measurement (§15.10).
	WriteProverMeasure(ctx context.Context, sidecarId Id, measure *SmtpProverMeasure) error
	// Every p/ record, by the sidecar that wrote it. A caller picks from them only hosts it checked
	// are the member's consented devices (§8.5; owner decision 126).
	ListProverMeasures(ctx context.Context) (map[Id]*SmtpProverMeasure, error)

	// Deposits an RFC 3464 DSN for the o/ entry effectKey names into this mailbox, as a received
	// message is deposited (§15.10's last line). One effect key may get several DSNs, one per send
	// that ended in one.
	DepositDsn(ctx context.Context, effectKey []byte, dsn []byte) error
}
