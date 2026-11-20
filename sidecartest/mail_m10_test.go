//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M10's mailbox cases on T2 (MAIL-M10-04; §22.8's FS-76, FS-78, FS-111 and FS-112, FI-18, FI-19; §23.6's later of
// M10-out and M7-out): mailworld's rows (m10_rows.go), which server's sidecart3 runs on T3's stores
// (mail_m10_t3_test.go), each on a mailbox of its own: mail through the router and the receiver's session into
// evsservice's engine on the Net's fake host, ingested with its index delta by the in-ref writer, erased by
// MailEraser, and held to SearchOracle. The rows add no mechanism. What a real mailbox does not carry yet, and so no
// row here shows, is in that file's header, each gap named for the task it goes back to: no erasure is shown
// complete, none runs at the storage limit, and FS-76's queries run on a search world.

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// A mailbox at format 2 on a Net of its own, T2's fakes.
func newMailM10World(t *testing.T) *mailworld.M10World {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	return mailworld.NewM10World(t, net, nil)
}

// FS-76's mailbox case: the corpus's delivered mail, its index held to the oracle at every bucket boundary, roll-up
// and erasure, and the query set on a desktop and a phone.
func TestFs76MailboxCase(t *testing.T) {
	mailworld.RunM10Fs76Mailbox(t, newMailM10World(t), nil)
}

// FS-78's mailbox case: an admin's erasure of one email, its CUT, first ERASE and CLOSUREs.
func TestFs78MailboxCase(t *testing.T) {
	mailworld.RunM10Fs78Mailbox(t, newMailM10World(t))
}

// FS-111's mailbox case: an ingest paused before its head CAS across an erasure's CUT is refused 409 INDEX_EPOCH and
// commits without the erased message.
func TestFs111MailboxCase(t *testing.T) {
	mailworld.RunM10Fs111Mailbox(t, newMailM10World(t))
}

// FS-112's mailbox case: a 5 MiB message's five chunk documents, and their erasure.
func TestFs112MailboxCase(t *testing.T) {
	mailworld.RunM10Fs112Mailbox(t, newMailM10World(t), nil)
}
