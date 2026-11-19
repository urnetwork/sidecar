//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M8's mail rows that run on more than one tier (MAIL-M8-10), each one flow over an M8World that sidecartest's test
// runs on T2 and server's sidecart3 on T3's stores, where the world's log is server's sequencer.

package mailworld

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One indexer path, and FS-82's M8 case on it (§22.8's FS-82; R-MAIL-8, D-MAIL-15, owner decision 150): world's
// receiver, the device its settings named for the host, takes mail as an online receiver before any designation, while
// the owner's coverage reads foreground-only and Status, which ur status and mail.status print, carries §15.6's
// prompt, and a first burner comes back with the foreground-only copy; the device's own IndexerSet for mail lands at
// member scope, coverage reads indexer and the prompt is gone; and the designated receiver takes the next message
// through the router, both deposited under its own identity and ingested as the burner's mail. host names the path
// in a failure.
func RunM8IndexerPath(t testing.TB, world *M8World, host string) {
	t.Helper()
	ctx := world.Context()

	status, err := world.OwnerMail.Status(ctx)
	if err != nil || !status.Enabled || !status.MailIndexerKnown || status.MailIndexer || status.Prompt != sidecar.MailIndexerPrompt {
		t.Fatalf("%s: before a designation, status %+v: %v", host, status, err)
	}
	if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageForegroundOnly {
		t.Fatalf("%s: before a designation, coverage %s: %v", host, coverage, err)
	}
	created, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: "https://" + M8SenderDomain + "/signup"})
	if err != nil {
		t.Fatalf("%s: %v", host, err)
	}
	if created.CoverageCopy != sidecar.MailCoverageForegroundOnlyCopy {
		t.Fatalf("%s: the first burner's copy %q", host, created.CoverageCopy)
	}
	world.SyncReceiver()
	// FS-82's M8 case: with no mail indexer an online receiver still takes mail
	if reply := world.Send(created.Address, "before a designation", "Your verification code is 482913."); !reply.Is(250) {
		t.Fatalf("%s: mail before a designation: %s", host, reply)
	}

	world.Designate(world.Receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
	if indexers := world.Admission.State().Indexers(); len(indexers) != 1 || indexers[0].SidecarId != world.Receiver.SidecarId {
		t.Fatalf("%s: the designations %+v", host, indexers)
	}
	if coverage, err := world.OwnerMail.ReceiverCoverage(ctx); err != nil || coverage != sidecar.MailCoverageIndexer {
		t.Fatalf("%s: once designated, coverage %s: %v", host, coverage, err)
	}
	status, err = world.OwnerMail.Status(ctx)
	if err != nil || !status.MailIndexerKnown || !status.MailIndexer || status.Prompt != "" {
		t.Fatalf("%s: once designated, status %+v: %v", host, status, err)
	}
	if reply := world.Send(created.Address, "to the indexer", "Your verification code is 731004."); !reply.Is(250) {
		t.Fatalf("%s: mail to the designated indexer: %s", host, reply)
	}
	// both under the designated receiver's own identity, and ingested as the burner's mail
	for subject, depositorId := range world.Depositors() {
		if depositorId != world.Receiver.SidecarId {
			t.Fatalf("%s: %q was deposited by %s, not the %s", host, subject, depositorId, host)
		}
	}
	messages := world.Ingest()
	for _, subject := range []string{"before a designation", "to the indexer"} {
		message := messages[subject]
		if message == nil || message.DepositorId != world.Receiver.SidecarId {
			t.Fatalf("%s: %q was not ingested from the %s: %+v", host, subject, host, message)
		}
	}
}

// The hosts an indexer path runs under: each is one mechanism, a ur daemon, so each path is the same run under its
// host's name. No app is a mail indexer (owner decision 197).
func M8IndexerHosts() []string {
	return []string{"desktop daemon", "nas", "vps"}
}
