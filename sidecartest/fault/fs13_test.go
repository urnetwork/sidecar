//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

package fault

// FS-13 (§22.8; §15.7's ingest and erasure rows, D-MAIL-5, FI-1, FI-5; MAIL-M7-27) on T2, over mailworld.MailWorld's
// evs engine: a message through the router is deposited, and the owner's ingest is killed between its push and its
// CONSUME, at MAIL-M7-15's barrier mail.ingest.consume.before, so the message's m/ and its i/ row stand beside the
// unconsumed deposit. The owner's device then erases the message (MAIL-M7-16): its first ERASE names the message and
// takes its body's key and the deposit's slot, and its CLOSURE re-checkpoints the i/ segment without the row and its
// ERASE takes every older version's key. Then:
//
//   - a reader admitted after the erasure opens none of it: no version of m/, no older version of the i/ segment, the
//     newest holding no row of it, and not the deposit;
//   - a restarted ingest, on the owner's device and on the new reader's, consumes the deposit with no message and writes
//     no m/ again;
//   - the killed ingest, let go, writes nothing either.
//
// FI-1's and FI-5's oracles read the fault world's evs objects, not this world's, so this run checks the row's clauses
// by reads alone; a fault.Builder over a Net that binds them is the review phase's, and until then a gate sweep reads
// FS-13 missing.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The bytes of every version of path that reader opens, by version; refused versions are absent.
func fs13OpenVersions(t *testing.T, ctx context.Context, repo *sidecar.EvsRepo, path string) (opened map[uint64][]byte, versionCount int) {
	t.Helper()
	history, err := repo.History(ctx, &sidecar.EvsReadArgs{Path: path})
	if err != nil {
		t.Fatalf("%s's history: %v", path, err)
	}
	opened = map[uint64][]byte{}
	for _, version := range history.Versions {
		if version.Removed {
			continue
		}
		out := &bytes.Buffer{}
		if _, err := repo.ReadVersion(ctx, &sidecar.EvsReadArgs{Path: path, Version: version.Version}, out); err == nil {
			opened[version.Version] = out.Bytes()
		}
	}
	return opened, len(history.Versions)
}

// An owner's erasure on a fresh store also destroys the deposit slot when a different reader's CONSUME committed
// its removal but the slot delete failed. The eraser has no consume journal from that reader to replay.
func TestFs13ErasesAConsumedDepositWhoseOriginalSlotSurvived(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	world := mailworld.NewMailWorld(t, host, clock, settings)
	consumer := world.AdmitReader()
	ingestClient := world.Device(consumer, false, sidecartest.NewFakeStore().Root(), nil)
	recipient := settings.Addresses[0]
	body := []byte("From: <sender@sender.example>\r\nTo: <" + recipient + ">\r\nSubject: interrupted\r\n\r\nMessage for the owner.\r\n")
	if reply := world.Send(netip.MustParseAddr("203.0.113.9"), settings.MxHost(), "sender@sender.example", []string{recipient}, body); !reply.Is(250) {
		t.Fatal(reply)
	}
	deposits, err := world.StandingDeposits(ingestClient)
	if err != nil || len(deposits) != 1 {
		t.Fatalf("deposit before ingest: %d, %v", len(deposits), err)
	}
	slotId := deposits[0].Deposit.SlotId
	slotKey := evsservice.SlotKey(world.RepoId, slotId)
	if _, err := host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpDelete, KeyPrefix: slotKey, Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	var written *sidecar.MailMessage
	ingest := world.Ingestor(ingestClient, consumer.SidecarId, func(message *sidecar.MailMessage) { written = message }, nil)
	if _, err := ingest.Ingest(ctx); err == nil || written == nil {
		t.Fatalf("ingest before failed slot delete: message %v, %v", written, err)
	}
	owner := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	if standing, err := world.StandingDeposits(owner); err != nil || len(standing) != 0 {
		t.Fatalf("the committed CONSUME left %d standing deposits: %v", len(standing), err)
	}
	if _, err := world.Cluster.Head(ctx, slotKey); err != nil {
		t.Fatalf("the interrupted CONSUME's surviving slot: %v", err)
	}
	erasure, err := world.Eraser(owner, world.Owner.SidecarId).Erase(ctx, written.Month, []sidecar.Id{written.Id})
	if err != nil || erasure.State != sidecar.MailErasureDone {
		t.Fatalf("the owner's erasure: %+v, %v", erasure, err)
	}
	erased := false
	confirmed, err := owner.Repo(world.RepoId).ReadErasures(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range confirmed {
		for _, key := range evidence.Keys {
			erased = erased || key.SlotId == slotId && key.KeyIndex == 0
		}
	}
	if !erased {
		t.Fatal("the completed erasure omitted the surviving deposit slot")
	}
	slot, err := world.Cluster.Get(ctx, slotKey)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Body.Close()
	data, err := io.ReadAll(slot.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := sidecar.EvsDecodeSlotObject(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := sidecar.EvsSlotKeyAt(decoded, 0); held {
		t.Fatal("the completed erasure left the original deposit key in the service store")
	}
}

func TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	// Fail one path read in the unconsumed depositor's ref, after its mailbox write is durable.
	var failDepositRead atomic.Bool
	var depositRefId sidecar.Id
	readFailure := errors.New("deposit entry temporarily unavailable")
	settings.EvsReadError = func(read *protocol.EvsReadRequest) error {
		if failDepositRead.Load() && len(read.GetPaths()) != 0 && bytes.Equal(read.GetRefId(), depositRefId[:]) && failDepositRead.Swap(false) {
			return readFailure
		}
		return nil
	}
	world := mailworld.NewMailWorld(t, host, clock, settings)
	depositRefId = sidecar.EvsDepositRefId(world.RepoId, world.Receiver.SidecarId)
	recipient := settings.Addresses[0]
	owner := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	kept := []byte("From: <sender@sender.example>\r\nTo: <" + recipient + ">\r\nSubject: kept\r\nMessage-ID: <kept@sender.example>\r\n\r\nA message that stays.\r\n")
	erased := []byte("From: <sender@sender.example>\r\nTo: <" + recipient + ">\r\nSubject: erased\r\nMessage-ID: <erased@sender.example>\r\n\r\nA message to erase.\r\n")
	sender := netip.MustParseAddr("203.0.113.9")
	if reply := world.Send(sender, settings.MxHost(), "sender@sender.example", []string{recipient}, kept); !reply.Is(250) {
		t.Fatalf("the kept message: %s", reply)
	}
	if pass, err := world.Ingestor(owner, world.Owner.SidecarId, nil, nil).Ingest(ctx); err != nil || pass.Ingested != 1 {
		t.Fatalf("the kept message's ingest: %+v, %v", pass, err)
	}
	if reply := world.Send(sender, settings.MxHost(), "sender@sender.example", []string{recipient}, erased); !reply.Is(250) {
		t.Fatalf("the message to erase: %s", reply)
	}

	// the owner's ingest killed between its push and its CONSUME
	reached := make(chan struct{})
	release := make(chan struct{})
	releaseIngest := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseIngest)
	var holdOnce sync.Once
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != "mail.ingest.consume.before" {
			return
		}
		held := false
		holdOnce.Do(func() { held = true })
		if held {
			close(reached)
			<-release
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	var written *sidecar.MailMessage
	crashing := world.Ingestor(owner, world.Owner.SidecarId, func(message *sidecar.MailMessage) { written = message }, nil)
	crashed := make(chan error, 1)
	go func() {
		_, err := crashing.Ingest(context.Background())
		crashed <- err
	}()
	select {
	case <-reached:
	case <-time.After(settings.StepTimeout):
		t.Fatal("the ingest never reached its CONSUME")
	}
	if written == nil {
		t.Fatal("the killed ingest wrote no message before its CONSUME")
	}
	messagePath := sidecar.MailMessagePath(written.Month, written.Id)
	segmentPath := sidecar.MailIndexPath(written.Month, 0)
	if deposits, err := world.StandingDeposits(owner); err != nil || len(deposits) != 1 {
		t.Fatalf("the deposit beside its message: %d, %v", len(deposits), err)
	}

	// The owner needs a verified answer for the deposit slot before any key can go.
	eraser := world.Eraser(owner, world.Owner.SidecarId)
	failDepositRead.Store(true)
	if erasure, err := eraser.Erase(ctx, written.Month, []sidecar.Id{written.Id}); !errors.Is(err, readFailure) || erasure != nil {
		t.Fatalf("erasure with incomplete deposit inventory: %+v, %v", erasure, err)
	}
	if committed, err := owner.Repo(world.RepoId).ReadErasures(ctx, 0); err != nil || len(committed) != 0 {
		t.Fatalf("committed erasures before the retry: %d, %v", len(committed), err)
	}
	erasure, err := eraser.Erase(ctx, written.Month, []sidecar.Id{written.Id})
	if err != nil || erasure.State != sidecar.MailErasureDone {
		t.Fatalf("the erasure: %+v, %v", erasure, err)
	}

	// a reader admitted after it opens none of the message's copies
	newcomer := world.AdmitReader()
	newcomerEvs := world.Device(newcomer, false, sidecartest.NewFakeStore().Root(), nil)
	newcomerRepo := newcomerEvs.Repo(world.RepoId)
	if opened, versionCount := fs13OpenVersions(t, ctx, newcomerRepo, messagePath); len(opened) != 0 || versionCount == 0 {
		t.Fatalf("the newcomer opened %d of the erased message's %d versions", len(opened), versionCount)
	}
	opened, versionCount := fs13OpenVersions(t, ctx, newcomerRepo, segmentPath)
	if len(opened) != 1 || versionCount < 2 {
		t.Fatalf("the newcomer opened %d of the i/ segment's %d versions", len(opened), versionCount)
	}
	for _, content := range opened {
		if bytes.Contains(content, written.Id.Bytes()) || !bytes.Contains(content, []byte("kept")) {
			t.Fatal("the i/ segment's open version holds the erased row, or lost the kept one")
		}
	}
	err = newcomerRepo.ReadDeposits(ctx, world.Receiver.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		content, err := io.ReadAll(body)
		if err == nil && bytes.Contains(content, []byte("A message to erase.")) {
			t.Error("the newcomer opened the erased deposit")
		}
		return nil
	})
	// the deposit's slot went with the ERASE, so its seal does not open
	if !errors.Is(err, sidecar.ErrEvsSealInvalid) {
		t.Fatalf("the newcomer's read of the erased deposit: %v", err)
	}

	// restarted ingests consume the deposit with no message, and write no m/ again
	for _, restart := range []struct {
		client    *sidecar.EvsClient
		sidecarId sidecar.Id
	}{{owner, world.Owner.SidecarId}, {newcomerEvs, newcomer.SidecarId}} {
		pass, err := world.Ingestor(restart.client, restart.sidecarId, nil, nil).Ingest(ctx)
		if err != nil || pass.Ingested != 0 || pass.Present != 0 {
			t.Fatalf("a restarted ingest: %+v, %v", pass, err)
		}
	}
	if deposits, err := world.StandingDeposits(owner); err != nil || len(deposits) != 0 {
		t.Fatalf("deposits after the restarted ingests: %d, %v", len(deposits), err)
	}
	if opened, _ := fs13OpenVersions(t, ctx, owner.Repo(world.RepoId), messagePath); len(opened) != 0 {
		t.Fatal("the erased message opens after the restarted ingests")
	}

	// the killed ingest, let go, writes nothing
	releaseIngest()
	select {
	case <-crashed:
	case <-time.After(settings.StepTimeout):
		t.Fatal("the held ingest never returned")
	}
	if opened, _ := fs13OpenVersions(t, ctx, newcomerRepo, messagePath); len(opened) != 0 {
		t.Fatal("the erased message opens after the held ingest returned")
	}
}
