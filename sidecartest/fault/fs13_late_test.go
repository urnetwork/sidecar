//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

package fault

// An erase completes while the ingestor has opened the deposit but has not published
// its mailbox push. The held writer then stops after that push committed. All devices,
// storage and SMTP streams belong to a private MailWorld.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// Reads the staged slots directly so a reader's plaintext withholding cannot hide a missing rewrite.
func fs13SlotHasKey(t *testing.T, world *mailworld.MailWorld, slotId sidecar.Id) bool {
	t.Helper()
	obj, err := world.Cluster.Get(t.Context(), evsservice.SlotKey(world.RepoId, slotId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Body.Close()
	data, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := sidecar.EvsDecodeSlotObject(data)
	if err != nil {
		t.Fatal(err)
	}
	_, held := sidecar.EvsSlotKeyAt(slot, 0)
	return held
}

func TestFs13WithholdsAndShredsLateIngestAfterDepositOnlyErase(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	world := mailworld.NewMailWorld(t, host, clock, settings)
	owner := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	recipient := settings.Addresses[0]
	msg := []byte("From: sender@sender.example\r\nTo: " + recipient + "\r\nSubject: late\r\n\r\nPrivate body.\r\n")
	if reply := world.Send(netip.MustParseAddr("203.0.113.9"), settings.MxHost(), "sender@sender.example", []string{recipient}, msg); !reply.Is(250) {
		t.Fatal(reply)
	}
	deposits, err := world.StandingDeposits(owner)
	if err != nil || len(deposits) != 1 {
		t.Fatalf("standing deposits: %d, %v", len(deposits), err)
	}
	deposit := deposits[0]
	messageId := sidecar.Id(deposit.Deposit.EntryId)
	month := sidecar.MailYearMonthOf(sidecar.MailDepositReceiveTime(deposit.Trailer, uint64(deposit.Deposit.Time.UnixMilli())))
	writerId := world.AdmitReader()
	writer := world.Device(writerId, false, sidecartest.NewFakeStore().Root(), nil)
	pushBefore, pushAfter := make(chan struct{}), make(chan struct{})
	letWrite, letExit := make(chan struct{}), make(chan struct{})
	releaseWrite, releaseExit := sync.OnceFunc(func() { close(letWrite) }), sync.OnceFunc(func() { close(letExit) })
	t.Cleanup(releaseWrite)
	t.Cleanup(releaseExit)
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch name {
		case "mail.ingest.push.before":
			close(pushBefore)
			<-letWrite
		case "mail.ingest.push.after":
			close(pushAfter)
			<-letExit
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(settings.StepTimeout):
			t.Fatal("ingest did not reach its barrier")
		}
	}
	crashingCtx, stopWriter := context.WithCancel(ctx)
	t.Cleanup(stopWriter)
	announced := make(chan struct{}, 1)
	ingestor := world.Ingestor(writer, writerId.SidecarId, func(*sidecar.MailMessage) { announced <- struct{}{} }, nil)
	done := make(chan error, 1)
	go func() {
		_, err := ingestor.Ingest(crashingCtx)
		done <- err
	}()
	wait(pushBefore)
	erasure, err := world.Eraser(owner, world.Owner.SidecarId).Erase(ctx, month, []sidecar.Id{messageId})
	if err != nil || erasure.State != sidecar.MailErasureDone {
		t.Fatalf("deposit-only erase: %+v, %v", erasure, err)
	}
	releaseWrite()
	wait(pushAfter)
	fresh := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	repo := fresh.Repo(world.RepoId)
	paths := []string{sidecar.MailMessagePath(month, messageId), sidecar.MailIndexPath(month, 0)}
	var lateSlots []sidecar.Id
	for _, path := range paths {
		history, err := repo.History(ctx, &sidecar.EvsReadArgs{Path: path})
		if err != nil || len(history.Versions) != 1 || len(history.Versions[0].SlotIds) == 0 {
			t.Fatalf("late path history: %+v, %v", history, err)
		}
		lateSlots = append(lateSlots, history.Versions[0].SlotIds...)
		out := &bytes.Buffer{}
		if _, err := repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path}, out); !errors.Is(err, sidecar.ErrEvsErased) || out.Len() != 0 {
			t.Fatalf("late read returned %d bytes, %v", out.Len(), err)
		}
	}
	for _, slot := range lateSlots {
		if !fs13SlotHasKey(t, world, slot) {
			t.Fatal("the fixture did not leave a late key for the restarted admin")
		}
	}
	stopWriter()
	releaseExit()
	if err := <-done; err == nil || len(announced) != 0 {
		t.Fatalf("interrupted writer: %v, %d notifications", err, len(announced))
	}
	sidecar.SetTestHooks(nil)
	restarted := world.Ingestor(fresh, world.Owner.SidecarId, nil, nil)
	if pass, err := restarted.Ingest(ctx); err != nil || pass.Erased != 1 || pass.Consumed != 1 {
		t.Fatalf("restarted admin: %+v, %v", pass, err)
	}
	for _, slot := range append(lateSlots, deposit.Deposit.SlotId) {
		if fs13SlotHasKey(t, world, slot) {
			t.Fatal("restart left an original, body or index slot open")
		}
	}
	rows, err := repo.ReadErasures(ctx, 0)
	if err != nil || len(rows) != 3 || rows[1].ErasureId != erasure.ErasureId || rows[1].Complete || !rows[2].Complete {
		t.Fatalf("signed reconciliation: %+v, %v", rows, err)
	}
}
