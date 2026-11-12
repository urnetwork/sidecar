// The conformance suite for sidecar.RecordStreams (RECORD-M2-03): what record_seam.go declares, and what §11.8's refs
// table and §11.12 require of it, run on FakeRecordStreams here and on RECORD-M3-12's EvsRepo binding on T2, so the
// fake stays honest (D-TEST-2). Every case reaches the streams through the interface and the world's setup alone, on
// a repo of its own, so one world serves the whole run.
//
// A case is a plain function returning its first failure, and RunRecordStreamsSuite loops over them, as
// dns_store_suite.go does, since one world's cases are homogeneous variations (connect/CODESTYLE.md:216). A failure in
// one does not stop the next.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the suite needs of a world of RecordStreams: fresh repos, scopes to grant on them, the gate, evs's clock, and
// each sidecar's view. FakeRecordStreams is one; RECORD-M3-12's harness on T2 is the other (record_evs_test.go).
type RecordStreamsWorld interface {
	// A fresh record-class repo, its refs empty and no scope granted.
	NewRepo(ctx context.Context) (sidecar.Id, error)
	// Gives sidecarId scope on repoId, as the access log and §7.8's tokens would.
	Grant(repoId sidecar.Id, sidecarId sidecar.Id, scope RecordStreamsScope) error
	// Closes or opens the repo's gate for later pushes and deposits.
	SetGateClosed(repoId sidecar.Id, closed bool)
	// Moves evs's clock forward.
	Advance(duration time.Duration)
	// What sidecarId reaches, carrying its scope.
	For(sidecarId sidecar.Id) sidecar.RecordStreams
}

// A world whose slot rows are another width than RECORD.md section 5.2's 64 B: the T2 harness's, whose row codec wraps
// a row as one of evs's 32 B object keys while RECORD.md's rows wait on question record-m2-01-slot-row-salt. A world
// that does not implement it takes 64 B rows.
type RecordStreamsWorldRows interface {
	RowByteCount() int
}

// How long one case may wait on the world before it fails with what it was waiting for. Real time, so only ever a
// failure's bound (§22.8): nothing here sleeps.
const recordStreamsSuiteCaseTimeout = 30 * time.Second

type recordStreamsSuiteCase struct {
	name string
	run  func(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error
}

// Runs every case on world, each on a fresh repo.
func RunRecordStreamsSuite(t *testing.T, world RecordStreamsWorld) {
	t.Helper()
	for _, suiteCase := range recordStreamsSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), recordStreamsSuiteCaseTimeout)
			defer cancel()
			repoId, err := world.NewRepo(ctx)
			if err != nil {
				t.Errorf("%s: a repo: %v", suiteCase.name, err)
				return
			}
			if err := suiteCase.run(ctx, world, repoId); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func recordStreamsSuiteCases() []recordStreamsSuiteCase {
	return []recordStreamsSuiteCase{
		{name: "a push reads back", run: caseRecordStreamsPushReadsBack},
		{name: "a stream takes creates only", run: caseRecordStreamsCreatesOnly},
		{name: "another writer is refused", run: caseRecordStreamsOwnStreamOnly},
		{name: "each step takes its scope", run: caseRecordStreamsScopes},
		{name: "a retry keeps its slot ids", run: caseRecordStreamsRetryKeepsSlotIds},
		{name: "a closed gate's refusal is recorded", run: caseRecordStreamsGateClosed},
		{name: "a receipt-only depositor keeps the budget", run: caseRecordStreamsReceiptBudget},
		{name: "deposits are read and consumed", run: caseRecordStreamsDepositConsume},
		{name: "an erased key is unreadable", run: caseRecordStreamsEraseRemovesKey},
		{name: "nothing to erase is recorded", run: caseRecordStreamsNothingToErase},
		{name: "a commit is a hint", run: caseRecordStreamsSubscribe},
	}
}

// A world whose pushes must declare a pin of its own chain, as evs's gate and a binding's verified state hold them
// to: the T2 harness's. A world that does not implement it takes the suite's own.
type RecordStreamsWorldPin interface {
	Pin() *bridge.AuthPin
}

// A pin the suite's pushes declare.
func recordStreamsSuitePin(world RecordStreamsWorld) *bridge.AuthPin {
	if pins, ok := world.(RecordStreamsWorldPin); ok {
		return pins.Pin()
	}
	return &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x07}, 32)}
}

// A push of one entry a path, each keyed by a row of a fresh slot at its index, the world's row width. Push, slot and
// deposit ids are random, as the record's writer draws them: an Id's first 8 bytes repeat within a millisecond, and
// evs knows a refused push by its push id's first 8 bytes (§11.8's refusal row).
func recordStreamsSuitePush(world RecordStreamsWorld, writerId sidecar.Id, paths ...string) *sidecar.RecordStreamPush {
	rowByteCount := sidecar.RecordSlotRowByteCount
	if rows, ok := world.(RecordStreamsWorldRows); ok {
		rowByteCount = rows.RowByteCount()
	}
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewEvsPushId(),
		WriterSidecarId: writerId,
		SlotId:          sidecar.NewEvsSlotId(),
		AuthPin:         recordStreamsSuitePin(world),
	}
	for index, path := range paths {
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: uint32(index), Row: bytes.Repeat([]byte{byte(index + 1)}, rowByteCount)})
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: []byte("entry " + path)})
	}
	return push
}

// A deposit of a batch of byteCount bytes.
func recordStreamsSuiteDeposit(world RecordStreamsWorld, depositorId sidecar.Id, byteCount int) *sidecar.RecordStreamDeposit {
	return &sidecar.RecordStreamDeposit{
		PushId:             sidecar.NewEvsPushId(),
		DepositorSidecarId: depositorId,
		DepositId:          sidecar.Id(sidecar.NewEvsRandomToken()),
		Batch:              bytes.Repeat([]byte{0x5a}, byteCount),
		AuthPin:            recordStreamsSuitePin(world),
	}
}

// Nil when err is a refusal with code, and a failure saying what came instead otherwise.
func wantRecordStreamRefusal(what string, err error, code protocol.EvsRefusalCode) error {
	got, ok := sidecar.RecordStreamRefusalCode(err)
	if !ok || got != code {
		return fmt.Errorf("%s: want %s, got %v", what, code, err)
	}
	return nil
}

// Grants each sidecar its scope, stopping at the first failure.
func grantRecordStreams(world RecordStreamsWorld, repoId sidecar.Id, sidecarScopes map[sidecar.Id]RecordStreamsScope) error {
	for sidecarId, scope := range sidecarScopes {
		if err := world.Grant(repoId, sidecarId, scope); err != nil {
			return err
		}
	}
	return nil
}

// A stream's newest version, 0 when it has none.
func recordStreamVersion(ctx context.Context, streams sidecar.RecordStreams, repoId sidecar.Id, writerId sidecar.Id) (uint64, error) {
	heads, err := streams.Streams(ctx, repoId)
	if err != nil {
		return 0, err
	}
	for _, head := range heads {
		if head.SidecarId == writerId {
			return head.Version, nil
		}
	}
	return 0, nil
}

func caseRecordStreamsPushReadsBack(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		return err
	}
	streams := world.For(writerId)
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1", "e/0/0/2")
	commit, err := streams.Append(ctx, repoId, push)
	if err != nil {
		return err
	}
	if commit.Version != 1 || commit.TimeMillis <= 0 {
		return fmt.Errorf("the first push committed %+v", commit)
	}
	if version, err := recordStreamVersion(ctx, streams, repoId, writerId); err != nil || version != 1 {
		return fmt.Errorf("the stream lists version %d: %v", version, err)
	}
	versions, err := streams.ReadStream(ctx, repoId, writerId, 0)
	if err != nil {
		return err
	}
	if len(versions) != 1 {
		return fmt.Errorf("%d versions read back", len(versions))
	}
	version := versions[0]
	if version.Version != 1 || version.PushId != push.PushId || version.SlotId != push.SlotId || version.TimeMillis != commit.TimeMillis {
		return fmt.Errorf("the push read back as %+v", version)
	}
	// the pin the push declared at least: a binding may declare its newer verified state's
	if version.AuthPin.GetVersion() < push.AuthPin.GetVersion() ||
		(version.AuthPin.GetVersion() == push.AuthPin.GetVersion() && !bytes.Equal(version.AuthPin.GetChain(), push.AuthPin.GetChain())) {
		return errors.New("the push's pin did not read back")
	}
	if len(version.Entries) != len(push.Entries) {
		return fmt.Errorf("%d entries read back", len(version.Entries))
	}
	for i, entry := range version.Entries {
		if entry.Path != push.Entries[i].Path || !bytes.Equal(entry.Entry, push.Entries[i].Entry) {
			return fmt.Errorf("entry %d read back as %s", i, entry.Path)
		}
	}
	if later, err := streams.ReadStream(ctx, repoId, writerId, 1); err != nil || len(later) != 0 {
		return fmt.Errorf("after version 1 read %d versions: %v", len(later), err)
	}
	slot, err := streams.ReadSlot(ctx, repoId, push.SlotId)
	if err != nil {
		return err
	}
	if len(slot.Rows) != len(push.SlotRows) {
		return fmt.Errorf("the slot holds %d rows", len(slot.Rows))
	}
	for i, row := range slot.Rows {
		if row.KeyIndex != push.SlotRows[i].KeyIndex || !bytes.Equal(row.Row, push.SlotRows[i].Row) {
			return fmt.Errorf("slot row %d read back as index %d", i, row.KeyIndex)
		}
	}
	return wantRecordStreamRefusal("a slot no push made", errOf(streams.ReadSlot(ctx, repoId, sidecar.NewId())), protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

// The error of a two-value call.
func errOf[T any](value T, err error) error {
	return err
}

func caseRecordStreamsCreatesOnly(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		return err
	}
	streams := world.For(writerId)
	if _, err := streams.Append(ctx, repoId, recordStreamsSuitePush(world, writerId, "e/0/0/1", "e/0/0/2")); err != nil {
		return err
	}
	rewrite := recordStreamsSuitePush(world, writerId, "e/0/0/2", "e/0/0/3")
	if err := wantRecordStreamRefusal("a push rewriting a path", errOf(streams.Append(ctx, repoId, rewrite)), protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT); err != nil {
		return err
	}
	twice := recordStreamsSuitePush(world, writerId, "e/0/0/4", "e/0/0/4")
	if _, err := streams.Append(ctx, repoId, twice); err == nil {
		return errors.New("a push creating a path twice committed")
	}
	if version, err := recordStreamVersion(ctx, streams, repoId, writerId); err != nil || version != 1 {
		return fmt.Errorf("a refused push moved the stream to %d: %v", version, err)
	}
	return nil
}

func caseRecordStreamsOwnStreamOnly(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	otherId := sidecar.NewId()
	err := grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		writerId: {Read: true, Write: true},
		otherId:  {Read: true, Write: true, Deposit: true},
	})
	if err != nil {
		return err
	}
	if _, err := world.For(writerId).Append(ctx, repoId, recordStreamsSuitePush(world, writerId, "e/0/0/1")); err != nil {
		return err
	}
	forged := recordStreamsSuitePush(world, writerId, "e/0/0/2")
	if err := wantRecordStreamRefusal("another writer's push", errOf(world.For(otherId).Append(ctx, repoId, forged)), protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE); err != nil {
		return err
	}
	if version, err := recordStreamVersion(ctx, world.For(writerId), repoId, writerId); err != nil || version != 1 {
		return fmt.Errorf("another writer moved the stream to %d: %v", version, err)
	}
	forgedDeposit := recordStreamsSuiteDeposit(world, writerId, 512)
	return wantRecordStreamRefusal("a deposit to another's ref", errOf(world.For(otherId).Deposit(ctx, repoId, forgedDeposit)), protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
}

func caseRecordStreamsScopes(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	noneId := sidecar.NewId()
	readerId := sidecar.NewId()
	if err := world.Grant(repoId, readerId, RecordStreamsScope{Read: true}); err != nil {
		return err
	}
	none := world.For(noneId)
	reader := world.For(readerId)
	// a sidecar with no scope, and a reader's push, CONSUME and ERASE, may be refused before evs is asked, by the
	// binding's key holder, which seals for writers alone, so any refusal answers; a reader's deposit reaches evs,
	// which refuses it 403 SCOPE
	refusedChecks := []struct {
		what string
		err  error
	}{
		{what: "a push with no scope", err: errOf(none.Append(ctx, repoId, recordStreamsSuitePush(world, noneId, "e/0/0/1")))},
		{what: "a stream list with no scope", err: errOf(none.Streams(ctx, repoId))},
		{what: "a stream read with no scope", err: errOf(none.ReadStream(ctx, repoId, readerId, 0))},
		{what: "an erasure read with no scope", err: errOf(none.ReadErasures(ctx, repoId, 0))},
		{what: "a deposit list with no scope", err: errOf(none.DepositRefs(ctx, repoId))},
		{what: "a push at read", err: errOf(reader.Append(ctx, repoId, recordStreamsSuitePush(world, readerId, "e/0/0/1")))},
		{
			what: "a CONSUME at read",
			err: errOf(reader.Consume(ctx, repoId, &sidecar.RecordStreamConsume{
				PushId: sidecar.NewEvsPushId(), DepositorSidecarId: noneId, DepositIds: []sidecar.Id{sidecar.NewId()},
			})),
		},
		{
			what: "an ERASE at read",
			err: errOf(reader.Erase(ctx, repoId, &sidecar.RecordStreamErase{
				PushId: sidecar.NewEvsPushId(), Keys: []*sidecar.RecordSlotKey{{SlotId: sidecar.NewId(), KeyIndex: 0}},
			})),
		},
	}
	for _, check := range refusedChecks {
		if check.err == nil {
			return fmt.Errorf("%s: not refused", check.what)
		}
	}
	checks := []struct {
		what string
		err  error
	}{
		{what: "a deposit at read", err: errOf(reader.Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, readerId, 512)))},
	}
	for _, check := range checks {
		if err := wantRecordStreamRefusal(check.what, check.err, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE); err != nil {
			return err
		}
	}
	return nil
}

func caseRecordStreamsRetryKeepsSlotIds(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		return err
	}
	streams := world.For(writerId)
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1")
	commit, err := streams.Append(ctx, repoId, push)
	if err != nil {
		return err
	}
	retried, err := streams.Append(ctx, repoId, push)
	if err != nil {
		return fmt.Errorf("a retry of the same statement: %v", err)
	}
	if *retried != *commit {
		return fmt.Errorf("a retry answered %+v, the push %+v", retried, commit)
	}
	reslotted := *push
	reslotted.SlotId = sidecar.NewEvsSlotId()
	if err := wantRecordStreamRefusal("a retry with new slot ids", errOf(streams.Append(ctx, repoId, &reslotted)), protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED); err != nil {
		return err
	}
	if version, err := recordStreamVersion(ctx, streams, repoId, writerId); err != nil || version != 1 {
		return fmt.Errorf("retries moved the stream to %d: %v", version, err)
	}
	return nil
}

func caseRecordStreamsGateClosed(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		return err
	}
	streams := world.For(writerId)
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1")
	world.SetGateClosed(repoId, true)
	_, err := streams.Append(ctx, repoId, push)
	if err := wantRecordStreamRefusal("a push past a closed gate", err, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED); err != nil {
		return err
	}
	var refusal *sidecar.RecordStreamRefusal
	if !errors.As(err, &refusal) || !refusal.Recorded {
		return errors.New("GATE_CLOSED was not recorded")
	}
	world.SetGateClosed(repoId, false)
	// The refused statement can never commit (I-EVS-3): its retry gets the recorded refusal.
	if err := wantRecordStreamRefusal("a retry after the gate opened", errOf(streams.Append(ctx, repoId, push)), protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED); err != nil {
		return err
	}
	rebuilt := *push
	rebuilt.PushId = sidecar.NewEvsPushId()
	rebuilt.SlotId = sidecar.NewEvsSlotId()
	commit, err := streams.Append(ctx, repoId, &rebuilt)
	if err != nil {
		return fmt.Errorf("a rebuilt push: %v", err)
	}
	if commit.Version != 1 {
		return fmt.Errorf("the rebuilt push committed version %d", commit.Version)
	}
	return nil
}

func caseRecordStreamsReceiptBudget(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	receiptId := sidecar.NewId()
	depositorId := sidecar.NewId()
	err := grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		receiptId:   {Deposit: true, ReceiptOnly: true},
		depositorId: {Deposit: true},
	})
	if err != nil {
		return err
	}
	receipts := world.For(receiptId)
	// past 4 KiB: evs answers its size cap 403 QUOTA_LIMIT where §11.12 says 429, so either answers
	oversize := errOf(receipts.Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, receiptId, 5*1024)))
	if wantRecordStreamRefusal("a 5 KiB receipt", oversize, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT) != nil {
		if err := wantRecordStreamRefusal("a 5 KiB receipt", oversize, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED); err != nil {
			return err
		}
	}
	for count := 1; count <= 256; count += 1 {
		if _, err := receipts.Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, receiptId, 1024)); err != nil {
			return fmt.Errorf("receipt %d: %v", count, err)
		}
	}
	if err := wantRecordStreamRefusal("receipt 257", errOf(receipts.Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, receiptId, 1024))), protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED); err != nil {
		return err
	}
	// Another depositor is not a receipt-only one: no such cap.
	if _, err := world.For(depositorId).Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, depositorId, 5*1024)); err != nil {
		return fmt.Errorf("a 5 KiB deposit from a writer's depositor: %v", err)
	}
	world.Advance(24 * time.Hour)
	if _, err := receipts.Deposit(ctx, repoId, recordStreamsSuiteDeposit(world, receiptId, 1024)); err != nil {
		return fmt.Errorf("a receipt the next day: %v", err)
	}
	return nil
}

func caseRecordStreamsDepositConsume(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	depositorId := sidecar.NewId()
	ingesterId := sidecar.NewId()
	err := grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		depositorId: {Deposit: true},
		ingesterId:  {Read: true, Write: true},
	})
	if err != nil {
		return err
	}
	depositor := world.For(depositorId)
	ingester := world.For(ingesterId)
	first := recordStreamsSuiteDeposit(world, depositorId, 512)
	second := recordStreamsSuiteDeposit(world, depositorId, 768)
	for _, deposit := range []*sidecar.RecordStreamDeposit{first, second} {
		if _, err := depositor.Deposit(ctx, repoId, deposit); err != nil {
			return err
		}
	}
	again := recordStreamsSuiteDeposit(world, depositorId, 512)
	again.DepositId = first.DepositId
	if err := wantRecordStreamRefusal("a deposit reusing an id", errOf(depositor.Deposit(ctx, repoId, again)), protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT); err != nil {
		return err
	}
	refs, err := ingester.DepositRefs(ctx, repoId)
	if err != nil {
		return err
	}
	if len(refs) != 1 || refs[0].SidecarId != depositorId || refs[0].Version != 2 {
		return fmt.Errorf("the deposit refs read %+v", refs)
	}
	deposits, err := ingester.ReadDeposits(ctx, repoId, depositorId)
	if err != nil {
		return err
	}
	if len(deposits) != 2 || deposits[0].DepositId != first.DepositId || deposits[1].DepositId != second.DepositId ||
		deposits[0].Version >= deposits[1].Version || !bytes.Equal(deposits[1].Batch, second.Batch) {
		return errors.New("the deposits did not read back in version order")
	}
	consume := &sidecar.RecordStreamConsume{PushId: sidecar.NewEvsPushId(), DepositorSidecarId: depositorId, DepositIds: []sidecar.Id{first.DepositId}}
	if _, err := ingester.Consume(ctx, repoId, consume); err != nil {
		return err
	}
	deposits, err = ingester.ReadDeposits(ctx, repoId, depositorId)
	if err != nil {
		return err
	}
	if len(deposits) != 1 || deposits[0].DepositId != second.DepositId {
		return fmt.Errorf("%d deposits after a CONSUME", len(deposits))
	}
	// A second ingester's CONSUME of what is gone: the deposit reads as consumed either way.
	late := &sidecar.RecordStreamConsume{PushId: sidecar.NewEvsPushId(), DepositorSidecarId: depositorId, DepositIds: []sidecar.Id{first.DepositId}}
	return wantRecordStreamRefusal("a CONSUME of a consumed deposit", errOf(ingester.Consume(ctx, repoId, late)), protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
}

func caseRecordStreamsEraseRemovesKey(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	adminId := sidecar.NewId()
	err := grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		writerId: {Read: true, Write: true},
		adminId:  {Read: true, Write: true, Admin: true},
	})
	if err != nil {
		return err
	}
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1", "e/0/0/2", "e/0/0/3")
	if _, err := world.For(writerId).Append(ctx, repoId, push); err != nil {
		return err
	}
	admin := world.For(adminId)
	erase := &sidecar.RecordStreamErase{
		PushId:     sidecar.NewEvsPushId(),
		ErasureId:  sidecar.NewId(),
		Complete:   true,
		Keys:       []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: 1}},
		SealedNote: []byte("sealed note"),
	}
	if _, err := admin.Erase(ctx, repoId, erase); err != nil {
		return err
	}
	slot, err := world.For(writerId).ReadSlot(ctx, repoId, push.SlotId)
	if err != nil {
		return err
	}
	if len(slot.Rows) != 2 || slot.Rows[0].KeyIndex != 0 || slot.Rows[1].KeyIndex != 2 {
		return fmt.Errorf("after the ERASE the slot holds %d rows", len(slot.Rows))
	}
	for _, row := range slot.Rows {
		if bytes.Equal(row.Row, push.SlotRows[1].Row) {
			return errors.New("the erased key is still readable")
		}
	}
	erasures, err := admin.ReadErasures(ctx, repoId, 0)
	if err != nil {
		return err
	}
	if len(erasures) != 1 || erasures[0].PushId != erase.PushId || erasures[0].EraserSidecarId != adminId ||
		erasures[0].ErasureId != erase.ErasureId || !erasures[0].Complete ||
		!bytes.Equal(erasures[0].SealedNote, erase.SealedNote) || len(erasures[0].Keys) != 1 ||
		*erasures[0].Keys[0] != *erase.Keys[0] {
		return errors.New("the ERASE did not read back")
	}
	// The entry files stay: headers and chains still verify after erasure (§16.8).
	versions, err := admin.ReadStream(ctx, repoId, writerId, 0)
	if err != nil {
		return err
	}
	if len(versions) != 1 || len(versions[0].Entries) != 3 {
		return errors.New("the ERASE took entry files")
	}
	return nil
}

func caseRecordStreamsNothingToErase(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	adminId := sidecar.NewId()
	err := grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		writerId: {Read: true, Write: true},
		adminId:  {Read: true, Admin: true},
	})
	if err != nil {
		return err
	}
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1")
	if _, err := world.For(writerId).Append(ctx, repoId, push); err != nil {
		return err
	}
	admin := world.For(adminId)
	key := &sidecar.RecordSlotKey{SlotId: push.SlotId, KeyIndex: 0}
	if _, err := admin.Erase(ctx, repoId, &sidecar.RecordStreamErase{PushId: sidecar.NewEvsPushId(), Keys: []*sidecar.RecordSlotKey{key}}); err != nil {
		return err
	}
	again := &sidecar.RecordStreamErase{PushId: sidecar.NewEvsPushId(), Keys: []*sidecar.RecordSlotKey{key}}
	_, err = admin.Erase(ctx, repoId, again)
	if err := wantRecordStreamRefusal("an ERASE of an erased key", err, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		return err
	}
	var refusal *sidecar.RecordStreamRefusal
	if !errors.As(err, &refusal) || !refusal.Recorded {
		return errors.New("NOTHING_TO_ERASE was not recorded")
	}
	if err := wantRecordStreamRefusal("its retry", errOf(admin.Erase(ctx, repoId, again)), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		return err
	}
	unknown := &sidecar.RecordStreamErase{PushId: sidecar.NewEvsPushId(), Keys: []*sidecar.RecordSlotKey{{SlotId: sidecar.NewId(), KeyIndex: 3}}}
	if err := wantRecordStreamRefusal("an ERASE of no slot", errOf(admin.Erase(ctx, repoId, unknown)), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		return err
	}
	erasures, err := admin.ReadErasures(ctx, repoId, 0)
	if err != nil {
		return err
	}
	if len(erasures) != 1 {
		return fmt.Errorf("%d ERASEs committed", len(erasures))
	}
	return nil
}

func caseRecordStreamsSubscribe(ctx context.Context, world RecordStreamsWorld, repoId sidecar.Id) error {
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		return err
	}
	streams := world.For(writerId)
	hinted := make(chan sidecar.Id, 16)
	unsubscribe := streams.Subscribe(repoId, func(hintedRepoId sidecar.Id) {
		select {
		case hinted <- hintedRepoId:
		default:
		}
	})
	defer unsubscribe()
	if _, err := streams.Append(ctx, repoId, recordStreamsSuitePush(world, writerId, "e/0/0/1")); err != nil {
		return err
	}
	select {
	case hintedRepoId := <-hinted:
		if hintedRepoId != repoId {
			return fmt.Errorf("a hint for repo %s", hintedRepoId)
		}
	case <-ctx.Done():
		return errors.New("no hint after a commit")
	}
	return nil
}
