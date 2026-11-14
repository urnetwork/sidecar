//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-30's M3 case on T2 (§22.8; §16, §8.5, §11.12; D-MCP-18, I-4; RECORD-M3-11), and record.proto's freeze evidence.
//
// FS-30: an EvsShare reader's first read of a vault with the author offline. The reader is a sidecar.SidecarRecord
// as built, its receipts the real RecordReceipts over its own store, and the author's ingester the real one; evs is
// sidecartest's FakeRecordStreams, T2's fake, which holds §11.12's receipt bounds as evs does. The schedule:
//
//	read      the reader's first read lands one receipt in its deposit ref before any object is decrypted, the
//	          author never having run
//	restart   evs commits the next read's receipt and its answer is lost, so nothing is decrypted; the reader's
//	          next life sends the same statement, and one receipt stands for the read
//	forge     the reader deposits an entry that is no read receipt, within its budget
//	budget    the reader reads up to its day's bound, then once more: the refusal schedule's read is past the bound,
//	          refused with nothing decrypted, as is a deposit past the receipt size, and its twin's is the day's last
//	          and passes. A push to the vault is refused in both: the reader writes no stream there
//	ingest    the author comes online: every deposit is consumed, each receipt is an entry of the author's stream,
//	          the forged entry is never ingested, and it alarms once
//
// After every step: every object the reader decrypted is named by a receipt evs held before the decrypt (I-4), and
// the author's stream holds nothing but read receipts.
//
// What this is not: a run over evsservice's engine through RECORD-M3-12's binding, which needs a record world of real
// engines this package does not have (the root's record_evs_test.go holds one for its own tests). The audit reader's
// case is M6's.
//
// record.proto's freeze evidence (§22.10's row for record.proto, §23.8's Gn-out): the list a gate reads, held to what
// this repository holds, so an item that went away fails here and is never read as passed.
//
//	vectors   testdata/record/vectors.json over the stored bytes of every M3 kind, verified on each leg by
//	          record_vectors_test.go and sealed again to the same bytes by record_vectors_fixture_test.go
//	fuzz      FuzzRecordHeader and FuzzRecordEntry, their seeds in testdata/fuzz/ running in every test run
//	FS rows   FS-25 to FS-29, MCP's, each a builder registered on T2 that its own test runs under every rule of §22.8

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs30 = Register("FS-30", "", []Tier{TierT2}, Twin(Fs30ReadPastTheBound, Fs30ReadWithinTheBound))

// See the file header.
func Fs30ReadPastTheBound(net *Net) *Schedule {
	schedule := fs30(true)
	schedule.Refuses = "an EvsShare reader's read past its day's receipt bound, and its deposit past the receipt size"
	return schedule
}

// See the file header.
func Fs30ReadWithinTheBound(net *Net) *Schedule {
	return fs30(false)
}

// The receipts a reader deposits a day in FS-30's world: small, so a schedule reaches the bound in a few reads.
const fs30ReceiptDayCount = 6

// One sidecar of FS-30's world: its identity key, its record directory, and what its record raised.
type fs30Device struct {
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	store     sidecar.SidecarStore
	streams   sidecar.RecordStreams

	stateLock sync.Mutex
	alarms    []sidecar.SidecarRecordAlarm
}

// Sidecar.Sign with the device's key.
func (self *fs30Device) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *fs30Device) alarmReasons() []sidecar.SidecarRecordAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.alarms)
}

// evs as the reader reaches it, which can lose the answer of the next deposit it commits, as a kill between evs's
// commit and the reader's read does.
type fs30LossyStreams struct {
	sidecar.RecordStreams

	stateLock sync.Mutex
	loseNext  bool
	deposits  []*sidecar.RecordStreamDeposit
}

var errFs30AnswerLost = errors.New("evs unreachable")

func (self *fs30LossyStreams) Deposit(ctx context.Context, repoId sidecar.Id, deposit *sidecar.RecordStreamDeposit) (*sidecar.RecordStreamCommit, error) {
	lose := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.deposits = append(self.deposits, deposit)
		lose := self.loseNext
		self.loseNext = false
		return lose
	}()
	commit, err := self.RecordStreams.Deposit(ctx, repoId, deposit)
	if err == nil && lose {
		return nil, errFs30AnswerLost
	}
	return commit, err
}

func (self *fs30LossyStreams) attempts() []*sidecar.RecordStreamDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// FS-30's world: one member's vault, its author's device, and another member's sidecar that reads it under an
// EvsShare.
type fs30World struct {
	clock   *sidecartest.FakeClock
	streams *sidecartest.FakeRecordStreams
	auth    *sidecartest.FakeRecordAuth
	fixture *sidecartest.FakeRecordAuthFixture
	vaultId sidecar.Id
	author  *fs30Device
	reader  *fs30Device
	lossy   *fs30LossyStreams

	stateLock sync.Mutex
	// each object the reader decrypted, hex
	decrypted []string
	// each object a receipt evs held names, hex, and the receipts by entry id
	receipted map[string]bool
	receipts  map[sidecar.Id]bool
	// reads that passed
	readCount int
}

// A device of the world with its own key and store.
func (self *fs30World) device(name string) (*fs30Device, error) {
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	store, err := sidecartest.NewFakeStore().Root().Directory(name, name)
	if err != nil {
		return nil, err
	}
	device := &fs30Device{sidecarId: sidecar.NewId(), key: key, store: store}
	device.streams = self.streams.For(device.sidecarId)
	self.fixture.IdentityKeys[device.sidecarId] = publicKey
	return device, nil
}

func (self *fs30World) publish() {
	self.fixture.TimeMillis = self.clock.Now().UnixMilli()
	self.auth.Append(self.fixture)
}

// One process's life of device's record, over what its store holds now.
func (self *fs30World) open(device *fs30Device) (*sidecar.SidecarRecord, error) {
	return sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		Store:             device.store,
		Sign:              device.sign,
		Runs:              sidecartest.NewFakeRunView(),
		Streams:           device.streams,
		Auth:              func() sidecar.RecordAuthView { return self.auth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm.Reason)
		},
		Clock:    self.clock,
		Settings: sidecar.DefaultSidecarSettings().Record,
	})
}

func newFs30World(ctx context.Context) (*fs30World, error) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeRecordStreamsSettings()
	settings.ReceiptDayCount = fs30ReceiptDayCount
	world := &fs30World{
		clock:     clock,
		streams:   sidecartest.NewFakeRecordStreams(clock, nil, settings),
		auth:      sidecartest.NewFakeRecordAuth(),
		receipted: map[string]bool{},
		receipts:  map[sidecar.Id]bool{},
	}
	vaultId, err := world.streams.NewRepo(ctx)
	if err != nil {
		return nil, err
	}
	world.vaultId = vaultId
	authorMemberId, readerMemberId := sidecar.NewId(), sidecar.NewId()
	world.fixture = &sidecartest.FakeRecordAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{},
		Members:      map[sidecar.Id]sidecar.Id{},
		Sponsors:     map[sidecar.Id]sidecar.Id{},
		Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{vaultId: {}},
		Vaults:       map[sidecar.Id]sidecar.Id{authorMemberId: vaultId},
	}
	if world.author, err = world.device("author"); err != nil {
		return nil, err
	}
	if world.reader, err = world.device("reader"); err != nil {
		return nil, err
	}
	repo := world.fixture.Repos[vaultId]
	// the author's device is consented and writes its own stream of its vault
	world.fixture.Members[world.author.sidecarId] = authorMemberId
	repo.Readers = append(repo.Readers, world.author.sidecarId)
	repo.Writers = append(repo.Writers, world.author.sidecarId)
	repo.Consented = append(repo.Consented, world.author.sidecarId)
	if err := world.streams.Grant(vaultId, world.author.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Deposit: true}); err != nil {
		return nil, err
	}
	// the reader is another member's: it reads the vault and deposits read receipts alone (§8.5, §11.12)
	world.fixture.Members[world.reader.sidecarId] = readerMemberId
	repo.Readers = append(repo.Readers, world.reader.sidecarId)
	repo.Depositors = append(repo.Depositors, world.reader.sidecarId)
	repo.ReceiptOnly = append(repo.ReceiptOnly, world.reader.sidecarId)
	if err := world.streams.Grant(vaultId, world.reader.sidecarId, sidecartest.RecordStreamsScope{Read: true, Deposit: true, ReceiptOnly: true}); err != nil {
		return nil, err
	}
	world.lossy = &fs30LossyStreams{RecordStreams: world.reader.streams}
	world.reader.streams = world.lossy
	world.publish()
	return world, nil
}

// A read of objectIds through the receipt gate in one life of the reader's record: the receipt first, and each
// object decrypted only once it returns.
func (self *fs30World) read(ctx context.Context, objectIds [][]byte) error {
	record, err := self.open(self.reader)
	if err != nil {
		return err
	}
	request := &sidecar.RecordReceiptRequest{RepoId: self.vaultId, Purpose: sidecar.RecordReadPurposeRead, ObjectIds: objectIds, NoSession: true}
	if err := record.Receipts().Deposit(ctx, request); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, objectId := range objectIds {
		self.decrypted = append(self.decrypted, hex.EncodeToString(objectId))
	}
	self.readCount += 1
	return nil
}

// count object ids no other read names.
func fs30ObjectIds(label string, count int) [][]byte {
	objectIds := [][]byte{}
	for index := range count {
		objectId := sidecar.NewId()
		objectIds = append(objectIds, append([]byte(fmt.Sprintf("%s-%d-", label, index)), objectId.Bytes()...)[:16])
	}
	return objectIds
}

// One entry waiting in the reader's deposit ref, opened as the author's ingester opens it.
type fs30Waiting struct {
	entryId sidecar.Id
	kind    sidecar.RecordKind
	read    *protocol.ReadBody
}

// The entries waiting in the reader's deposit ref, as the vault's owner reads them.
func (self *fs30World) waiting(ctx context.Context) ([]*fs30Waiting, error) {
	deposits, err := self.author.streams.ReadDeposits(ctx, self.vaultId, self.reader.sidecarId)
	if err != nil {
		return nil, err
	}
	waiting := []*fs30Waiting{}
	for _, deposit := range deposits {
		entries, err := sidecar.RecordDepositBatchParse(deposit.Batch, sidecar.DefaultSidecarSettings().Record.DepositByteCount)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(entry.Signed, signed); err != nil {
				return nil, err
			}
			header, err := sidecar.ParseStoredRecordHeader(signed.GetBody())
			if err != nil {
				return nil, err
			}
			item := &fs30Waiting{entryId: sidecar.Id(header.Header.GetEntryId()), kind: sidecar.RecordKind(header.Header.GetKind())}
			if item.kind == sidecar.RecordKindRead {
				opened, err := sidecar.RecordOpen(header, entry.SealedBody, entry.Key, entry.Salt)
				if err != nil {
					return nil, err
				}
				item.read = &protocol.ReadBody{}
				if err := proto.Unmarshal(opened, item.read); err != nil {
					return nil, err
				}
			}
			waiting = append(waiting, item)
		}
	}
	return waiting, nil
}

// The kinds of the entries the author's stream of the vault holds, in push order.
func (self *fs30World) authorKinds(ctx context.Context) ([]sidecar.RecordKind, error) {
	versions, err := self.author.streams.ReadStream(ctx, self.vaultId, self.author.sidecarId, 0)
	if err != nil {
		return nil, err
	}
	kinds := []sidecar.RecordKind{}
	for _, version := range versions {
		for _, streamEntry := range version.Entries {
			entry := &protocol.RecordEntry{}
			if err := proto.Unmarshal(streamEntry.Entry, entry); err != nil {
				return nil, err
			}
			header, err := sidecar.ParseStoredRecordHeader(entry.GetHeader().GetBody())
			if err != nil {
				return nil, err
			}
			kinds = append(kinds, sidecar.RecordKind(header.Header.GetKind()))
		}
	}
	return kinds, nil
}

// I-4 as this row holds it, after every step: each object the reader decrypted is named by a receipt evs held, and
// the author's stream holds read receipts alone.
func (self *fs30World) check(ctx context.Context) error {
	waiting, err := self.waiting(ctx)
	if err != nil {
		return err
	}
	kinds, err := self.authorKinds(ctx)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, item := range waiting {
		if item.read == nil {
			continue
		}
		self.receipts[item.entryId] = true
		for _, objectId := range item.read.GetObjectIds() {
			self.receipted[hex.EncodeToString(objectId)] = true
		}
	}
	for _, objectId := range self.decrypted {
		if !self.receipted[objectId] {
			return fmt.Errorf("object %s was decrypted with no receipt evs held", objectId)
		}
	}
	for _, kind := range kinds {
		if kind != sidecar.RecordKindRead {
			return fmt.Errorf("the author's stream holds a %s from the reader's deposits", kind)
		}
	}
	return nil
}

// The receipts evs has held so far, and the reads that passed.
func (self *fs30World) counts() (receiptCount int, readCount int, decryptCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.receipts), self.readCount, len(self.decrypted)
}

// The world a schedule's steps share, made by its first step.
type fs30State struct {
	world *fs30World
}

// The schedule: see the file header. past is the refusal schedule's.
func fs30(past bool) *Schedule {
	state := &fs30State{}
	step := func(actor string, action func(ctx context.Context, world *fs30World) error) *Step {
		return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
			if state.world == nil {
				return errors.New("FS-30's world was not set up")
			}
			return action(ctx, state.world)
		}}
	}
	// how many receipts stand, and how many reads passed and objects were decrypted, as a judge states them
	want := func(ctx context.Context, world *fs30World, receipts int, reads int, decrypts int) error {
		if err := world.check(ctx); err != nil {
			return err
		}
		if receiptCount, readCount, decryptCount := world.counts(); receiptCount != receipts || readCount != reads || decryptCount != decrypts {
			return fmt.Errorf("%d receipts, %d reads and %d decrypts, not %d, %d and %d", receiptCount, readCount, decryptCount, receipts, reads, decrypts)
		}
		return nil
	}
	restartObjects := fs30ObjectIds("restart", 2)
	// the reads that fill the day: with the first, the restart's and the forged deposit, one short of the bound in
	// the twin and at it in the refusal schedule
	fill := fs30ReceiptDayCount - 4
	if past {
		fill = fs30ReceiptDayCount - 3
	}
	steps := []*Step{
		{Actor: "authority", Action: func(ctx context.Context, net *Net) error {
			world, err := newFs30World(ctx)
			if err != nil {
				return err
			}
			state.world = world
			return nil
		}},
		step("reader", func(ctx context.Context, world *fs30World) error {
			return world.read(ctx, fs30ObjectIds("first", 1))
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			// the author has never run, and the receipt is in evs
			return want(ctx, world, 1, 1, 1)
		}),
		step("reader", func(ctx context.Context, world *fs30World) error {
			world.lossy.stateLock.Lock()
			world.lossy.loseNext = true
			world.lossy.stateLock.Unlock()
			if err := world.read(ctx, restartObjects); !errors.Is(err, sidecar.ErrRecordReceiptRefused) {
				return fmt.Errorf("a read whose receipt's answer was lost: %v", err)
			}
			return nil
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			// evs holds the receipt, and nothing was decrypted under it
			return want(ctx, world, 2, 1, 1)
		}),
		step("reader", func(ctx context.Context, world *fs30World) error {
			// the next life reads again: the same statement, which evs answers with its commit
			if err := world.read(ctx, restartObjects); err != nil {
				return err
			}
			attempts := world.lossy.attempts()
			count := len(attempts)
			if count < 3 || attempts[count-2].PushId != attempts[count-1].PushId || attempts[count-2].DepositId != attempts[count-1].DepositId {
				return fmt.Errorf("%d deposit attempts, the last two not one statement", count)
			}
			return nil
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			return want(ctx, world, 2, 2, 3)
		}),
		step("reader", func(ctx context.Context, world *fs30World) error {
			// an entry that is no receipt, sealed by hand with the reader's key and deposited within its budget
			store, err := sidecartest.NewFakeStore().Root().Directory("hand", "hand")
			if err != nil {
				return err
			}
			env := &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, world.reader.sidecarId), Sign: world.reader.sign}
			sealed, err := sidecar.RecordSeal(env, &sidecar.RecordSealArgs{
				LogId:         world.vaultId,
				Kind:          sidecar.RecordKindNote,
				Source:        sidecar.RecordSourceAgent,
				TimeMillis:    world.clock.Now().UnixMilli(),
				Tainted:       true,
				PolicyVersion: world.auth.Tip().Pin().GetVersion(),
				Body:          &protocol.CoordinationBody{Text: "an instruction dressed as a receipt"},
			})
			if err != nil {
				return err
			}
			batch, err := proto.Marshal(&protocol.RecordDepositBatch{Entries: []*protocol.RecordDeposit{sealed.Deposit()}})
			if err != nil {
				return err
			}
			_, err = world.streams.For(world.reader.sidecarId).Deposit(ctx, world.vaultId, &sidecar.RecordStreamDeposit{
				PushId:             sidecar.NewId(),
				DepositorSidecarId: world.reader.sidecarId,
				DepositId:          sidecar.NewId(),
				Batch:              batch,
				AuthPin:            world.auth.Tip().Pin(),
			})
			return err
		}),
		step("reader", func(ctx context.Context, world *fs30World) error {
			for index := range fill {
				if err := world.read(ctx, fs30ObjectIds(fmt.Sprintf("fill%d", index), 1)); err != nil {
					return err
				}
			}
			return nil
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			return want(ctx, world, 2+fill, 2+fill, 3+fill)
		}),
		step("reader", func(ctx context.Context, world *fs30World) error {
			err := world.read(ctx, fs30ObjectIds("last", 1))
			streams := world.streams.For(world.reader.sidecarId)
			// the reader writes no stream of the vault, in budget or out
			_, pushErr := streams.Append(ctx, world.vaultId, &sidecar.RecordStreamPush{
				PushId:          sidecar.NewId(),
				WriterSidecarId: world.reader.sidecarId,
				SlotId:          sidecar.NewId(),
				SlotRows:        []*sidecar.RecordSlotRow{{KeyIndex: 0, Row: make([]byte, 64)}},
				Entries:         []*sidecar.RecordStreamEntry{{Path: "e/0/0/1", Entry: []byte("an entry")}},
				AuthPin:         world.auth.Tip().Pin(),
			})
			if code, ok := sidecar.RecordStreamRefusalCode(pushErr); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
				return fmt.Errorf("the reader's push to the vault: %v", pushErr)
			}
			if !past {
				return err
			}
			if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED {
				return fmt.Errorf("a read past the day's receipt bound: %v", err)
			}
			_, largeErr := streams.Deposit(ctx, world.vaultId, &sidecar.RecordStreamDeposit{
				PushId:             sidecar.NewId(),
				DepositorSidecarId: world.reader.sidecarId,
				DepositId:          sidecar.NewId(),
				Batch:              make([]byte, sidecartest.DefaultFakeRecordStreamsSettings().ReceiptByteCount+1),
				AuthPin:            world.auth.Tip().Pin(),
			})
			if code, ok := sidecar.RecordStreamRefusalCode(largeErr); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED {
				return fmt.Errorf("a deposit past the receipt size: %v", largeErr)
			}
			return nil
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			if past {
				// refused: no receipt, no read, nothing decrypted
				return want(ctx, world, 2+fill, 2+fill, 3+fill)
			}
			return want(ctx, world, 3+fill, 3+fill, 4+fill)
		}),
		step("author", func(ctx context.Context, world *fs30World) error {
			// the author comes online: ingest, push, and the consume of what the push held
			record, err := world.open(world.author)
			if err != nil {
				return err
			}
			if err := record.Ingester().Ingest(ctx, world.vaultId); err != nil {
				return err
			}
			if err := record.Flush(ctx); err != nil {
				return err
			}
			return record.Ingester().Ingest(ctx, world.vaultId)
		}),
		step("judge", func(ctx context.Context, world *fs30World) error {
			if err := world.check(ctx); err != nil {
				return err
			}
			waiting, err := world.waiting(ctx)
			if err != nil {
				return err
			}
			if len(waiting) != 0 {
				return fmt.Errorf("%d deposits left after the author's ingest", len(waiting))
			}
			kinds, err := world.authorKinds(ctx)
			if err != nil {
				return err
			}
			receiptCount, _, _ := world.counts()
			if len(kinds) != receiptCount {
				return fmt.Errorf("the author's stream holds %d entries for %d receipts", len(kinds), receiptCount)
			}
			if reasons := world.author.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmDepositorKind}) {
				return fmt.Errorf("the reader's forged entry raised %v", reasons)
			}
			return nil
		}),
	}
	return &Schedule{
		Steps: steps,
		Check: []Invariant{NewInvariant("I-4/receipt", func(ctx context.Context, oracle *Oracle) error {
			if state.world == nil {
				return nil
			}
			return state.world.check(ctx)
		})},
		Tiers: []Tier{TierT2},
	}
}

func TestFs30(t *testing.T) {
	RunRow(t, "FS-30", "", nil)
}

// The FS rows §22.10 lists as record.proto's Gn-out evidence.
var recordFreezeRows = []string{"FS-25", "FS-26", "FS-27", "FS-28", "FS-29"}

// Those of them whose builders hold barriers, linked on the sidecar_testhooks leg alone.
var recordFreezeHookRows = []string{"FS-26"}

// The seed shapes RECORD-M3-11 names, a file of each in both targets' corpora.
var recordFreezeSeeds = []string{"seed-valid", "seed-reordered", "seed-repeated", "seed-unknown", "seed-packed", "seed-unpacked", "seed-non-minimal"}

// Every item of record.proto's Gn-out evidence is in this repository: the vectors hold every part RECORD-M3-11 names,
// both fuzz targets hold every seed shape, and each of FS-25 to FS-29 has a T2 builder on the leg that links it. What ran is each item's own
// test's to say; this fails when an item is gone.
func TestRecordFreezeEvidenceIsHeld(t *testing.T) {
	root := filepath.Join("..", "..")
	content, err := os.ReadFile(filepath.Join(root, "testdata", "record", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]json.RawMessage{}
	if err := json.Unmarshal(content, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"entries", "deposit_batch", "decision", "actions"} {
		if raw, ok := vectors[part]; !ok || len(raw) <= len("null") {
			t.Errorf("the vectors hold no %s", part)
		}
	}
	for _, target := range []string{"FuzzRecordHeader", "FuzzRecordEntry"} {
		entries, err := os.ReadDir(filepath.Join(root, "testdata", "fuzz", target))
		if err != nil {
			t.Errorf("%s has no corpus: %v", target, err)
			continue
		}
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		for _, seed := range recordFreezeSeeds {
			if !slices.Contains(names, seed) {
				t.Errorf("%s has no %s", target, seed)
			}
		}
	}
	for _, rowId := range recordFreezeRows {
		registration := Lookup(rowId, "", TierT2)
		if registration == nil && slices.Contains(recordFreezeHookRows, rowId) && !sidecartest.HooksLinked {
			t.Logf("record.proto Gn-out: %s holds barriers, so its builder links on the sidecar_testhooks leg alone", rowId)
			continue
		}
		if registration == nil {
			t.Errorf("%s has no T2 builder registered: missing", rowId)
			continue
		}
		t.Logf("record.proto Gn-out: %s", registration)
	}
}
