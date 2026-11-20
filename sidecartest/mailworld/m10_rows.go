//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M10's mailbox cases of §22.8's search rows (MAIL-M10-04; FS-76, FS-78, FS-111, FS-112, FI-18, FI-19; §15.7's search
// index and erasure rows): SEARCH's schedules run on a real mailbox, each one flow over an M10World that sidecartest's
// test runs on T2 and server's sidecart3 on T3's stores. They add no mechanism: a row composes what MAIL-M10-01 to
// MAIL-M10-03 and SEARCH's index landed, and a failure here goes back to the task that owns the part that failed.
//
// The world is MailWorld's receive path with the format2 gate open for its network (§19.11): mail goes through the
// router and the receiver's session into evsservice's engine as a deposit, and a consented device's MailIngestor
// writes m/, i/ and the message's index delta in one push, the in-ref index writer on its client as a composition
// will install one (SearchTestIndexWriter: no host installs it yet, MAIL-M10-01's note). Erasures are MailEraser's
// under the mailbox's admin, whose CUT, CLOSUREs and ERASEs go through EvsRepo to the engine. The index is read back
// through EvsRepo as every index builder reads it, and held to SearchOracle, which shares no index code: its ledger is
// told each message as ingest stored it, read back from m/, under the mailbox's own key and ref.
//
//	RunM10Fs76Mailbox   FS-76's corpus mail (SearchCorpus's MIME forms and edge classes, and four messages only the
//	                    canonical reading finds a word of), delivered over the corpus's 200 days and ingested by two
//	                    devices in turn; at every bucket boundary 1 s before and after, after every roll-up, after
//	                    the erasure and at the end the mailbox's index holds live exactly the oracle's documents; and
//	                    the query set runs on a desktop and a phone against the oracle over the same messages'
//	                    stored bytes on a search world (the file's second half), since no device searches an index
//	                    over EvsRepo yet
//	RunM10Fs78Mailbox   an admin's erasure of one email among three: its CUT first, the ref's index_epoch at the
//	                    CUT's version, the email's own keys gone with the first ERASE so its body opens for no
//	                    device, a fresh one included, then the CLOSUREs of the index file and the i/ segment holding
//	                    it, after which no index file holds its postings and the others' stand
//	RunM10Fs111Mailbox  writer A's ingest, planned with document D in its head, paused before its head CAS; eraser
//	                    B's CUT, first ERASE and CLOSUREs commit; the paused push gets 409 INDEX_EPOCH and the ingest
//	                    plans again, committing the new message without D; a fresh device opens none of D's copies
//	RunM10Fs112Mailbox  one message with 5 MiB of text, five chunk documents: the index holds the oracle's five, the
//	                    erasure's CUT lists them all, its body no longer opens, and the CLOSUREs leave no chunk live
//
// What a real mailbox does not carry yet, each named for the task it goes back to. None of it is asserted here, and
// none of these rows shows an erasure complete:
//
//   - an index file first created above the ref's version 1 cannot be rewritten in a slot-keyed repo: EvsRepo's
//     SlotKeysOf refuses a history that does not end at version 1 (ErrEvsSlotKeysIncomplete), and under §11.7 every
//     path created after the ref's first push starts above it. Such an erasure stops after its CUT and first ERASE
//     with the postings still under a standing key. Every erasure here is therefore of a message the mailbox's first
//     push ingested, whose index files and i/ segment begin at version 1, before any roll-up moved it (question
//     mail-m10-04-closure-of-a-file-born-past-version-1; EVS2-M10-12's SlotKeysOf, SEARCH-M10-17's eraser);
//   - an erasure fails outright, after its CUT and first ERASE, where an index file it does not rewrite stands at a
//     second version: the eraser's history walk reads each retained version through the EvsRepo store, whose Retained
//     names it without its content hash, and whose Read then refuses it as ErrEvsSealInvalid, a plaintext hash
//     mismatch. So in every row the only index file past its first version when the erasure runs is the one the
//     erased message's own writer rewrote (question mail-m10-04-index-eraser-history-reads, part a; SEARCH-M10-17's
//     seam);
//   - no erasure says complete: the EvsRepo store answers its retained history incomplete, as SEARCH-M10-17 left
//     it, so each stays rewriting and unproven. And once a mailbox holds a second erasure a resume of the first
//     fails, the walk reading a version whose key the second's ERASE destroyed, which EvsRepo answers as
//     ErrEvsSealInvalid and the walk takes as a failure, not as collected (the same question, part b). So no row
//     resumes, and FS-111's killed eraser, its restart and the member's other device after 25 h do not run;
//   - the exact storage limit, the closure allowance's floor, the 429s and the finish estimate (FS-78's and FS-112's
//     wait): ?closure=1 uploads at the limit are not built on the client (EVS2-M10-12), so those clauses stay
//     MAIL-M10-02's and SEARCH-M10-37's, on their fakes;
//   - a search over the mailbox's own index: no EvsRepo adapter of the sync engine's source exists (SEARCH-M10-19)
//     and no host installs an engine (MAIL-M10-03's note), so FS-76's query set runs on a search world;
//   - the purge of the old ciphertext (EVSB-M10-01's PurgeSink.Certain is unwired), FI-19's stored-version sweep,
//     the hold cases (M5-out) and a group inbox.
//
// Every name and address is synthetic: .example names and RFC 5737 addresses (connect/CODESTYLE.md's test data rule).
// Nothing sleeps: a step waits on a pipe, a barrier it armed or the session's reply.

package mailworld

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The envelope sender of M10's corpus mail, and the index file an erasure's CUT writes its set to (§11.12's cut row).
const (
	M10CorpusSender   = "corpus@corpus.example"
	m10ErasureSetPath = ".ur-index/x"
)

// What a M10World is built with.
type M10WorldSettings struct {
	// The network's label under the world's root; empty takes MailWorld's. A T3 run gives one of its own, so its
	// {mxr_<label>} meets no other run's on the private Redis.
	Label string
	// The fake host the world's engines read their gates, quota and tokens from; nil takes the Net's.
	Host *sidecartest.FakeHost
	// MailWorldSettings.Stores: nil keeps the fake host's, T2's.
	Stores func(service string) *sidecar.ServiceHost
	// The format2 gate's purge and drop modes as sidecar.yml spells them; empty takes observe, as §23.9 opens it.
	Purge string
	Drop  string
	// Told after each move of the world's clock, before the world's next step; nil for none. T3 has its stores'
	// checks read again here, since the first requests after a move are a deposit's uploads, sent side by side.
	Advanced func()
}

// One push evs refused a device of the world: the answer's status and the refusal's code.
type M10Refusal struct {
	Status int
	Code   protocol.EvsRefusalCode
}

// One consented device of the mailbox's member: its evs client at format 2 with the in-ref index writer on it.
type M10Device struct {
	Name   string
	Signer *sidecartest.FakeGkmSigner
	Evs    *sidecar.EvsClient
	Repo   *sidecar.EvsRepo

	// where the device's eraser journals an erasure between its CUT and its first ERASE
	journal sidecar.SidecarStore

	stateLock sync.Mutex
	// each plan the in-ref writer saw: whether it carried an index write
	plans []bool
	// each standing its eraser raised
	events []*sidecar.SidecarErasure
}

// How many content plans the device's index writer has seen, a plan made again counted again.
func (self *M10Device) PlanCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.plans)
}

// The standings the device's erasers raised, in order.
func (self *M10Device) ErasureEvents() []*sidecar.SidecarErasure {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// One message as an ingest stored it.
type M10Message struct {
	Id    sidecar.Id
	Month sidecar.MailYearMonth
	// Its m/ path, the bytes and version it stands at there, and the ref version and signed time of its push.
	Path       string
	Content    []byte
	Version    uint64
	RefVersion uint64
	Time       time.Time
	Entry      *protocol.IndexEntry
	// The device that ingested it.
	WriterId sidecar.Id
}

// One mailbox at format 2 with its index on (the file header's world). Its exported fields are set once.
type M10World struct {
	t        testing.TB
	ctx      context.Context
	settings *M10WorldSettings

	Net  *sidecartest.Net
	Mail *MailWorld
	// The mailbox's one address.
	Address string
	// The owner's laptop, the mailbox's admin: the eraser.
	Owner *M10Device
	// A second consented device of the member, which reads and writes and administers nothing.
	Reader *M10Device
	// What SearchOracle judges the mailbox's index by.
	Ledger *sidecartest.SearchLedger
	Oracle *sidecartest.SearchOracle

	stateLock sync.Mutex
	refusals  []M10Refusal
	// the mailbox's main ref, known once its first push committed
	refId sidecar.Id
}

// The world on net, settings nil taking T2's.
func NewM10World(t testing.TB, net *sidecartest.Net, settings *M10WorldSettings) *M10World {
	t.Helper()
	if settings == nil {
		settings = &M10WorldSettings{}
	}
	host := settings.Host
	if host == nil {
		host = net.Fakes()
	}
	purge, drop := settings.Purge, settings.Drop
	if purge == "" {
		purge = "observe"
	}
	if drop == "" {
		drop = "observe"
	}
	self := &M10World{t: t, settings: settings, Net: net, Ledger: sidecartest.NewSearchLedger()}
	self.Oracle = sidecartest.NewSearchOracle(self.Ledger)
	mailSettings := DefaultMailWorldSettings()
	if settings.Label != "" {
		mailSettings.Label = settings.Label
	}
	self.Address = "ann@" + mailSettings.Label + "." + mailSettings.Root
	mailSettings.Addresses = []string{self.Address}
	mailSettings.NetworkId = sidecar.NewId()
	mailSettings.Stores = settings.Stores
	mailSettings.EvsAnswered = self.answered
	// the format2 gate lists the network before any engine reads it; MailWorld then opens evs and mxedge beside it
	gates := fmt.Sprintf("sidecar:\n  format2: {enabled: true, networks: [%q], percent: 0, purge: %q, drop: %q}\n", connect.Id(mailSettings.NetworkId).String(), purge, drop)
	if err := host.Gates.Set(gates); err != nil {
		t.Fatal(err)
	}
	self.Mail = NewMailWorld(t, host, net.Clock(), mailSettings)
	self.ctx = self.Mail.ctx
	self.Owner = self.device("owner", self.Mail.Owner)
	self.Reader = self.FreshDevice("reader")
	return self
}

// What the world's clients run under, which ends with the test.
func (self *M10World) Context() context.Context {
	return self.ctx
}

// Moves the world's clock by wait, stopping at each UTC date change on the way until the router's probe there has
// ended and its loop waits at the next: the fake clock fires a passed timer at its own time and moves on, so one
// move across a date change would pass the probe's store timeout while it reads and leave the router not ready for
// the next session (MailWorldSettings.ProbeInterval's note).
func (self *M10World) Advance(wait time.Duration) {
	self.t.Helper()
	clock := self.Net.Clock()
	target := clock.Now().Add(wait)
	for {
		dayChange := clock.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		if target.Before(dayChange) {
			break
		}
		nextDayChange := dayChange.Add(24 * time.Hour)
		waitsBefore := self.Mail.timerCountAt(nextDayChange)
		clock.AdvanceTo(dayChange)
		self.Mail.AwaitTimerCountAt(nextDayChange, waitsBefore+1)
	}
	clock.AdvanceTo(target)
	if self.settings.Advanced != nil {
		self.settings.Advanced()
	}
}

// Whether signer administers the mailbox: its owner's laptop alone, as its RepoAdmin row says.
func (self *M10World) IsAdmin(signer sidecar.Id) bool {
	return signer == self.Mail.Owner.SidecarId
}

// A device of signer: its client writes format 2 while the gate admits the network, and carries the in-ref index
// writer, which notes each plan it sees.
func (self *M10World) device(name string, signer *sidecartest.FakeGkmSigner) *M10Device {
	self.t.Helper()
	client := self.Mail.Device(signer, false, sidecartest.NewFakeStore().Root(), nil)
	networkId := connect.Id(self.Mail.NetworkId)
	gates := self.Mail.Host.Gates
	client.SetFormat2Source(func() bool { return gates.Format2().Admits(networkId) })
	client.EnableFormat2Reader()
	device := &M10Device{Name: name, Signer: signer, Evs: client, Repo: client.Repo(self.Mail.RepoId), journal: sidecartest.NewFakeStore().Root()}
	remove, err := sidecar.InstallSearchTestIndexWriterCounting(client, &sidecar.SearchTestIndexWriterArgs{IsAdmin: self.IsAdmin}, func(indexed bool) {
		device.stateLock.Lock()
		defer device.stateLock.Unlock()
		device.plans = append(device.plans, indexed)
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(remove)
	return device
}

// A consented device admitted now, as a member's new device is: it holds nothing of the mailbox before.
func (self *M10World) FreshDevice(name string) *M10Device {
	self.t.Helper()
	return self.device(name, self.Mail.AdmitReader())
}

// MailWorldSettings.EvsAnswered: keeps each push evs refused.
func (self *M10World) answered(request *http.Request, status int, body []byte) {
	if status == http.StatusOK || !strings.HasSuffix(request.URL.Path, "/push") {
		return
	}
	reply := &protocol.EvsRefusalReply{}
	refusal := M10Refusal{Status: status}
	if err := proto.Unmarshal(body, reply); err == nil {
		refusal.Code = reply.GetCode()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, refusal)
}

// Every push evs refused a device of the world so far, in order.
func (self *M10World) Refusals() []M10Refusal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.refusals)
}

// One message from sender through the router and the receiver's session to the mailbox: 250 once its deposit is
// durable, or the test fails.
func (self *M10World) Deliver(from string, message []byte) {
	self.t.Helper()
	if reply := self.Mail.Send(M8Sender, self.Mail.Settings().MxHost(), from, []string{self.Address}, message); !reply.Is(250) {
		self.t.Fatalf("mail to %s: %s", self.Address, reply)
	}
}

// Every standing deposit ingested on device, each message its pass wrote read back from m/ as it stands and told to
// the oracle's ledger as one indexed commit of its writer.
func (self *M10World) Ingest(device *M10Device) []*M10Message {
	self.t.Helper()
	messages, err := self.ingest(device)
	if err != nil {
		self.t.Fatal(err)
	}
	return messages
}

// See Ingest: the error rather than the test's failure, for a step run beside the test's goroutine.
func (self *M10World) ingest(device *M10Device) ([]*M10Message, error) {
	ingested := []*sidecar.MailMessage{}
	alarms := []*sidecar.MailIngestAlarm{}
	ingestor := self.Mail.Ingestor(device.Evs, device.Signer.SidecarId, func(message *sidecar.MailMessage) {
		ingested = append(ingested, message)
	}, func(alarm *sidecar.MailIngestAlarm) {
		alarms = append(alarms, alarm)
	})
	pass, err := ingestor.Ingest(self.ctx)
	if err != nil {
		return nil, fmt.Errorf("the %s's ingest: %w", device.Name, err)
	}
	if pass.Ingested != len(ingested) || pass.Consumed != len(ingested) || 0 < len(alarms) {
		return nil, fmt.Errorf("the %s's ingest: %+v, %d messages, %d alarms", device.Name, pass, len(ingested), len(alarms))
	}
	messages := []*M10Message{}
	for _, message := range ingested {
		stored := &M10Message{Id: message.Id, Month: message.Month, Path: sidecar.MailMessagePath(message.Month, message.Id), Entry: message.Entry, WriterId: device.Signer.SidecarId}
		content := &bytes.Buffer{}
		info, err := device.Repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: stored.Path}, content)
		if err != nil {
			return nil, fmt.Errorf("the %s reading %s back: %w", device.Name, stored.Path, err)
		}
		stored.Content, stored.Version, stored.RefVersion, stored.Time = content.Bytes(), info.Version, info.CommitVersion, info.Time
		messages = append(messages, stored)
	}
	return messages, self.record(device, messages)
}

// Tells the ledger messages, each push one commit, in the order they committed.
func (self *M10World) record(device *M10Device, messages []*M10Message) error {
	if len(messages) == 0 {
		return nil
	}
	if err := self.followRef(device); err != nil {
		return err
	}
	ordered := slices.Clone(messages)
	slices.SortStableFunc(ordered, func(a *M10Message, b *M10Message) int {
		return int(a.RefVersion) - int(b.RefVersion)
	})
	for i := 0; i < len(ordered); {
		commit := &sidecartest.SearchCommit{
			RepoId: self.Mail.RepoId, RefId: self.refId, RefVersion: ordered[i].RefVersion, Time: ordered[i].Time,
			WriterId: device.Signer.SidecarId, Indexed: true,
		}
		for ; i < len(ordered) && ordered[i].RefVersion == commit.RefVersion; i += 1 {
			commit.Changes = append(commit.Changes, &sidecartest.SearchChange{Path: ordered[i].Path, Version: ordered[i].Version, Content: ordered[i].Content})
		}
		if err := self.Ledger.Commit(commit); err != nil {
			return err
		}
	}
	return nil
}

// The mailbox's main ref in the ledger, under the mailbox's own key as gkm answers it to the owner's laptop, read by
// every consented device: added once, at the ref's first push.
func (self *M10World) followRef(device *M10Device) error {
	if self.refId != (sidecar.Id{}) {
		return nil
	}
	refId, err := device.Repo.RefIdOf(self.ctx, nil)
	if err != nil {
		return err
	}
	gkm := self.Mail.Gkm.Client(self.Mail.Owner.SidecarId, self.Mail.Owner.Sign)
	gkm.AuthAdvanced(self.Mail.view())
	key, err := gkm.CurrentRepoKey(self.ctx, self.Mail.RepoId)
	if err != nil {
		return err
	}
	self.refId = refId
	return self.Ledger.AddRepo(&sidecartest.SearchLedgerRepo{
		RepoId: self.Mail.RepoId, NetworkId: self.Mail.NetworkId, Kind: protocol.RepoKind_REPO_KIND_MAILBOX,
		DefaultRefId: refId, Key: key, ReaderIds: self.Mail.ReaderIds(),
	})
}

// One message delivered and ingested on device: the one message its pass wrote.
func (self *M10World) DeliverAndIngest(device *M10Device, from string, message []byte) *M10Message {
	self.t.Helper()
	self.Deliver(from, message)
	messages := self.Ingest(device)
	if len(messages) != 1 {
		self.t.Fatalf("the %s's ingest of one message wrote %d", device.Name, len(messages))
	}
	return messages[0]
}

// The oracle's scope over the mailbox as the owner's laptop reads it, every partition.
func (self *M10World) scope() *sidecartest.SearchScope {
	return &sidecartest.SearchScope{
		Partitions: sidecartest.SearchScopeAll, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.Mail.NetworkId}, ReaderId: self.Mail.Owner.SidecarId,
	}
}

// The mailbox's index at its head as device reads it through EvsRepo.
func (self *M10World) Index(device *M10Device) (*sidecar.SearchTestEvsIndex, error) {
	return sidecar.ReadSearchTestEvsIndex(self.ctx, device.Repo, nil, self.IsAdmin)
}

// Holds the mailbox's index, as device reads it, to the oracle (FI-18's covered clause and FI-19's current-file
// clause at the grain a real mailbox gives): the documents its files hold live are the oracle's, each under the
// doc_key the oracle derives from the mailbox's key and at the version it stands at, none more and none fewer, so
// every chunk of every standing message is indexed and nothing an erasure's rewrite removed is.
func (self *M10World) HoldIndex(device *M10Device, label string) error {
	index, err := self.Index(device)
	if err != nil {
		return fmt.Errorf("%s: the %s's read of the index: %w", label, device.Name, err)
	}
	documents, err := self.Oracle.Documents(self.scope())
	if err != nil {
		return fmt.Errorf("%s: the oracle: %w", label, err)
	}
	want := map[[16]byte]uint64{}
	for _, document := range documents {
		want[document.DocKey] = document.Version
		if version, ok := index.Live[document.DocKey]; !ok || version != document.Version {
			return fmt.Errorf("%s: the index holds %s at %d (live %t), the oracle at %d", label, document, version, ok, document.Version)
		}
	}
	for key, version := range index.Live {
		if _, ok := want[key]; !ok {
			return fmt.Errorf("%s: the index holds %x live at %d, which is no document of the oracle's %d", label, key[:4], version, len(documents))
		}
	}
	return nil
}

// An eraser of the mailbox on device, as a device starting builds one: it holds none of an earlier eraser's memory
// but the device's journal.
func (self *M10World) Eraser(device *M10Device) *sidecar.MailEraser {
	self.t.Helper()
	eraser, err := sidecar.NewMailEraser(&sidecar.MailEraserArgs{
		Repo:      device.Repo,
		SidecarId: device.Signer.SidecarId,
		Authority: &mailWorldEraseAuthority{world: self.Mail},
		Progress: func(erasure *sidecar.SidecarErasure) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.events = append(device.events, erasure)
		},
		Journal: device.journal,
		Clock:   self.Mail.Clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return eraser
}

// Whether message's body opens for device: its m/ file read at the head.
func (self *M10World) BodyOpens(device *M10Device, message *M10Message) bool {
	_, err := device.Repo.ReadHead(self.ctx, &sidecar.EvsReadArgs{Path: message.Path, Fresh: true}, io.Discard)
	return err == nil
}

// What one erasure of the owner's left on evs, as M10's rows hold it.
type m10Erased struct {
	erasure *sidecar.MailErasure
	// the CUT's ref version
	cutVersion uint64
}

// The owner's erasure of message, held to §15.7's order as far as a real mailbox carries it (the file header): the
// CUT commits first, moving the ref's index_epoch to its version and raising fenced before any other standing; the
// first ERASE destroys the message's own keys, so its body opens for no device; CLOSUREs of the erasure commit; and no
// index file holds a posting of the message live afterwards. The ledger forgets the message from its CUT.
func (self *M10World) eraseHeld(label string, message *M10Message) (*m10Erased, error) {
	owner := self.Owner
	before, err := self.Index(owner)
	if err != nil {
		return nil, err
	}
	if _, cut := before.Files[m10ErasureSetPath]; cut {
		return nil, fmt.Errorf("%s: the mailbox holds an erasure set before its first erasure", label)
	}
	eventsBefore := len(owner.ErasureEvents())
	erasure, err := self.Eraser(owner).Erase(self.ctx, message.Month, []sidecar.Id{message.Id})
	if err != nil {
		return nil, fmt.Errorf("%s: the erasure: %w", label, err)
	}
	if err := self.Ledger.Erase(self.Mail.RepoId, self.refId, message.Path, message.Version); err != nil {
		return nil, err
	}
	if !erasure.Fenced || !slices.Contains(erasure.MessageIds, message.Id) {
		return nil, fmt.Errorf("%s: the erasure is not fenced: %+v", label, erasure)
	}
	events := owner.ErasureEvents()[eventsBefore:]
	if len(events) == 0 || events[0].State != sidecar.SidecarErasureFenced || events[0].ErasureId != erasure.ErasureId {
		return nil, fmt.Errorf("%s: the erasure's first standing is not fenced: %+v", label, events)
	}
	after, err := self.Index(owner)
	if err != nil {
		return nil, err
	}
	cutVersion := after.Files[m10ErasureSetPath]
	epoch, err := sidecar.SearchTestEvsIndexEpoch(self.ctx, owner.Repo, nil)
	if err != nil {
		return nil, err
	}
	if cutVersion <= before.Version || epoch != cutVersion {
		return nil, fmt.Errorf("%s: the CUT's set stands at %d over a head at %d, the ref's index_epoch at %d", label, cutVersion, before.Version, epoch)
	}
	// the first ERASE names the message's path in its note and destroys its keys
	erasures, err := owner.Repo.ReadErasures(self.ctx, 0)
	if err != nil {
		return nil, err
	}
	first := slices.IndexFunc(erasures, func(erased *sidecar.EvsErasure) bool { return erased.ErasureId == erasure.ErasureId })
	if first < 0 || len(erasures[first].Keys) == 0 || !bytes.Contains(erasures[first].Note, []byte(message.Path)) ||
		erasures[first].EraserSidecarId != owner.Signer.SidecarId {
		return nil, fmt.Errorf("%s: the erasure's first ERASE does not name %s: %+v", label, message.Path, erasures)
	}
	for _, device := range []*M10Device{owner, self.Reader} {
		if self.BodyOpens(device, message) {
			return nil, fmt.Errorf("%s: the erased message's body still opens for the %s", label, device.Name)
		}
	}
	closures, err := sidecar.SearchTestEvsClosureCount(self.ctx, owner.Repo, nil, erasure.ErasureId)
	if err != nil {
		return nil, err
	}
	if closures == 0 {
		return nil, fmt.Errorf("%s: evs holds no CLOSURE of the erasure", label)
	}
	held, err := sidecar.SearchTestEvsFilesHolding(self.ctx, owner.Repo, nil, message.Path)
	if err != nil {
		return nil, err
	}
	for _, file := range held {
		if file.Live {
			return nil, fmt.Errorf("%s: %s still holds the erased message live at %d", label, file.Path, file.Version)
		}
	}
	return &m10Erased{erasure: erasure, cutVersion: cutVersion}, nil
}

// Holds a device admitted after an erasure to FS-111's last clause as a real mailbox carries it: it opens none of
// the erased message's copies, neither its body nor a posting in any index file, and reads the index the oracle
// describes.
func (self *M10World) holdFresh(label string, erased *M10Message, standing ...*M10Message) error {
	fresh := self.FreshDevice("fresh device")
	if self.BodyOpens(fresh, erased) {
		return fmt.Errorf("%s: the erased message's body opens for a fresh device", label)
	}
	held, err := sidecar.SearchTestEvsFilesHolding(self.ctx, fresh.Repo, nil, erased.Path)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return file.Live }) {
		return fmt.Errorf("%s: a fresh device finds the erased message live in %+v", label, held)
	}
	for _, message := range standing {
		if !self.BodyOpens(fresh, message) {
			return fmt.Errorf("%s: %s, which no erasure named, does not open for a fresh device", label, message.Path)
		}
	}
	return self.HoldIndex(fresh, label+", a fresh device")
}

// FS-78's mailbox case (the file header's row): three emails in an indexed mailbox, the first ingested by the
// owner's laptop in the mailbox's first push, the others by the member's second device and the laptop; the admin
// erases the first.
func RunM10Fs78Mailbox(t testing.TB, world *M10World) {
	t.Helper()
	sender := "signup@" + M8SenderDomain
	erased := world.DeliverAndIngest(world.Owner, sender, M8Message(world.Address, "cormorant ledger", "The cormorant ledger closes at noon."))
	// one more by each device, so no index file but the erased email's own stands at a second version (the file
	// header's gaps)
	standing := []*M10Message{
		world.DeliverAndIngest(world.Reader, sender, M8Message(world.Address, "lighthouse rota", "The lighthouse rota for the spring tides.")),
		world.DeliverAndIngest(world.Owner, sender, M8Message(world.Address, "harbor notice", "The harbor notice lists the dredging days.")),
	}
	if err := world.HoldIndex(world.Owner, "before the erasure"); err != nil {
		t.Fatal(err)
	}
	if _, err := world.eraseHeld("FS-78's erasure", erased); err != nil {
		t.Fatal(err)
	}
	// masked and rewritten: the index the owner and the other device read holds the two standing emails alone
	for _, device := range []*M10Device{world.Owner, world.Reader} {
		if err := world.HoldIndex(device, "after the erasure, the "+device.Name); err != nil {
			t.Fatal(err)
		}
		for _, message := range standing {
			if !world.BodyOpens(device, message) {
				t.Fatalf("%s, which the erasure did not name, no longer opens for the %s", message.Path, device.Name)
			}
		}
	}
	// a companion to the erased email's writer: its next ingest, planned from the rewritten head, indexes as before
	standing = append(standing, world.DeliverAndIngest(world.Owner, sender, M8Message(world.Address, "tide tables", "The tide tables for the estuary.")))
	if err := world.HoldIndex(world.Owner, "after the eraser's next ingest"); err != nil {
		t.Fatal(err)
	}
	if err := world.holdFresh("FS-78", erased, standing...); err != nil {
		t.Fatal(err)
	}
}

// FS-111's mailbox case (the file header's row): writer A is the member's second device and eraser B the owner's
// laptop, the mailbox's admin. A's ingest of D is the mailbox's first push; A's ingest of the next message, planned
// with D in its head, is paused at evs just before its head CAS while B's erasure of D commits.
func RunM10Fs111Mailbox(t testing.TB, world *M10World) {
	t.Helper()
	ctx := world.Context()
	sender := "signup@" + M8SenderDomain
	writerA := world.Reader
	erased := world.DeliverAndIngest(writerA, sender, M8Message(world.Address, "cormorant ledger", "The cormorant ledger closes at noon."))
	if err := world.HoldIndex(world.Owner, "before the paused push"); err != nil {
		t.Fatal(err)
	}
	world.Deliver(sender, M8Message(world.Address, "lighthouse rota", "The lighthouse rota for the spring tides."))
	barriers := world.Net.Barriers()
	if err := barriers.Arm(evsservice.BarrierHeadCasBefore, "", 0); err != nil {
		t.Fatal(err)
	}
	plansBefore, refusalsBefore := writerA.PlanCount(), len(world.Refusals())
	type ingested struct {
		messages []*M10Message
		err      error
	}
	done := make(chan ingested, 1)
	go func() {
		messages, err := world.ingest(writerA)
		done <- ingested{messages: messages, err: err}
	}()
	if err := barriers.AwaitHeld(ctx, evsservice.BarrierHeadCasBefore, ""); err != nil {
		t.Fatal(err)
	}
	// B's CUT, first ERASE and CLOSUREs commit while A's push waits at its head CAS
	cut, err := world.eraseHeld("FS-111's erasure", erased)
	if err != nil {
		barriers.Release(evsservice.BarrierHeadCasBefore)
		t.Fatal(err)
	}
	if err := barriers.Release(evsservice.BarrierHeadCasBefore); err != nil {
		t.Fatal(err)
	}
	var result ingested
	select {
	case result = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if result.err != nil || len(result.messages) != 1 {
		t.Fatalf("A's paused ingest wrote %d messages: %v", len(result.messages), result.err)
	}
	kept := result.messages[0]
	// the paused push was refused 409 INDEX_EPOCH, and the ingest planned it again
	refused := 0
	for _, refusal := range world.Refusals()[refusalsBefore:] {
		if refusal.Status == http.StatusConflict && refusal.Code == protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH {
			refused += 1
		}
	}
	if refused == 0 {
		t.Fatalf("no push was refused 409 INDEX_EPOCH: %+v", world.Refusals()[refusalsBefore:])
	}
	if plans := writerA.PlanCount() - plansBefore; plans < 2 {
		t.Fatalf("A's ingest planned its push %d times, so it was not built again", plans)
	}
	if kept.RefVersion <= cut.cutVersion {
		t.Fatalf("A's push committed at %d, not after the CUT at %d", kept.RefVersion, cut.cutVersion)
	}
	// committed without D: the index holds the new message alone, for every device
	for _, device := range []*M10Device{world.Owner, writerA} {
		if err := world.HoldIndex(device, "after the rebuilt push, the "+device.Name); err != nil {
			t.Fatal(err)
		}
	}
	// the fake clock passes 20 min, and what a device reads has not changed
	world.Advance(20 * time.Minute)
	if err := world.holdFresh("FS-111", erased, kept); err != nil {
		t.Fatal(err)
	}
}

// What RunM10Fs112Mailbox's message is made of.
type M10Fs112Settings struct {
	// The message's text: FS-112's 5 MiB less a margin for its headers' fields, so the extracted text stays within
	// five chunks.
	TextByteCount int
	// The chunk documents such a message gives (§11.14's D4).
	ChunkCount int
	Seed       uint64
}

// FS-112's message.
func DefaultM10Fs112Settings() *M10Fs112Settings {
	return &M10Fs112Settings{TextByteCount: 5*1024*1024 - 64*1024, ChunkCount: 5, Seed: 112}
}

// A message to recipient whose body is byteCount bytes of words from seed, in lines SMTP carries.
func m10LongMessage(recipient string, byteCount int, seed uint64) []byte {
	random := rand.New(rand.NewPCG(seed, seed^0x5eed5eed5eed5eed))
	syllables := []string{"ka", "lo", "mi", "ne", "ru", "sa", "to", "ve", "wi", "zu", "ba", "de", "fi", "go", "hu", "ji"}
	message := &bytes.Buffer{}
	message.WriteString(strings.Join([]string{
		"From: Archive <archive@" + M8SenderDomain + ">",
		"To: <" + recipient + ">",
		"Subject: the long ledger",
		"Date: Thu, 19 Nov 2026 12:00:00 +0000",
		"Message-ID: <long-ledger@" + M8SenderDomain + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=us-ascii",
		"",
		"",
	}, "\r\n"))
	bodyStart := message.Len()
	line := 0
	for message.Len()-bodyStart < byteCount {
		for range 1 + random.IntN(4) {
			message.WriteString(syllables[random.IntN(len(syllables))])
		}
		if line += 1; line%9 == 0 {
			message.WriteString("\r\n")
		} else {
			message.WriteString(" ")
		}
	}
	message.WriteString("\r\n")
	return message.Bytes()
}

// FS-112's mailbox case (the file header's row): one admitted message with 5 MiB of text, ingested by the owner's
// laptop in the mailbox's first push, and its erasure.
func RunM10Fs112Mailbox(t testing.TB, world *M10World, settings *M10Fs112Settings) {
	t.Helper()
	if settings == nil {
		settings = DefaultM10Fs112Settings()
	}
	long := world.DeliverAndIngest(world.Owner, "archive@"+M8SenderDomain, m10LongMessage(world.Address, settings.TextByteCount, settings.Seed))
	// five chunk documents, each the oracle's
	documents, err := world.Oracle.Documents(world.scope())
	if err != nil {
		t.Fatal(err)
	}
	chunks := map[uint32]bool{}
	for _, document := range documents {
		if document.Name == long.Path {
			chunks[document.Chunk] = true
		}
	}
	if len(documents) != settings.ChunkCount || len(chunks) != settings.ChunkCount {
		t.Fatalf("a message of %d bytes is %d documents of the oracle's, chunks %v, not %d", len(long.Content), len(documents), chunks, settings.ChunkCount)
	}
	if err := world.HoldIndex(world.Owner, "the long message's chunks"); err != nil {
		t.Fatal(err)
	}
	standing := world.DeliverAndIngest(world.Reader, "signup@"+M8SenderDomain, M8Message(world.Address, "harbor notice", "The harbor notice lists the dredging days."))
	if err := world.HoldIndex(world.Reader, "before the erasure"); err != nil {
		t.Fatal(err)
	}
	if _, err := world.eraseHeld("FS-112's erasure", long); err != nil {
		t.Fatal(err)
	}
	// its body no longer opens, and no chunk of it stands in any index file: the short message alone
	for _, device := range []*M10Device{world.Owner, world.Reader} {
		if err := world.HoldIndex(device, "after the erasure, the "+device.Name); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.holdFresh("FS-112", long, standing); err != nil {
		t.Fatal(err)
	}
}

// --- FS-76 ---

// What RunM10Fs76Mailbox runs with.
type M10Fs76Settings struct {
	// The corpus's mail: its seed and how many messages its 200 days hold. Notes and their changes are the general
	// repo's, FS-76's M10 case.
	Seed         int64
	MessageCount int
	// Queries of each form the query set draws, and its seed.
	PerClass  int
	QuerySeed int64
	// After how many of the corpus's messages the first message is erased, and the canonical-reading messages land.
	EraseAfterCount     int
	CanonicalAfterCount int
	// The most roll-ups one boundary may owe, a bound on a loop.
	RollUpMaxCount int
	// The mailbox's bucket window in days: §11.14's default, which stands where no settings version says otherwise.
	WindowDays uint32
	// The pages a search may take, and the most one read of an index file asks for.
	PageCount     int
	ReadByteCount int64
}

// FS-76's mailbox case at a draft's scale.
func DefaultM10Fs76Settings() *M10Fs76Settings {
	return &M10Fs76Settings{
		Seed: 76, MessageCount: 40, PerClass: 2, QuerySeed: 76, EraseAfterCount: 3, CanonicalAfterCount: 5,
		RollUpMaxCount: 8, WindowDays: 30, PageCount: 4096, ReadByteCount: 32 * 1024 * 1024,
	}
}

// One message only the canonical reading finds a word of, and the word.
type m10Canonical struct {
	word    string
	message []byte
}

// FS-76's canonical-reading messages as SMTP carries them: a word a quoted-printable soft line break joins, a name
// from RFC 2231 sections, a word behind &#9 in HTML and a word in an unpadded base64 tail.
func m10CanonicalMessages(recipient string) []*m10Canonical {
	header := func(tag string, more ...string) string {
		return strings.Join(append([]string{
			"From: Canon <canon@" + M8SenderDomain + ">",
			"To: <" + recipient + ">",
			"Subject: canonical " + tag,
			"Date: Thu, 19 Nov 2026 12:00:00 +0000",
			"Message-ID: <canonical-" + tag + "@" + M8SenderDomain + ">",
			"MIME-Version: 1.0",
		}, more...), "\r\n")
	}
	return []*m10Canonical{
		{word: "marlinspike", message: []byte(header("softbreak", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable") +
			"\r\n\r\nthe bosun keeps a marlin=\r\nspike in the locker\r\n")},
		{word: "quarterdeck", message: []byte(header("sections", "Content-Type: multipart/mixed; boundary=canon-boundary") + "\r\n\r\n" + strings.Join([]string{
			"--canon-boundary",
			"Content-Type: text/plain; charset=utf-8",
			"",
			"the plans are attached",
			"--canon-boundary",
			"Content-Type: application/octet-stream",
			"Content-Disposition: attachment; filename*0=\"quarter\"; filename*1=\"deck.bin\"",
			"Content-Transfer-Encoding: base64",
			"",
			"AAEC",
			"--canon-boundary--",
			"",
		}, "\r\n"))},
		{word: "topgallant", message: []byte(header("entity", "Content-Type: text/html; charset=utf-8") +
			"\r\n\r\n<html><body><p>mizzen&#9;topgallant&#9;spar</p></body></html>\r\n")},
		{word: "forecastle", message: []byte(header("tail", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64") +
			// "stow it in the forecastle" without its padding
			"\r\n\r\nc3RvdyBpdCBpbiB0aGUgZm9yZWNhc3RsZQ\r\n")},
	}
}

// The search world FS-76's query set runs on (the file header's last gap): the mailbox's messages as ingest stored
// them, written again at their m/ paths by the index's own in-ref writer to a mailbox ref on the root's stand-in for
// evs, a desktop holding their text and a phone following it, and an oracle of its own over that ref's key.
type m10SearchHalf struct {
	world     *M10World
	settings  *M10Fs76Settings
	index     *sidecar.SearchTestWorld
	ledger    *sidecartest.SearchLedger
	oracle    *sidecartest.SearchOracle
	networkId sidecar.Id
	readerId  sidecar.Id
	desktop   *sidecar.SearchTestDevice
	phone     *sidecar.SearchTestDevice
	// each message's version there, by path
	versions map[string]uint64
	// searches run, and the oracle's matches they were held to
	searchCount int
	matchCount  int
}

func m10Id(label string) sidecar.Id {
	digest := sha256.Sum256([]byte(label))
	return sidecar.Id(digest[:16])
}

func newM10SearchHalf(world *M10World, settings *M10Fs76Settings) (*m10SearchHalf, error) {
	ctx := world.Context()
	repoId, refId := m10Id("m10 fs76 search repo"), m10Id("m10 fs76 search ref")
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: repoId, RefId: refId, Clock: world.Net.Clock(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX})
	if err != nil {
		return nil, err
	}
	self := &m10SearchHalf{
		world: world, settings: settings, index: index, ledger: sidecartest.NewSearchLedger(),
		networkId: m10Id("m10 fs76 search network"), readerId: m10Id("m10 fs76 search reader"), versions: map[string]uint64{},
	}
	err = self.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
		RepoId: repoId, NetworkId: self.networkId, Kind: protocol.RepoKind_REPO_KIND_MAILBOX, DefaultRefId: refId,
		Key: index.RepoKey(), ReaderIds: []sidecar.Id{self.readerId},
	})
	if err != nil {
		return nil, err
	}
	self.oracle = sidecartest.NewSearchOracle(self.ledger)
	desktop, phone := sidecar.SearchConditions{DaemonHost: true}, sidecar.SearchConditions{Unmetered: true, Charging: true, Reported: true, Foreground: true}
	self.desktop, err = index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: sidecar.DefaultSidecarSettings().Search, Conditions: func() sidecar.SearchConditions { return desktop },
		ReadByteCount: settings.ReadByteCount, Coverage: true, Text: true,
	})
	if err != nil {
		return nil, err
	}
	world.t.Cleanup(self.desktop.Close)
	self.phone, err = index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: sidecartest.SearchRemotePhoneSettings(), Conditions: func() sidecar.SearchConditions { return phone },
		ReadByteCount: settings.ReadByteCount, Coverage: true,
	})
	if err != nil {
		return nil, err
	}
	world.t.Cleanup(self.phone.Close)
	return self, nil
}

// message, as the mailbox stores it, committed to the search world by its writer at the clock now.
func (self *m10SearchHalf) commit(message *M10Message) error {
	changes := []*sidecar.SearchTestChange{{Path: message.Path, Content: message.Content}}
	commit, err := self.index.CommitIndexed(self.world.Context(), message.WriterId, self.world.Net.Clock().Now(), changes)
	if err != nil {
		return err
	}
	self.versions[message.Path] = commit.Versions[message.Path]
	return self.ledger.Commit(&sidecartest.SearchCommit{
		RepoId: self.index.RepoId(), RefId: self.index.RefId(), RefVersion: commit.RefVersion, Time: commit.Time,
		WriterId: message.WriterId, Indexed: 0 < commit.IndexWriteCount,
		Changes: []*sidecartest.SearchChange{{Path: message.Path, Version: commit.Versions[message.Path], Content: message.Content}},
	})
}

// message's CUT there, from which every search masks it.
func (self *m10SearchHalf) cut(message *M10Message) error {
	version := self.versions[message.Path]
	if _, err := self.index.Cut(self.world.Context(), m10Id("m10 fs76 erasure "+message.Path), []*sidecar.SearchTestDocument{{Path: message.Path, Version: version}}); err != nil {
		return err
	}
	return self.ledger.Erase(self.index.RepoId(), self.index.RefId(), message.Path, version)
}

// Every expired bucket rolled into all, as the mailbox's own roll-ups run.
func (self *m10SearchHalf) rollUp(runner sidecar.Id) error {
	for range self.settings.RollUpMaxCount {
		rolled, err := self.index.RollUpResult(self.world.Context(), runner)
		if err != nil {
			return err
		}
		if rolled.Skipped != "" {
			return nil
		}
		if err := self.ledger.RolledThrough(self.index.RepoId(), self.index.RefId(), rolled.StartDay); err != nil {
			return err
		}
	}
	return fmt.Errorf("the search world owes more than %d roll-ups", self.settings.RollUpMaxCount)
}

func m10DocumentKey(path string, docKey [16]byte, version uint64) string {
	return fmt.Sprintf("%s#%x@%d", path, docKey[:4], version)
}

// The query set on the desktop and the phone, on the buckets and on buckets plus all, each device synced first, held
// to the oracle (FI-18; FS-76's equality): the desktop's hits, checked against its own text, are the oracle's
// matches, each verified; the phone's candidates include every match and each names a document's newest live
// version, none resting on a version the erasure's mask hides.
func (self *m10SearchHalf) hold(label string, queries []string) error {
	ctx := self.world.Context()
	for _, held := range []struct {
		name   string
		device *sidecar.SearchTestDevice
	}{{name: "desktop", device: self.desktop}, {name: "phone", device: self.phone}} {
		if err := held.device.Sync(ctx); err != nil && !errors.Is(err, sidecar.ErrSearchSyncUnfollowed) {
			return fmt.Errorf("%s: the %s's sync: %w", label, held.name, err)
		}
		for _, scope := range []sidecar.SearchScope{sidecar.SearchLatest, sidecar.SearchAll} {
			partitions := sidecartest.SearchScopeAll
			if scope == sidecar.SearchLatest {
				partitions = sidecartest.SearchScopeLatest
			}
			oracleScope := &sidecartest.SearchScope{Partitions: partitions, Breadth: sidecartest.SearchBreadthNetwork, NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId}
			documents, err := self.oracle.Documents(oracleScope)
			if err != nil {
				return fmt.Errorf("%s: the oracle: %w", label, err)
			}
			live := map[string]bool{}
			for _, document := range documents {
				live[m10DocumentKey(document.Name, document.DocKey, document.Version)] = true
			}
			for _, query := range queries {
				at := fmt.Sprintf("%s: the %s's search for %q in scope %d", label, held.name, query, scope)
				matches, covered, err := self.oracle.Judge(query, oracleScope)
				if err != nil && !errors.Is(err, sidecartest.ErrSearchOracleQueryRefused) {
					return fmt.Errorf("%s: the oracle cannot judge it: %w", at, err)
				}
				isCovered := map[string]bool{}
				for _, document := range covered {
					isCovered[m10DocumentKey(document.Name, document.DocKey, document.Version)] = true
				}
				want := []string{}
				for _, match := range matches {
					key := m10DocumentKey(match.Name, match.DocKey, match.Version)
					if !isCovered[key] {
						return fmt.Errorf("%s: the oracle's match %s is not covered, though every push here is indexed", at, key)
					}
					want = append(want, key)
				}
				slices.Sort(want)
				self.searchCount += 1
				self.matchCount += len(want)
				search, err := held.device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: scope, Remote: "off"}, self.settings.PageCount, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", at, err)
				}
				hits := []string{}
				for _, hit := range search.Hits() {
					if hit.State == sidecar.SearchNear {
						continue
					}
					hits = append(hits, m10DocumentKey(hit.Path, hit.DocKey, hit.Version))
					if held.name == "desktop" && hit.State != sidecar.SearchVerified {
						return fmt.Errorf("%s left %s@%d unverified, state %d, though it holds the text", at, hit.Path, hit.Version, hit.State)
					}
				}
				slices.Sort(hits)
				if len(slices.Compact(slices.Clone(hits))) != len(hits) {
					return fmt.Errorf("%s shows a document twice: %v", at, hits)
				}
				for _, key := range want {
					if !slices.Contains(hits, key) {
						return fmt.Errorf("%s left out %s, covered and matching: found %v", at, key, hits)
					}
				}
				for _, key := range hits {
					if held.name == "desktop" && !slices.Contains(want, key) {
						return fmt.Errorf("%s found %s, which the oracle does not match: found %v, the oracle %v", at, key, hits, want)
					}
					if !live[key] {
						return fmt.Errorf("%s found %s, which is no document's newest live version", at, key)
					}
				}
			}
		}
	}
	return nil
}

// FS-76's mailbox case (the file header's row).
func RunM10Fs76Mailbox(t testing.TB, world *M10World, settings *M10Fs76Settings) {
	t.Helper()
	if settings == nil {
		settings = DefaultM10Fs76Settings()
	}
	ctx := world.Context()
	clock := world.Net.Clock()
	corpusSettings := sidecartest.DefaultSearchCorpusSettings()
	corpusSettings.Seed = settings.Seed
	corpusSettings.Start = clock.Now()
	corpusSettings.MessageCount, corpusSettings.NoteCount, corpusSettings.ChangeCount, corpusSettings.SkipPercent = settings.MessageCount, 0, 0, 0
	corpus := sidecartest.NewSearchCorpus(corpusSettings)
	queries := []string{}
	for _, query := range sidecartest.NewSearchQuerySet(corpus, settings.QuerySeed, settings.PerClass).Queries {
		if !slices.Contains(queries, query.Text) {
			queries = append(queries, query.Text)
		}
	}
	canonical := m10CanonicalMessages(world.Address)
	for _, message := range canonical {
		queries = append(queries, message.word)
	}
	search, err := newM10SearchHalf(world, settings)
	if err != nil {
		t.Fatal(err)
	}
	devices := []*M10Device{world.Owner, world.Reader}
	check := func(label string) {
		t.Helper()
		for _, device := range devices {
			if err := world.HoldIndex(device, label+", the "+device.Name); err != nil {
				t.Fatal(err)
			}
		}
		if err := search.hold(label, queries); err != nil {
			t.Fatal(err)
		}
	}
	// a message delivered and ingested by the next device in turn, the same bytes then committed to the search world
	delivered := 0
	deliver := func(from string, content []byte) *M10Message {
		t.Helper()
		message := world.DeliverAndIngest(devices[delivered%len(devices)], from, content)
		delivered += 1
		if err := search.commit(message); err != nil {
			t.Fatal(err)
		}
		return message
	}
	// every expired bucket of the mailbox rolled into all by the owner's laptop, through EvsRepo
	rollUp := func(label string) int {
		t.Helper()
		rolled := 0
		for range settings.RollUpMaxCount {
			result, err := sidecar.RollUpSearchTestEvs(ctx, world.Owner.Repo, nil, world.Owner.Signer.SidecarId, world.IsAdmin)
			if err != nil {
				t.Fatalf("%s: the mailbox's roll-up: %v", label, err)
			}
			if result.Skipped != "" {
				break
			}
			rolled += 1
			if err := world.Ledger.RolledThrough(world.Mail.RepoId, world.refId, result.StartDay); err != nil {
				t.Fatal(err)
			}
		}
		if err := search.rollUp(world.Owner.Signer.SidecarId); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return rolled
	}
	var first *M10Message
	boundaries, rollUps, forms := 0, 0, map[string]bool{}
	for _, step := range corpus.Steps {
		if step.Commit == nil || len(step.Commit.Changes) != 1 {
			t.Fatalf("the corpus's mail holds a step that is no one message: %+v", step)
		}
		// each bucket boundary between here and the message's time: 1 s before, 1 s after, then the roll-ups it owes
		for {
			startDay := sidecar.SearchTestBucketStartDay(clock.Now())
			if startDay%settings.WindowDays != 0 {
				t.Fatalf("the bucket at day %d is no multiple of the %d-day window", startDay, settings.WindowDays)
			}
			nextStartDay := startDay + settings.WindowDays
			boundary := time.Unix(int64(nextStartDay)*24*60*60, 0).UTC()
			if step.At.Before(boundary) {
				break
			}
			boundaries += 1
			world.Advance(boundary.Add(-time.Second).Sub(clock.Now()))
			check(fmt.Sprintf("1 s before the boundary at day %d", nextStartDay))
			world.Advance(2 * time.Second)
			check(fmt.Sprintf("1 s after the boundary at day %d", nextStartDay))
			if rolled := rollUp(fmt.Sprintf("the boundary at day %d", nextStartDay)); 0 < rolled {
				rollUps += rolled
				check(fmt.Sprintf("after the roll-ups at day %d", nextStartDay))
			}
		}
		if wait := step.At.Sub(clock.Now()); 0 < wait {
			world.Advance(wait)
		}
		content := step.Commit.Changes[0].Content
		for _, form := range []string{"base64", "quoted-printable", "text/html", "multipart/alternative", "multipart/mixed", "iso-8859-1"} {
			if bytes.Contains(content, []byte(form)) {
				forms[form] = true
			}
		}
		message := deliver(M10CorpusSender, content)
		if first == nil {
			first = message
		}
		if delivered == settings.CanonicalAfterCount {
			for _, canon := range canonical {
				deliver("canon@"+M8SenderDomain, canon.message)
			}
			check("after the canonical-reading messages")
		}
		if delivered == settings.EraseAfterCount {
			// the erasure, of the message the mailbox's first push ingested (the file header's first gap)
			if _, err := world.eraseHeld("FS-76's erasure", first); err != nil {
				t.Fatal(err)
			}
			if err := search.cut(first); err != nil {
				t.Fatal(err)
			}
			check("after the erasure")
		}
	}
	check("at the end")
	if delivered != settings.MessageCount+len(canonical) || boundaries == 0 || rollUps == 0 || search.matchCount == 0 {
		t.Fatalf("the run delivered %d messages across %d boundaries and %d roll-ups, its %d searches held to %d matches",
			delivered, boundaries, rollUps, search.searchCount, search.matchCount)
	}
	t.Logf("FS-76's mailbox case: %d messages, %d bucket boundaries, %d roll-ups on the mailbox, 1 erasure; %d queries, %d searches on the search world held to %d matches",
		delivered, boundaries, rollUps, len(queries), search.searchCount, search.matchCount)
	for _, form := range []string{"base64", "quoted-printable", "text/html"} {
		if !forms[form] {
			t.Fatalf("the corpus's mail holds no %s part: %v", form, forms)
		}
	}
	// each canonical word is found, on the desktop, in its own message alone
	documents, err := world.Oracle.Documents(world.scope())
	if err != nil {
		t.Fatal(err)
	}
	for _, canon := range canonical {
		matches := world.Oracle.Matches(canon.word, world.scope())
		if len(matches) != 1 || !slices.ContainsFunc(documents, func(document *sidecartest.DocumentKey) bool { return document.DocKey == matches[0].DocKey }) {
			t.Fatalf("the oracle finds %q in %d of the mailbox's documents", canon.word, len(matches))
		}
	}
}
