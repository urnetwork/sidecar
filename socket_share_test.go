//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// ur share (SOCK-M5-15) on the in-memory socket network, a sealed store and an armed clock, §22.5's list: no get or
// resume at or past expire_millis, a live stream reset there, a sharer restarted past it serving nothing, --expires
// over 30 days refused, uses never exceeded across a crash after a Reserve, two getters racing the last use; and
// resume by the same getter only, a wrong secret spending nothing, a changed file, rm ending live streams, the wrong
// listener refused before OPEN, FI-7's crash points, and the link and part files.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// One network's shares on the test network and a sealed store, started and restarted by hand.
type testShareFixture struct {
	t         *testing.T
	clock     *testArmedClock
	net       *testSocketNet
	backend   *testSocketBackend
	directory string
	shares    *socketShares
}

func newTestShareFixture(t *testing.T) *testShareFixture {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	network := newTestSocketNet()
	backend := newTestSocketBackend(network)
	backend.store = instance.Store(&testNetworkId)
	fixture := &testShareFixture{t: t, clock: newTestArmedClock(), net: network, backend: backend, directory: t.TempDir()}
	fixture.shares = fixture.start()
	return fixture
}

// A fresh process's shares over the same store and network, loaded once, as a daemon's start loads them.
func (self *testShareFixture) start() *socketShares {
	ctx, cancel := context.WithCancel(context.Background())
	self.t.Cleanup(cancel)
	shares := &socketShares{
		networkId:       testNetworkId,
		backend:         self.backend,
		settings:        self.backend.settingsValue.Share,
		clock:           self.clock,
		log:             NewNoopLogger(),
		ctx:             ctx,
		cancel:          cancel,
		dialerSidecarId: self.net.dialerSidecarId,
		tokenShares:     map[string]*socketShare{},
		failedTokens:    map[string]bool{},
		pendingTokens:   map[string]bool{},
	}
	shares.load()
	return shares
}

// The sharer's process ends with no end of its shares, as a crash or a daemon's stop leaves them, and a new one starts.
func (self *testShareFixture) restart() {
	self.shares.stop()
	self.shares = self.start()
}

// A file of content in the fixture's directory.
func (self *testShareFixture) file(name string, content []byte) string {
	path := filepath.Join(self.directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		self.t.Fatal(err)
	}
	return path
}

// ur share add's params for path, as ur draws and hashes them.
func (self *testShareFixture) params(path string, uses uint32, expires time.Duration) *DaemonShareAddParams {
	content, err := os.ReadFile(path)
	if err != nil {
		self.t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		self.t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	token, secret := NewShareCredentials()
	return &DaemonShareAddParams{
		Path:          path,
		Size:          info.Size(),
		MtimeNanos:    info.ModTime().UnixNano(),
		Sha256:        sum[:],
		Uses:          uses,
		ExpiresMillis: expires.Milliseconds(),
		Token:         token,
		Secret:        secret,
	}
}

// Adds a share of path, answering its link.
func (self *testShareFixture) add(path string, uses uint32, expires time.Duration) *ShareLink {
	self.t.Helper()
	params := self.params(path, uses, expires)
	reply, err := self.shares.add(context.Background(), params)
	if err != nil {
		self.t.Fatal(err)
	}
	link, err := ParseShareLink(FormatShareLink(reply.NetworkLabel, reply.Token, reply.SidecarId, params.Secret))
	if err != nil {
		self.t.Fatal(err)
	}
	return link
}

// One whole get of link by getterId into out. A get that succeeds returns once the sharer is through with it: the
// getter's half ends at the reset that a last use's end starts with, before that end has unlistened, deleted the
// record and forgotten the share, and the sharer's serve closes its conn only after all of that.
func (self *testShareFixture) get(link *ShareLink, getterId Id, out string) error {
	self.t.Helper()
	part, err := OpenSharePart(out, link.Token, 4096)
	if err != nil {
		return err
	}
	conn, served, err := self.net.dialServed(socketShareNamePrefix+link.Token, getterId)
	if err != nil {
		part.Close()
		return err
	}
	defer conn.Close()
	if err := part.Get(conn, link); err != nil {
		return err
	}
	testSocketAwait(self.t, served, "end of the sharer's serve")
	return nil
}

// The share's folded record on disk, nil once it was deleted.
func (self *testShareFixture) record(token string) *socketShareState {
	self.t.Helper()
	ledger, err := newSocketShareLedger(self.backend.store)
	if err != nil {
		self.t.Fatal(err)
	}
	state, err := ledger.read(token)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	return state
}

// The live share of token in shares.
func (self *testShareFixture) live(token string) *socketShare {
	self.t.Helper()
	self.shares.stateLock.Lock()
	defer self.shares.stateLock.Unlock()
	share := self.shares.tokenShares[token]
	if share == nil {
		self.t.Fatalf("no live share")
	}
	return share
}

var testShareContent = bytes.Repeat([]byte("synthetic shared bytes, line after line\n"), 4000)

// A get receives the whole file under its hash, its part and id files go, and a one-use share ends with its Done:
// the stream resets, the listener goes and the record is deleted.
func TestShareGetReceivesFileAndEnds(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	if link.SidecarId != *fixture.backend.sidecar || link.NetworkLabel != "abcdefghij" || !fixture.net.listening(socketShareNamePrefix+link.Token) {
		t.Fatalf("link %+v", link)
	}
	if record := fixture.record(link.Token); record == nil || record.share.Uses != 1 || len(record.share.Secret) != socketShareSecretByteCount {
		t.Fatalf("record %+v", record)
	}
	out := filepath.Join(fixture.directory, "got.bin")
	if err := fixture.get(link, testSocketId("getter"), out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, testShareContent) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	for _, leftover := range []string{out + ".part", out + sharePartIdSuffix} {
		if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stays: %v", filepath.Base(leftover), err)
		}
	}
	// the Done ended the share
	if fixture.record(link.Token) != nil || fixture.net.listening(socketShareNamePrefix+link.Token) || fixture.shares.liveCount() != 0 {
		t.Error("the share outlived its one use")
	}
}

// An omitted count is one use; 0 is unlimited until the expiry, every get served; n serves n and then answers spent.
func TestShareCountsUses(t *testing.T) {
	fixture := newTestShareFixture(t)
	unlimited := fixture.add(fixture.file("unlimited.bin", testShareContent), 0, time.Hour)
	for i := range 3 {
		if err := fixture.get(unlimited, testSocketId("getter "+string(rune('a'+i))), filepath.Join(fixture.directory, "u"+string(rune('a'+i)))); err != nil {
			t.Fatalf("unlimited get %d: %v", i, err)
		}
	}
	if record := fixture.record(unlimited.Token); record == nil || len(record.reserves) != 3 || record.remaining() != -1 {
		t.Errorf("an unlimited share after three gets: %+v", record)
	}
	two := fixture.add(fixture.file("two.bin", testShareContent), 2, time.Hour)
	if err := fixture.get(two, testSocketId("first"), filepath.Join(fixture.directory, "t1")); err != nil {
		t.Fatal(err)
	}
	// a reserved use, not yet done: the second get takes the last use, the third is spent
	share := fixture.live(two.Token)
	if decision := share.decide(testShareHeader(two.Secret, NewId(), 0), testSocketId("second")); decision.kind != socketShareDecisionOk {
		t.Fatalf("the second use: %v", decision.kind)
	}
	if err := fixture.get(two, testSocketId("third"), filepath.Join(fixture.directory, "t3")); !errors.Is(err, ErrShareSpent) {
		t.Errorf("a third get of two uses: %v", err)
	}
}

// §22.5: no get starts or resumes at or past expire_millis. The expiry's timer ends the share there, and a header that
// arrives at it, before the timer has run, is reset with no use spent.
func TestShareNoGetAtOrPastExpiry(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 2, time.Hour)
	share := fixture.live(link.Token)
	getId := NewId()
	getter := testSocketId("getter")
	if decision := share.decide(testShareHeader(link.Secret, getId, 0), getter); decision.kind != socketShareDecisionOk {
		t.Fatalf("before the expiry: %v", decision.kind)
	}
	// at the expiry instant itself, a header decided before the timer has run: held here by stopping the timer
	share.stateLock.Lock()
	stopExpiry := share.stopExpiry
	share.stateLock.Unlock()
	stopExpiry()
	fixture.clock.advance(time.Hour)
	if share.state.share.ExpireMillis != fixture.clock.Now().UnixMilli() {
		t.Fatal("the clock is not at the expiry")
	}
	for _, header := range [][]byte{testShareHeader(link.Secret, getId, 10), testShareHeader(link.Secret, NewId(), 0)} {
		if decision := share.decide(header, getter); decision.kind != socketShareDecisionReset {
			t.Errorf("at the expiry: %v", decision.kind)
		}
	}
	if record := fixture.record(link.Token); len(record.reserves) != 1 {
		t.Errorf("reserves %d after gets at the expiry", len(record.reserves))
	}
	// what the timer runs
	share.end()
	if fixture.record(link.Token) != nil || fixture.net.listening(socketShareNamePrefix+link.Token) {
		t.Error("the share outlived its expiry")
	}
	if err := fixture.get(link, getter, filepath.Join(fixture.directory, "late")); !errors.Is(err, ErrSocketNoListener) {
		t.Errorf("a get past the expiry: %v", err)
	}
}

// §22.5: a live stream is reset at the expiry, whatever it was sending.
func TestShareLiveStreamResetAtExpiry(t *testing.T) {
	fixture := newTestShareFixture(t)
	big := bytes.Repeat([]byte{0x5a}, 1024*1024)
	link := fixture.add(fixture.file("big.bin", big), 1, 10*time.Minute)
	conn, err := fixture.net.dialAs(socketShareNamePrefix+link.Token, testSocketId("getter"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(testShareHeader(link.Secret, NewId(), 0))
	answer := make([]byte, socketShareOkByteCount+4096)
	if _, err := io.ReadFull(conn, answer); err != nil || answer[0] != socketShareStatusOk {
		t.Fatalf("the stream's start: %v", err)
	}
	// the sharer is mid-file, held by the pipe's credit, when the expiry comes
	fixture.clock.advance(10 * time.Minute)
	if _, err := io.Copy(io.Discard, conn); !errors.Is(err, ErrSocketReset) {
		t.Errorf("the stream at the expiry: %v", err)
	}
	if fixture.record(link.Token) != nil {
		t.Error("the record outlived the expiry")
	}
}

// §22.5: a sharer offline at the expiry serves nothing once it starts again, and deletes the record.
func TestShareSharerRestartedPastExpiryServesNothing(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	fixture.shares.stop()
	fixture.clock.advance(2 * time.Hour)
	fixture.shares = fixture.start()
	if fixture.shares.liveCount() != 0 || fixture.net.listening(socketShareNamePrefix+link.Token) || fixture.record(link.Token) != nil {
		t.Error("a share past its expiry served after a restart")
	}
}

// A sharer restarted before the expiry serves the share again from its record, uses counted as they were.
func TestShareSurvivesRestart(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 2, time.Hour)
	if err := fixture.get(link, testSocketId("first"), filepath.Join(fixture.directory, "one")); err != nil {
		t.Fatal(err)
	}
	fixture.restart()
	if !fixture.net.listening(socketShareNamePrefix+link.Token) || fixture.live(link.Token).state.remaining() != 1 {
		t.Fatal("the restarted share")
	}
	if err := fixture.get(link, testSocketId("second"), filepath.Join(fixture.directory, "two")); err != nil {
		t.Fatal(err)
	}
	if fixture.record(link.Token) != nil {
		t.Error("two Dones of two uses left the record")
	}
}

// A stop whose cancel ends the accept loop before its unlisten runs leaves no listener holding the share's name: the
// loop closes the listener it held, so the restarted share listens again and serves.
func TestShareStopClosesListenerWhenAcceptEndsFirst(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	name := socketShareNamePrefix + link.Token
	fixture.net.stateLock.Lock()
	listener := fixture.net.listeners[name]
	fixture.net.stateLock.Unlock()
	if listener == nil {
		t.Fatal("the share is not listening")
	}
	// a stop's cancel alone, so the accept loop ends by its context with no unlisten yet
	fixture.shares.cancel()
	testSocketAwait(t, listener.closed, "close of the listener at the accept loop's end")
	fixture.restart()
	if !fixture.net.listening(name) {
		t.Fatal("the restarted share did not listen")
	}
	if err := fixture.get(link, testSocketId("getter"), filepath.Join(fixture.directory, "got.bin")); err != nil {
		t.Fatal(err)
	}
}

// §22.5 and owner decision 74: --expires past 30 days is refused, 30 days taken, and none takes the 24 h default.
func TestShareExpiresOver30DaysRefused(t *testing.T) {
	fixture := newTestShareFixture(t)
	path := fixture.file("data.bin", testShareContent)
	if _, err := fixture.shares.add(context.Background(), fixture.params(path, 1, 30*24*time.Hour+time.Millisecond)); !errors.Is(err, ErrShareExpiresTooLong) {
		t.Errorf("past 30 days: %v", err)
	}
	reply, err := fixture.shares.add(context.Background(), fixture.params(path, 1, 30*24*time.Hour))
	if err != nil || reply.ExpireMillis != fixture.clock.Now().Add(30*24*time.Hour).UnixMilli() {
		t.Errorf("30 days: %+v %v", reply, err)
	}
	reply, err = fixture.shares.add(context.Background(), fixture.params(path, 1, 0))
	if err != nil || reply.ExpireMillis != fixture.clock.Now().Add(24*time.Hour).UnixMilli() {
		t.Errorf("the default: %+v %v", reply, err)
	}
}

// §22.5: uses are never exceeded across a crash after a Reserve. The Reserve is fsynced before any byte, a restart
// counts it, another getter is then spent, and the crashed getter alone resumes it.
func TestShareUsesNeverExceededAcrossCrashAfterReserve(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	first := testSocketId("first")
	out := filepath.Join(fixture.directory, "first.bin")
	part, err := OpenSharePart(out, link.Token, 4096)
	if err != nil {
		t.Fatal(err)
	}
	getId := part.GetId()
	part.Close()
	if decision := fixture.live(link.Token).decide(testShareHeader(link.Secret, getId, 0), first); decision.kind != socketShareDecisionOk {
		t.Fatal(decision.kind)
	}
	// the crash: the Reserve is on the medium, and no byte left
	fixture.restart()
	if err := fixture.get(link, testSocketId("second"), filepath.Join(fixture.directory, "second.bin")); !errors.Is(err, ErrShareSpent) {
		t.Errorf("another getter after the crash: %v", err)
	}
	if err := fixture.get(link, first, out); err != nil {
		t.Fatalf("the crashed getter's resume: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, testShareContent) {
		t.Error("the resumed bytes")
	}
}

// §22.5: two getters racing the last use: exactly one is served and the other is spent, whatever their order.
func TestShareTwoGettersRaceLastUse(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, name := range []string{"left", "right"} {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- fixture.get(link, testSocketId(name), filepath.Join(fixture.directory, name))
		}()
	}
	group.Wait()
	close(results)
	served, spent := 0, 0
	for err := range results {
		switch {
		case err == nil:
			served += 1
		case errors.Is(err, ErrShareSpent), errors.Is(err, ErrSocketNoListener), errors.Is(err, ErrShareRefused):
			// spent, or the share had already ended with the winner's Done
			spent += 1
		default:
			t.Errorf("a racer: %v", err)
		}
	}
	if served != 1 || spent != 1 {
		t.Errorf("served %d, spent %d", served, spent)
	}
}

// A get cut off mid-stream resumes at its part's end under its get_id, and only its own getter resumes it: another
// sidecar holding the same get_id is reset and spends nothing.
func TestShareResumeBySameGetterOnly(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	getter := testSocketId("getter")
	out := filepath.Join(fixture.directory, "out.bin")
	part, err := OpenSharePart(out, link.Token, 4096)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := fixture.net.dialAs(socketShareNamePrefix+link.Token, getter)
	if err != nil {
		t.Fatal(err)
	}
	// the getter takes a part of the file and the stream is lost
	cut := &testShareCutStream{conn: conn, limit: socketShareOkByteCount + 10000}
	if err := part.Get(cut, link); !errors.Is(err, ErrShareRefused) {
		t.Fatalf("the cut get: %v", err)
	}
	if info, err := os.Stat(out + ".part"); err != nil || info.Size() != 10000 {
		t.Fatalf("the part after the cut: %v", err)
	}
	getId := part.GetId()

	// another sidecar with the same get_id is reset, spending nothing
	other := testSocketId("other")
	if decision := fixture.live(link.Token).decide(testShareHeader(link.Secret, getId, 10000), other); decision.kind != socketShareDecisionReset {
		t.Errorf("another getter's resume: %v", decision.kind)
	}
	if err := fixture.get(link, other, filepath.Join(fixture.directory, "other.bin")); !errors.Is(err, ErrShareSpent) {
		t.Errorf("another getter's own get: %v", err)
	}
	if err := fixture.get(link, getter, out); err != nil {
		t.Fatalf("the resume: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, testShareContent) {
		t.Error("the resumed file")
	}
}

// A stream that ends, as a lost one does, once limit bytes have been read.
type testShareCutStream struct {
	conn  *SocketConn
	read  int
	limit int
}

func (self *testShareCutStream) Read(b []byte) (int, error) {
	if self.limit <= self.read {
		self.conn.Abort()
		return 0, io.ErrUnexpectedEOF
	}
	b = b[:min(len(b), self.limit-self.read)]
	count, err := self.conn.Read(b)
	self.read += count
	return count, err
}

func (self *testShareCutStream) Write(b []byte) (int, error) {
	return self.conn.Write(b)
}

// A wrong secret is reset and spends nothing, and the right one is then served.
func TestShareWrongSecretSpendsNothing(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	wrong := *link
	wrong.Secret = bytes.Repeat([]byte{0x42}, socketShareSecretByteCount)
	if err := fixture.get(&wrong, testSocketId("guesser"), filepath.Join(fixture.directory, "guess")); !errors.Is(err, ErrShareRefused) {
		t.Errorf("a wrong secret: %v", err)
	}
	if record := fixture.record(link.Token); len(record.reserves) != 0 {
		t.Errorf("a wrong secret spent %d", len(record.reserves))
	}
	if err := fixture.get(link, testSocketId("getter"), filepath.Join(fixture.directory, "right")); err != nil {
		t.Fatal(err)
	}
}

// A file whose size or modification time moved answers changed, spending nothing.
func TestShareChangedFile(t *testing.T) {
	fixture := newTestShareFixture(t)
	path := fixture.file("data.bin", testShareContent)
	link := fixture.add(path, 1, time.Hour)
	info, _ := os.Stat(path)
	if err := os.Chtimes(path, info.ModTime(), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.get(link, testSocketId("getter"), filepath.Join(fixture.directory, "changed")); !errors.Is(err, ErrShareChanged) {
		t.Errorf("a touched file: %v", err)
	}
	os.WriteFile(path, append(testShareContent, 'x'), 0o600)
	if err := fixture.get(link, testSocketId("getter"), filepath.Join(fixture.directory, "longer")); !errors.Is(err, ErrShareChanged) {
		t.Errorf("a longer file: %v", err)
	}
	if record := fixture.record(link.Token); len(record.reserves) != 0 {
		t.Errorf("a changed file spent %d", len(record.reserves))
	}
}

// rm ends the share: its Remove is fsynced, live streams reset, the listener goes and the record is deleted.
func TestShareRmEndsLiveStreams(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("big.bin", bytes.Repeat([]byte{0x33}, 1024*1024)), 0, time.Hour)
	conn, err := fixture.net.dialAs(socketShareNamePrefix+link.Token, testSocketId("getter"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(testShareHeader(link.Secret, NewId(), 0))
	if _, err := io.ReadFull(conn, make([]byte, socketShareOkByteCount+1024)); err != nil {
		t.Fatal(err)
	}
	if removed, err := fixture.shares.remove(link.Token); err != nil || !removed {
		t.Fatalf("rm: %v %v", removed, err)
	}
	if _, err := io.Copy(io.Discard, conn); !errors.Is(err, ErrSocketReset) {
		t.Errorf("the live stream after rm: %v", err)
	}
	if fixture.record(link.Token) != nil || fixture.net.listening(socketShareNamePrefix+link.Token) {
		t.Error("the share outlived rm")
	}
	if _, err := fixture.shares.remove(link.Token); !errors.Is(err, ErrShareNone) {
		t.Errorf("a second rm: %v", err)
	}
}

// ur share get refuses before OPEN a listener whose verified sidecar_id is not the link's: the dialer opens nothing to
// it and the dial fails, while the right sidecar's listener opens.
func TestShareWrongListenerRefused(t *testing.T) {
	listener := newTestDialListener("sharer")
	fixture := newTestDialFixture(t, listener)
	fixture.service.answers = [][]*testDialListener{{listener}}
	impostor := testSocketId("not the sharer")
	fixture.dialer.listenerSidecarId = &impostor
	if _, err := fixture.dial(testDialName); err == nil || len(fixture.opener.openedIds()) != 0 {
		t.Errorf("a listener of another sidecar: %v, opened %d", err, len(fixture.opener.openedIds()))
	}
	sharer := listener.signer.sidecarId
	fixture.dialer.listenerSidecarId = &sharer
	conn, err := fixture.dial(testDialName)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

// FI-7: at every crash point of a two-use share's life, no more than two gets are ever served, and Reserves on the
// medium never pass two: after the Share row, after a Reserve, mid-stream, and after a Done.
func TestShareEffectsNeverExceedUsesAtEveryCrashPoint(t *testing.T) {
	for _, point := range []string{"share", "reserve", "stream", "done"} {
		fixture := newTestShareFixture(t)
		path := fixture.file("data.bin", testShareContent)
		served := 0
		var link *ShareLink
		crashed := testSocketId("crashed")
		crashedOut := filepath.Join(fixture.directory, "crashed")
		switch point {
		case "share":
			// the Share row is fsynced and the listen never ran
			params := fixture.params(path, 2, time.Hour)
			ledger, err := newSocketShareLedger(fixture.backend.store)
			if err != nil {
				t.Fatal(err)
			}
			log, err := ledger.log(params.Token)
			if err != nil {
				t.Fatal(err)
			}
			record := &socketShareRecord{Token: params.Token, Path: path, Size: params.Size, MtimeNanos: params.MtimeNanos, Sha256: params.Sha256,
				Secret: params.Secret, Uses: 2, ExpireMillis: fixture.clock.Now().Add(time.Hour).UnixMilli()}
			if err := appendSocketShareRow(log, newSocketShareState(), record); err != nil {
				t.Fatal(err)
			}
			link = &ShareLink{NetworkLabel: "abcdefghij", Token: params.Token, SidecarId: *fixture.backend.sidecar, Secret: params.Secret}
		case "reserve", "stream":
			link = fixture.add(path, 2, time.Hour)
			part, err := OpenSharePart(crashedOut, link.Token, 4096)
			if err != nil {
				t.Fatal(err)
			}
			if point == "reserve" {
				part.Close()
				fixture.live(link.Token).decide(testShareHeader(link.Secret, part.GetId(), 0), crashed)
			} else {
				conn, err := fixture.net.dialAs(socketShareNamePrefix+link.Token, crashed)
				if err != nil {
					t.Fatal(err)
				}
				part.Get(&testShareCutStream{conn: conn, limit: socketShareOkByteCount + 5000}, link)
			}
		case "done":
			link = fixture.add(path, 2, time.Hour)
			if err := fixture.get(link, crashed, crashedOut); err != nil {
				t.Fatal(err)
			}
			served += 1
		}
		fixture.restart()
		for _, name := range []string{"a", "b", "c"} {
			if err := fixture.get(link, testSocketId("after "+name), filepath.Join(fixture.directory, "after-"+name)); err == nil {
				served += 1
			}
		}
		if point == "reserve" || point == "stream" {
			if err := fixture.get(link, crashed, crashedOut); err == nil {
				served += 1
			}
		}
		if 2 < served {
			t.Errorf("%s: %d gets served of two uses", point, served)
		}
		if record := fixture.record(link.Token); record != nil && 2 < len(record.reserves) {
			t.Errorf("%s: %d reserves of two uses", point, len(record.reserves))
		}
		if served != 2 {
			t.Errorf("%s: %d gets served, where two uses serve two", point, served)
		}
	}
}

// A share keeps the daemon up while it lives (§5.8), and ur status counts it.
func TestShareKeepsDaemonUp(t *testing.T) {
	daemonFixture := newTestDaemonSockets(t)
	instance, _, _ := enrolledInstance(t)
	daemonFixture.backend.store = instance.Store(&testNetworkId)
	daemonFixture.started.daemon.Sockets().shareDialerSidecarId = daemonFixture.net.dialerSidecarId
	path := filepath.Join(t.TempDir(), "data.bin")
	os.WriteFile(path, testShareContent, 0o600)
	shareFixture := &testShareFixture{t: t, clock: daemonFixture.clock, net: daemonFixture.net, backend: daemonFixture.backend}
	params := shareFixture.params(path, 1, time.Hour)
	reply := &DaemonShareAddReply{}
	daemonFixture.call(t, DaemonMethodShareAdd, params, reply)
	if reply.Token != params.Token || reply.SidecarId != *daemonFixture.backend.sidecar || reply.NetworkLabel != "abcdefghij" {
		t.Fatalf("reply %+v", reply)
	}
	if !daemonFixture.started.daemon.busy() || daemonFixture.started.daemon.Sockets().LiveShareCount() != 1 {
		t.Error("a live share does not keep the daemon up")
	}
	list := &DaemonShareListReply{}
	daemonFixture.call(t, DaemonMethodShareList, nil, list)
	if len(list.Shares) != 1 || list.Shares[0].Token != params.Token || list.Shares[0].RemainingCount != 1 || !list.Shares[0].Serving {
		t.Errorf("list %+v", list.Shares)
	}

	// ur share get's path: a socket session holding the link's sidecar, then the getter's half over it
	link, err := ParseShareLink(FormatShareLink(reply.NetworkLabel, reply.Token, reply.SidecarId, params.Secret))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "got.bin")
	part, err := OpenSharePart(out, link.Token, 4096)
	if err != nil {
		t.Fatal(err)
	}
	client, err := daemonFixture.session(t, link.Address(), &link.SidecarId)
	if err != nil {
		t.Fatal(err)
	}
	if err := part.Get(client.Stream(), link); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, testShareContent) {
		t.Error("the file through the session")
	}
	if daemonFixture.started.daemon.Sockets().LiveShareCount() != 0 || daemonFixture.started.daemon.busy() {
		t.Error("the spent share still keeps the daemon up")
	}
}

// A link's form: <net>:share/<token>#<k>, k the sidecar and the secret, and anything else refused without echoing.
func TestShareLinkForm(t *testing.T) {
	token, secret := NewShareCredentials()
	if !validShareToken(token) || len(token) != 26 || len(secret) != socketShareSecretByteCount {
		t.Fatalf("credentials %q %d", token, len(secret))
	}
	sidecarId := testSocketId("sharer")
	text := FormatShareLink("abcdefghij", token, sidecarId, secret)
	link, err := ParseShareLink(text)
	if err != nil || link.Token != token || link.SidecarId != sidecarId || !bytes.Equal(link.Secret, secret) ||
		link.Address() != "abcdefghij:share/"+token {
		t.Fatalf("%+v %v", link, err)
	}
	address, fragment, _ := strings.Cut(text, "#")
	for _, bad := range []string{
		address,
		"share/" + token + "#" + fragment,
		"abcdefghij:db/primary#" + fragment,
		address + "#" + fragment[:len(fragment)-2],
		address + "#" + fragment + "==",
		"abcdefghij:share/short#" + fragment,
	} {
		if _, err := ParseShareLink(bad); !errors.Is(err, ErrShareLink) {
			t.Errorf("%q: %v", bad, err)
		} else if strings.Contains(err.Error(), fragment[:8]) {
			t.Errorf("the refusal echoes the link")
		}
	}
}

// A part's guards: an existing output is refused, a part with no id beside it is refused, and an id of another share.
func TestSharePartGuards(t *testing.T) {
	directory := t.TempDir()
	token, _ := NewShareCredentials()
	other, _ := NewShareCredentials()
	existing := filepath.Join(directory, "existing")
	os.WriteFile(existing, []byte("there"), 0o600)
	if _, err := OpenSharePart(existing, token, 4096); !errors.Is(err, ErrSharePart) {
		t.Errorf("an existing output: %v", err)
	}
	stray := filepath.Join(directory, "stray")
	os.WriteFile(stray+".part", []byte("stray"), 0o600)
	if _, err := OpenSharePart(stray, token, 4096); !errors.Is(err, ErrSharePart) {
		t.Errorf("a part without its id: %v", err)
	}
	out := filepath.Join(directory, "out")
	part, err := OpenSharePart(out, token, 4096)
	if err != nil {
		t.Fatal(err)
	}
	part.Close()
	if _, err := OpenSharePart(out, other, 4096); !errors.Is(err, ErrSharePart) {
		t.Errorf("another share's part: %v", err)
	}
	again, err := OpenSharePart(out, token, 4096)
	if err != nil || again.GetId() != part.GetId() || again.Offset() != 0 {
		t.Errorf("the same share's part again: %v", err)
	}
	again.Close()
}
