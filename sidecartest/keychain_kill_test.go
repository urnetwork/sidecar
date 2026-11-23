//go:build !js && !ios_extension

// §22.8's kills mid-keychain write (TEST-M2-16; §5.9): a running Sidecar whose state is files on disk, NewSidecarOsBackend's,
// is killed at each step a keychain.ur write takes, CreateTemp, each Write of the sealed file, its fsync, its rename and
// the directory's fsync, and comes up again on what the disk holds, where its keychain opens at the old state or the new
// one, never between, and never without the identity it enrolled with. The write is a component's SidecarSecrets.Put,
// run as an actor of the Net's barrier driver so the kill lands on its goroutine between the real file operations:
// the store seam counts only that actor's calls, and the kill parks it there as a dead process's thread would stop, while
// every later call of the process's, from any goroutine, fails, since a dead process writes nothing more. A process kill
// keeps what reached the file system, so a rename that returned survives; the power cuts that lose an unsynced rename are
// the root's keys_crash_test.go.
//
// A mutant backend that writes the file in place, truncating keychain.ur and writing it in two halves, must fail the
// same check, which is how it is known to bite. It writes keychain.ur alone in place and every other file as the OS
// backend does, so what a kill tears is keychain.ur: another goroutine's in-place write of a subprotocol file, cut by
// the kill, would keep the restarted sidecar's generation from starting, which says nothing of the keychain. The OS
// backend is on every leg with files: not js, not the iOS network extension's.
//
// A run's waits are in real time, since connect's timers are real (X9), and each is on what it waits for: a sidecar's
// state, the write's end, a component's attach, a sidecar's close. A loaded machine slows every one, so only the
// test's own deadline bounds them, less a share of the time left that a failure keeps for its report
// (keychainKillTestSettings): a run that never comes up fails saying at which kill step and in which phase it
// stopped, how long each phase took, the state its sidecar was last in, the state events it raised and what it
// logged.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// What bounds a kill test's waits. Only defaultKeychainKillTestSettings sets it.
type keychainKillTestSettings struct {
	// Of the time left before the test binary's deadline as a test starts, the share its waits leave unused, so a run
	// that never comes up fails with what it last saw, and closes what it started, before the binary's timeout ends
	// the test with a goroutine dump that names neither. A share of the test's own deadline rather than a fixed time,
	// since only -timeout says how long a loaded machine may take. Under -timeout 0 nothing bounds the waits.
	ReportShare float64
}

func defaultKeychainKillTestSettings() *keychainKillTestSettings {
	return &keychainKillTestSettings{
		ReportShare: 0.1,
	}
}

// The context a kill test's waits share: t's, which ends settings.ReportShare of the time left before t's deadline.
func keychainKillContext(t *testing.T, settings *keychainKillTestSettings) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		return context.WithCancel(t.Context())
	}
	report := time.Duration(float64(time.Until(deadline)) * settings.ReportShare)
	return context.WithDeadline(t.Context(), deadline.Add(-report))
}

// What a call to a dead process's store answers.
var errKeychainKilled = errors.New("the process was killed")

// The one file the mutant writes in place, as state_dir.go names it.
const keychainKillRecordsName = "keychain.ur"

// Where a kill run is, for the failure that stops it: its kill step, the writer's steps once the write ended, each
// phase it went through and how long it took, every state event its sidecars raised, as they arrived, and what they
// logged of their own. Safe for concurrent use: the sidecars' event callbacks add to it.
type keychainKillProgress struct {
	// non-positive: no kill
	killAt int
	start  time.Time
	// the run's, whose capture holds every line its sidecars logged
	net *Net

	stateLock  sync.Mutex
	trace      []string
	phase      string
	phaseStart time.Time
	// "<phase> <duration>", each phase ended
	phases []string
	// "<sidecar> <state> (<reason>) at <time into the run>"
	states []string
}

func newKeychainKillProgress(killAt int, net *Net) *keychainKillProgress {
	now := time.Now()
	return &keychainKillProgress{
		killAt:     killAt,
		start:      now,
		net:        net,
		phase:      "making the store",
		phaseStart: now,
	}
}

// Ends the phase the run is in and starts phase.
func (self *keychainKillProgress) enter(phase string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := time.Now()
	self.phases = append(self.phases, fmt.Sprintf("%s %v", self.phase, now.Sub(self.phaseStart).Round(time.Millisecond)))
	self.phase = phase
	self.phaseStart = now
}

// Records the writer's steps, once its write ended or died.
func (self *keychainKillProgress) wrote(trace []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.trace = trace
}

// Records each state event testSidecar raises from here on, under name, until the answer is called.
func (self *keychainKillProgress) follow(name string, testSidecar *TestSidecar) func() {
	return testSidecar.Sidecar().AddEventCallback(func(event sidecar.SidecarEvent) {
		if event.Kind != sidecar.SidecarEventState {
			return
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.states = append(self.states, fmt.Sprintf("%s %s (%s) at %v", name, event.State, event.Reason,
			time.Since(self.start).Round(time.Millisecond)))
	})
}

// The run's place, which begins every failure it reports: the kill and the writer's steps, then the phase it stopped
// in and how long it had waited there, the phases before it, the state events seen, and the core's and the
// instances' own log lines, which say why a keychain did not open or a generation did not start.
func (self *keychainKillProgress) where() string {
	logLines := []string{}
	for _, item := range self.net.capture.snapshot() {
		if item.Class == PrivacyClassLog && (bytes.HasPrefix(item.Body, []byte("[sidecar]")) || bytes.HasPrefix(item.Body, []byte("[keys]"))) {
			logLines = append(logLines, string(item.Body))
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kill := "with no kill"
	if 0 < self.killAt {
		kill = fmt.Sprintf("killed at step %d", self.killAt)
	}
	if 0 < len(self.trace) {
		kill += fmt.Sprintf(" after %q", self.trace)
	}
	now := time.Now()
	return fmt.Sprintf("%s, %s for %v, %v into the run (phases before: %s; state events: %s; logged: %q)", kill,
		self.phase, now.Sub(self.phaseStart).Round(time.Millisecond), now.Sub(self.start).Round(time.Millisecond),
		strings.Join(self.phases, ", "), strings.Join(self.states, ", "), logLines)
}

// Waits until testSidecar is in state, or ctx ends: then answers the state it was last in, beside its instance's.
func awaitKeychainKillState(ctx context.Context, testSidecar *TestSidecar, state sidecar.SidecarState) error {
	err := testSidecar.AwaitState(ctx, state)
	if err == nil {
		return nil
	}
	instanceState, _ := testSidecar.Instance().State()
	return fmt.Errorf("%w; its instance is %s", err, instanceState)
}

// Closes testSidecar, waiting under ctx for its generation and components to end, so none of it runs on beside the
// next process on its directory: TestSidecar.stop's own wait is NetSettings.ClientCloseTimeout, past which it answers
// with the Sidecar still closing.
func closeKeychainKillSidecar(ctx context.Context, testSidecar *TestSidecar) error {
	closeErr := testSidecar.Sidecar().CloseAndWait(ctx)
	stopErr := testSidecar.stop()
	if closeErr != nil {
		return errors.Join(fmt.Errorf("the sidecar did not close: %w", closeErr), stopErr)
	}
	return stopErr
}

// One process's view of its medium: alive until the writer's step killAt, then dead for every caller. Safe for
// concurrent use.
type keychainKillWorld struct {
	barriers *BarrierDriver
	// the actor whose calls count, and whose goroutine the kill parks
	actor *Actor

	stateLock sync.Mutex
	// non-positive: no kill
	killAt int
	steps  int
	dead   bool
	trace  []string
}

// Counts a step of the writer's, killing at the chosen one: the call never returns, and nothing after it reaches the
// medium. A dead process's calls fail, and other goroutines' calls pass uncounted.
func (self *keychainKillWorld) step(name string) error {
	counted := false
	kill := false
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.dead {
			return errKeychainKilled
		}
		if self.actor == nil || self.barriers.CurrentActor() != self.actor.Name() {
			return nil
		}
		counted = true
		self.steps += 1
		self.trace = append(self.trace, name)
		if self.steps == self.killAt {
			self.dead = true
			kill = true
		}
		return nil
	}()
	if err != nil {
		return err
	}
	if counted && kill {
		self.actor.crash()
	}
	return nil
}

// Whether the process is dead, for a read.
func (self *keychainKillWorld) refuse() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.dead {
		return errKeychainKilled
	}
	return nil
}

// The writer's steps so far and their names.
func (self *keychainKillWorld) counted() (int, []string, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.steps, append([]string{}, self.trace...), self.dead
}

// Starts counting actor's steps, killing at killAt.
func (self *keychainKillWorld) arm(actor *Actor, killAt int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.actor = actor
	self.killAt = killAt
	self.steps = 0
	self.trace = nil
}

// A SidecarStoreBackend over the OS backend at directory, each write's call a step of world's. With inPlace, the mutant:
// keychain.ur reaches its path by truncating it and writing it in two halves, each a step, rather than by the rename,
// and every other file by the rename.
type keychainKillBackend struct {
	inner     sidecar.SidecarStoreBackend
	world     *keychainKillWorld
	directory string
	inPlace   bool
}

func newKeychainKillBackend(t *testing.T, directory string, world *keychainKillWorld, inPlace bool) *keychainKillBackend {
	t.Helper()
	inner, err := sidecar.NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	return &keychainKillBackend{inner: inner, world: world, directory: directory, inPlace: inPlace}
}

func (self *keychainKillBackend) Open(path string) (io.ReadCloser, error) {
	if err := self.world.refuse(); err != nil {
		return nil, err
	}
	return self.inner.Open(path)
}

func (self *keychainKillBackend) CreateTemp() (sidecar.SidecarStoreBackendFile, error) {
	if err := self.world.step("create a temp file"); err != nil {
		return nil, err
	}
	file, err := self.inner.CreateTemp()
	if err != nil {
		return nil, err
	}
	return &keychainKillFile{backend: self, inner: file}, nil
}

func (self *keychainKillBackend) SyncDirectory(path string) error {
	if err := self.world.step("fsync the directory of " + path); err != nil {
		return err
	}
	return self.inner.SyncDirectory(path)
}

func (self *keychainKillBackend) Remove(path string) error {
	if err := self.world.step("remove " + path); err != nil {
		return err
	}
	return self.inner.Remove(path)
}

func (self *keychainKillBackend) List(prefix string) ([]sidecar.SidecarStoreEntry, error) {
	if err := self.world.refuse(); err != nil {
		return nil, err
	}
	return self.inner.List(prefix)
}

func (self *keychainKillBackend) RemoveTemp() error {
	if err := self.world.refuse(); err != nil {
		return err
	}
	return self.inner.RemoveTemp()
}

func (self *keychainKillBackend) OpenAppend(path string) (sidecar.SidecarStoreBackendAppendFile, bool, error) {
	if err := self.world.refuse(); err != nil {
		return nil, false, err
	}
	file, made, err := self.inner.OpenAppend(path)
	if err != nil {
		return nil, false, err
	}
	return &keychainKillAppendFile{world: self.world, inner: file}, made, nil
}

// A temp file whose calls are steps. The mutant also keeps what was written, since only Rename knows whether the
// file is keychain.ur, which it writes in place.
type keychainKillFile struct {
	backend *keychainKillBackend
	inner   sidecar.SidecarStoreBackendFile
	written bytes.Buffer
}

func (self *keychainKillFile) Write(p []byte) (int, error) {
	if err := self.backend.world.step("write a temp file"); err != nil {
		return 0, err
	}
	if self.backend.inPlace {
		self.written.Write(p)
	}
	return self.inner.Write(p)
}

func (self *keychainKillFile) Sync() error {
	if err := self.backend.world.step("fsync a temp file"); err != nil {
		return err
	}
	return self.inner.Sync()
}

func (self *keychainKillFile) Rename(path string) error {
	osPath := filepath.Join(self.backend.directory, filepath.FromSlash(path))
	if !self.backend.inPlace || filepath.Base(osPath) != keychainKillRecordsName {
		if err := self.backend.world.step("rename to " + path); err != nil {
			return err
		}
		return self.inner.Rename(path)
	}
	// the mutant: the old keychain.ur is cut and the new one written over it
	if err := os.MkdirAll(filepath.Dir(osPath), 0o700); err != nil {
		return err
	}
	content := self.written.Bytes()
	half := len(content) / 2
	if err := self.backend.world.step("truncate " + path); err != nil {
		return err
	}
	file, err := os.OpenFile(osPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := self.backend.world.step("write the first half of " + path); err != nil {
		return err
	}
	if _, err := file.Write(content[:half]); err != nil {
		return err
	}
	if err := self.backend.world.step("write the second half of " + path); err != nil {
		return err
	}
	if _, err := file.Write(content[half:]); err != nil {
		return err
	}
	self.inner.Discard()
	return file.Sync()
}

func (self *keychainKillFile) Discard() error {
	return self.inner.Discard()
}

// A log appender of the process's, which fails once it is dead.
type keychainKillAppendFile struct {
	world *keychainKillWorld
	inner sidecar.SidecarStoreBackendAppendFile
}

func (self *keychainKillAppendFile) Write(p []byte) (int, error) {
	if err := self.world.refuse(); err != nil {
		return 0, err
	}
	return self.inner.Write(p)
}

func (self *keychainKillAppendFile) Size() (int64, error) {
	return self.inner.Size()
}

func (self *keychainKillAppendFile) Truncate(byteCount int64) error {
	if err := self.world.refuse(); err != nil {
		return err
	}
	return self.inner.Truncate(byteCount)
}

func (self *keychainKillAppendFile) Sync() error {
	if err := self.world.refuse(); err != nil {
		return err
	}
	return self.inner.Sync()
}

func (self *keychainKillAppendFile) Close() error {
	return self.inner.Close()
}

// A component holding nothing but its view of the keychain, handed over at each attach.
type keychainKillComponent struct {
	secrets chan sidecar.SidecarSecrets
}

func (self *keychainKillComponent) Name() string {
	return "keychain-kill"
}

func (self *keychainKillComponent) Attach(env *sidecar.SidecarEnv) error {
	select {
	case self.secrets <- env.Secrets:
	default:
	}
	return nil
}

func (self *keychainKillComponent) Close() {
}

// A sidecar of net's on backend and keyStore, started on the durable state there as StartSidecar starts one in memory.
func startKeychainKillSidecar(net *Net, backend sidecar.SidecarStoreBackend, keyStore sidecar.SidecarKeyStore) (*TestSidecar, error) {
	api, err := net.Api()
	if err != nil {
		return nil, err
	}
	settings := sidecar.DefaultSidecarSettings()
	platform := newNetSidecarPlatform(net, "daemon", api)
	net.fillTestSidecarSettings("daemon", settings, api, platform)
	testSidecar := &TestSidecar{
		Name:     "daemon",
		Settings: settings,
		Api:      api,
		net:      net,
		platform: platform,
		backend:  backend,
		keyStore: keyStore,
	}
	if err := testSidecar.start(); err != nil {
		return nil, err
	}
	net.stateLock.Lock()
	defer net.stateLock.Unlock()
	net.testSidecars = append(net.testSidecars, testSidecar)
	return testSidecar, nil
}

// The keychain view of a running sidecar, once its component attaches.
func keychainKillSecrets(ctx context.Context, testSidecar *TestSidecar) (sidecar.SidecarSecrets, error) {
	component := &keychainKillComponent{secrets: make(chan sidecar.SidecarSecrets, 1)}
	if _, err := testSidecar.Sidecar().AddComponent(component); err != nil {
		return nil, err
	}
	select {
	case secrets := <-component.secrets:
		return secrets, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("the component never attached: %w", ctx.Err())
	}
}

// One run: a sidecar enrolled on a fresh directory, which writes the old value, then the new one with its process
// killed at the writer's step killAt (none when non-positive), and then comes up again on the directory. Every wait
// ends with ctx, the test's (keychainKillContext). Answers the writer's step count and what broke §5.9's rule.
func runKeychainKill(ctx context.Context, t *testing.T, killAt int, inPlace bool) (int, []string) {
	t.Helper()
	net := NewNet(t.Context(), nil)
	defer net.Close()
	progress := newKeychainKillProgress(killAt, net)
	directory := t.TempDir()
	keyStore := sidecar.NewSidecarMemoryKeyStore()
	world := &keychainKillWorld{barriers: net.Barriers()}
	progress.enter("starting the sidecar")
	daemon, err := startKeychainKillSidecar(net, newKeychainKillBackend(t, directory, world, inPlace), keyStore)
	if err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}
	defer progress.follow("writer", daemon)()
	progress.enter("waiting for the sidecar to be unenrolled")
	if err := awaitKeychainKillState(ctx, daemon, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}
	progress.enter("enrolling")
	if err := daemon.Enroll(ctx, net.DefaultNetworkId()); err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}
	progress.enter("waiting for the enrolled sidecar to be online")
	if err := awaitKeychainKillState(ctx, daemon, sidecar.SidecarStateOnline); err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}
	identity := daemon.Sidecar().Identity()
	if identity == nil {
		t.Fatalf("%s: the enrolled sidecar holds no identity", progress.where())
	}
	progress.enter("waiting for the sidecar's component to attach")
	secrets, err := keychainKillSecrets(ctx, daemon)
	if err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}
	progress.enter("writing the old value")
	if err := secrets.Put("value", []byte("old value")); err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}

	// the write, as the daemon's actor, killed at its step killAt
	actor := net.Actors().Actor(net.Context(), "daemon")
	world.arm(actor, killAt)
	progress.enter("writing the new value")
	run := net.Barriers().Start(actor, func() error {
		return secrets.Put("value", []byte("new value"))
	})
	select {
	case <-run.Ended():
	case <-ctx.Done():
		stepCount, trace, _ := world.counted()
		progress.wrote(trace)
		t.Fatalf("%s: the write never ended, %d steps in: %v", progress.where(), stepCount, ctx.Err())
	}
	stepCount, trace, died := world.counted()
	progress.wrote(trace)
	if !died && run.Err() != nil {
		t.Fatalf("%s: an unkilled write failed: %v", progress.where(), run.Err())
	}
	if 0 < killAt && killAt <= stepCount && !died {
		t.Fatalf("%s: no kill at step %d of %d", progress.where(), killAt, stepCount)
	}
	// the dead process's parked goroutine lets go of what it held, and the process stops, wholly, before another
	// starts on its directory; nothing it does now reaches the disk
	net.Barriers().Reap()
	progress.enter("waiting for the writing sidecar to close")
	if err := closeKeychainKillSidecar(ctx, daemon); err != nil {
		t.Fatalf("%s: %v", progress.where(), err)
	}

	problems := []string{}
	// the keychain opens, read by an instance of its own before any sidecar starts on it: a keychain that fails AEAD
	// leaves a sidecar Locked, the state it starts in, so only its store says so at once
	progress.enter("opening the keychain")
	if err := openKeychainKillState(ctx, t, directory, keyStore, identity.NetworkId, inPlace, net.Barriers()); err != nil {
		return stepCount, append(problems, fmt.Sprintf("%s: the keychain does not open: %v", progress.where(), err))
	}
	progress.enter("starting the sidecar again")
	restarted, err := startKeychainKillSidecar(net, newKeychainKillBackend(t, directory, &keychainKillWorld{barriers: net.Barriers()}, inPlace), keyStore)
	if err != nil {
		return stepCount, append(problems, fmt.Sprintf("%s: the sidecar did not start again: %v", progress.where(), err))
	}
	defer restarted.Close()
	defer progress.follow("restarted", restarted)()
	// its keychain opened above, so the Locked it starts in is one it leaves once its run loop reads that keychain,
	// however long a loaded machine takes to run it
	progress.enter("waiting for the restarted sidecar to be online")
	if err := awaitKeychainKillState(ctx, restarted, sidecar.SidecarStateOnline); err != nil {
		return stepCount, append(problems, fmt.Sprintf("%s: %v", progress.where(), err))
	}
	if reopened := restarted.Sidecar().Identity(); reopened == nil || reopened.SidecarId != identity.SidecarId || reopened.ClientId != identity.ClientId {
		problems = append(problems, fmt.Sprintf("%s: the identity is %+v, not the one enrolled", progress.where(), reopened))
	}
	progress.enter("waiting for the restarted sidecar's component to attach")
	reopenedSecrets, err := keychainKillSecrets(ctx, restarted)
	if err != nil {
		return stepCount, append(problems, fmt.Sprintf("%s: %v", progress.where(), err))
	}
	progress.enter("reading the value")
	value, err := reopenedSecrets.Get("value")
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("%s: the keychain opens without the value: %v", progress.where(), err))
	case string(value) != "old value" && string(value) != "new value":
		problems = append(problems, fmt.Sprintf("%s: the keychain holds %q", progress.where(), value))
	case !died && string(value) != "new value":
		problems = append(problems, fmt.Sprintf("%s: a write that returned was lost", progress.where()))
	}
	progress.enter("waiting for the restarted sidecar to close")
	if err := closeKeychainKillSidecar(ctx, restarted); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", progress.where(), err))
	}
	return stepCount, problems
}

// Opens directory's instance as a restart does and reads networkId's sealed store, which loads keychain.wrap and
// keychain.ur: nil when both open.
func openKeychainKillState(ctx context.Context, t *testing.T, directory string, keyStore sidecar.SidecarKeyStore, networkId sidecar.Id, inPlace bool, barriers *BarrierDriver) error {
	t.Helper()
	settings := sidecar.DefaultSidecarSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	instance, err := sidecar.NewSidecarInstance(ctx, &sidecar.SidecarInstanceArgs{
		Backend:  newKeychainKillBackend(t, directory, &keychainKillWorld{barriers: barriers}, inPlace),
		KeyStore: keyStore,
		Settings: settings,
	})
	if err != nil {
		return err
	}
	defer instance.Close()
	if err := instance.Unlock(nil); err != nil {
		return err
	}
	store, err := instance.Store(&networkId).Directory("keychain-kill", "keychain-kill")
	if err != nil {
		return err
	}
	_, err = store.List("")
	return err
}

// Every kill point of one keychain write, what broke the rule at each given to found as its run ends, so a later
// run's fatal failure loses none. The runs' waits share one context (keychainKillContext): once it has ended, the
// kill steps not run are one problem more, rather than each failing at its first wait.
func runKeychainKills(t *testing.T, inPlace bool, found func(problem string)) {
	t.Helper()
	ctx, cancel := keychainKillContext(t, defaultKeychainKillTestSettings())
	defer cancel()
	stepCount, problems := runKeychainKill(ctx, t, 0, inPlace)
	for _, problem := range problems {
		found(problem)
	}
	if stepCount < 4 {
		t.Fatalf("a keychain write of %d steps: a temp file, its fsync, its rename and the directory's fsync are each one", stepCount)
	}
	for killAt := 1; killAt <= stepCount; killAt += 1 {
		if err := ctx.Err(); err != nil {
			found(fmt.Sprintf("kill steps %d to %d of %d did not run: %v", killAt, stepCount, stepCount, err))
			return
		}
		_, killProblems := runKeychainKill(ctx, t, killAt, inPlace)
		for _, problem := range killProblems {
			found(problem)
		}
	}
}

// A kill at each step of a keychain write opens the keychain at its old or new state, with the identity in it.
func TestKeychainKilledAtEveryStepOpensOldOrNew(t *testing.T) {
	runKeychainKills(t, false, func(problem string) {
		t.Error(problem)
	})
}

// The same kills on a store that writes keychain.ur in place leave a keychain that is neither: one that no longer opens,
// cut between its truncation and its second half. Its other problems are a mutant's and fail nothing, but when no
// keychain tore they say what the kills found instead.
func TestKeychainKillCatchesAnInPlaceWrite(t *testing.T) {
	torn := 0
	problems := []string{}
	runKeychainKills(t, true, func(problem string) {
		if strings.Contains(problem, "the keychain does not open") || strings.Contains(problem, "the keychain holds") {
			torn += 1
		}
		problems = append(problems, problem)
	})
	if torn == 0 {
		t.Errorf("a write in place, killed at every step, left no keychain that failed to open; the kills found %q", problems)
	}
}

// The mutant's write of path as the store writes a file, CreateTemp, two Writes, Sync, Rename and SyncDirectory, of
// its old content and then its new with the writer killed at its step killAt (none when non-positive): what path
// holds after, and the writer's steps.
func runKeychainKillMutantWrite(ctx context.Context, t *testing.T, path string, killAt int) ([]byte, []string) {
	t.Helper()
	net := NewNet(t.Context(), nil)
	defer net.Close()
	directory := t.TempDir()
	world := &keychainKillWorld{barriers: net.Barriers()}
	backend := newKeychainKillBackend(t, directory, world, true)
	write := func(content string) error {
		file, err := backend.CreateTemp()
		if err != nil {
			return err
		}
		defer file.Discard()
		half := len(content) / 2
		if _, err := file.Write([]byte(content[:half])); err != nil {
			return err
		}
		if _, err := file.Write([]byte(content[half:])); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Rename(path); err != nil {
			return err
		}
		return backend.SyncDirectory(path)
	}
	if err := write("the old content"); err != nil {
		t.Fatal(err)
	}
	actor := net.Actors().Actor(net.Context(), "writer")
	world.arm(actor, killAt)
	run := net.Barriers().Start(actor, func() error {
		return write("the new content, a longer one")
	})
	select {
	case <-run.Ended():
	case <-ctx.Done():
		t.Fatalf("the write of %s killed at step %d never ended: %v", path, killAt, ctx.Err())
	}
	_, trace, died := world.counted()
	if !died && run.Err() != nil {
		t.Fatalf("an unkilled write of %s failed: %v", path, run.Err())
	}
	// the dead writer's parked goroutine leaves, discarding its temp file, which path never was
	net.Barriers().Reap()
	content, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("after %q: %v", trace, err)
	}
	return content, trace
}

// The mutant writes keychain.ur alone in place: a kill at each step of another file's write leaves that file at its old
// content or its new, as the OS backend's rename does, while some kill leaves keychain.ur at neither. A mutant that
// wrote every file in place tore what another goroutine was writing when the kill came, a subprotocol file among
// them, which kept the restarted sidecar's generation from starting where keychain.ur stayed whole.
func TestKeychainKillMutantWritesOnlyKeychainInPlace(t *testing.T) {
	ctx, cancel := keychainKillContext(t, defaultKeychainKillTestSettings())
	defer cancel()
	for _, c := range []struct {
		path  string
		tears bool
	}{
		{path: "net/n/subprotocol/state", tears: false},
		{path: "net/n/" + keychainKillRecordsName, tears: true},
	} {
		content, trace := runKeychainKillMutantWrite(ctx, t, c.path, 0)
		if string(content) != "the new content, a longer one" {
			t.Errorf("an unkilled write of %s left %q", c.path, content)
		}
		torn := 0
		for killAt := 1; killAt <= len(trace); killAt += 1 {
			content, killTrace := runKeychainKillMutantWrite(ctx, t, c.path, killAt)
			if string(content) == "the old content" || string(content) == "the new content, a longer one" {
				continue
			}
			torn += 1
			if !c.tears {
				t.Errorf("%s killed at step %d after %q holds %q, neither its old content nor its new", c.path, killAt, killTrace, content)
			}
		}
		if c.tears && torn == 0 {
			t.Errorf("%s, written in place and killed at each of its steps %q, never tore", c.path, trace)
		}
	}
}
