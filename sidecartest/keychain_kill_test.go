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
// same check, which is how it is known to bite. The OS backend is on every leg with files: not js, not the iOS
// network extension's.

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

// How long, in real time, a kill run's waits may take: only a failure's bound, since connect's timers are real (X9).
const testKeychainKillTimeout = 30 * time.Second

// What a call to a dead process's store answers.
var errKeychainKilled = errors.New("the process was killed")

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
// a file reaches its path by truncating it and writing it in two halves, each a step, rather than by the rename.
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

// A temp file whose calls are steps. The mutant keeps what was written to write it in place at Rename.
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
		return self.written.Write(p)
	}
	return self.inner.Write(p)
}

func (self *keychainKillFile) Sync() error {
	if err := self.backend.world.step("fsync a temp file"); err != nil {
		return err
	}
	if self.backend.inPlace {
		return nil
	}
	return self.inner.Sync()
}

func (self *keychainKillFile) Rename(path string) error {
	if !self.backend.inPlace {
		if err := self.backend.world.step("rename to " + path); err != nil {
			return err
		}
		return self.inner.Rename(path)
	}
	// the mutant: the old file is cut and the new one written over it
	osPath := filepath.Join(self.backend.directory, filepath.FromSlash(path))
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
// killed at the writer's step killAt (none when non-positive), and then comes up again on the directory. Answers the
// writer's step count and what broke §5.9's rule.
func runKeychainKill(t *testing.T, killAt int, inPlace bool) (int, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testKeychainKillTimeout)
	defer cancel()
	net := NewNet(t.Context(), nil)
	defer net.Close()
	directory := t.TempDir()
	keyStore := sidecar.NewSidecarMemoryKeyStore()
	world := &keychainKillWorld{barriers: net.Barriers()}
	daemon, err := startKeychainKillSidecar(net, newKeychainKillBackend(t, directory, world, inPlace), keyStore)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Enroll(ctx, net.DefaultNetworkId()); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	identity := daemon.Sidecar().Identity()
	if identity == nil {
		t.Fatal("the enrolled sidecar holds no identity")
	}
	secrets, err := keychainKillSecrets(ctx, daemon)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put("value", []byte("old value")); err != nil {
		t.Fatal(err)
	}

	// the write, as the daemon's actor, killed at its step killAt
	actor := net.Actors().Actor(net.Context(), "daemon")
	world.arm(actor, killAt)
	run := net.Barriers().Start(actor, func() error {
		return secrets.Put("value", []byte("new value"))
	})
	select {
	case <-run.Ended():
	case <-ctx.Done():
		t.Fatalf("the write at kill step %d never ended", killAt)
	}
	stepCount, trace, died := world.counted()
	if !died && run.Err() != nil {
		t.Fatalf("an unkilled write failed: %v", run.Err())
	}
	if 0 < killAt && killAt <= stepCount && !died {
		t.Fatalf("no kill at step %d of %d", killAt, stepCount)
	}
	// the dead process's parked goroutine lets go of what it held, and the process stops; nothing it does now reaches
	// the disk
	net.Barriers().Reap()
	daemon.stop()

	problems := []string{}
	// the keychain opens, read by an instance of its own before any sidecar starts on it: a keychain that fails AEAD
	// leaves a sidecar Locked, the state it starts in, so only its store says so at once
	if err := openKeychainKillState(ctx, t, directory, keyStore, identity.NetworkId, inPlace, net.Barriers()); err != nil {
		return stepCount, append(problems, fmt.Sprintf("after %q: the keychain does not open: %v", trace, err))
	}
	restarted, err := startKeychainKillSidecar(net, newKeychainKillBackend(t, directory, &keychainKillWorld{barriers: net.Barriers()}, inPlace), keyStore)
	if err != nil {
		return stepCount, append(problems, fmt.Sprintf("after %q: the sidecar did not start again: %v", trace, err))
	}
	defer restarted.Close()
	if err := restarted.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		return stepCount, append(problems, fmt.Sprintf("after %q: %v", trace, err))
	}
	if reopened := restarted.Sidecar().Identity(); reopened == nil || reopened.SidecarId != identity.SidecarId || reopened.ClientId != identity.ClientId {
		problems = append(problems, fmt.Sprintf("after %q: the identity is %+v, not the one enrolled", trace, reopened))
	}
	reopenedSecrets, err := keychainKillSecrets(ctx, restarted)
	if err != nil {
		return stepCount, append(problems, fmt.Sprintf("after %q: %v", trace, err))
	}
	value, err := reopenedSecrets.Get("value")
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("after %q: the keychain opens without the value: %v", trace, err))
	case string(value) != "old value" && string(value) != "new value":
		problems = append(problems, fmt.Sprintf("after %q: the keychain holds %q", trace, value))
	case !died && string(value) != "new value":
		problems = append(problems, fmt.Sprintf("after %q: a write that returned was lost", trace))
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

// Every kill point of one keychain write, and what broke the rule at each.
func runKeychainKills(t *testing.T, inPlace bool) []string {
	t.Helper()
	stepCount, problems := runKeychainKill(t, 0, inPlace)
	if stepCount < 4 {
		t.Fatalf("a keychain write of %d steps: a temp file, its fsync, its rename and the directory's fsync are each one", stepCount)
	}
	for killAt := 1; killAt <= stepCount; killAt += 1 {
		_, killProblems := runKeychainKill(t, killAt, inPlace)
		problems = append(problems, killProblems...)
	}
	return problems
}

// A kill at each step of a keychain write opens the keychain at its old or new state, with the identity in it.
func TestKeychainKilledAtEveryStepOpensOldOrNew(t *testing.T) {
	for _, problem := range runKeychainKills(t, false) {
		t.Error(problem)
	}
}

// The same kills on a store that writes keychain.ur in place leave a keychain that is neither: one that no longer opens,
// cut between its truncation and its second half.
func TestKeychainKillCatchesAnInPlaceWrite(t *testing.T) {
	torn := 0
	for _, problem := range runKeychainKills(t, true) {
		if strings.Contains(problem, "the keychain does not open") || strings.Contains(problem, "the keychain holds") {
			torn += 1
		}
	}
	if torn == 0 {
		t.Error("a write in place, killed at every step, left no keychain that failed to open")
	}
}
