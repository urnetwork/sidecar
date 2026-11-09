//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// The connect id of an id, as a client's settings carry it.
func connectIdOf(id Id) connect.Id {
	return connect.Id(id)
}

// A logger that keeps every line, safe for concurrent use.
type testLineLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testLineLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testLineLogger) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *testLineLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testLineLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testLineLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testLineLogger) V(level int32) Verbose {
	return testLineVerbose{log: self}
}

func (self *testLineLogger) text() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

type testLineVerbose struct {
	log *testLineLogger
}

func (self testLineVerbose) Enabled() bool {
	return true
}

func (self testLineVerbose) Info(args ...any) {
	self.log.Info(args...)
}

func (self testLineVerbose) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// api's enrollment routes in memory: enroll mints a client of networkId, bind verifies the binding's signatures and
// generation, and remove-client records what it removed. What a test sets changes the answers.
type testEnrollApi struct {
	t         *testing.T
	networkId Id

	stateLock sync.Mutex
	// answers
	adminRefused  bool
	enrollRefusal *testApiRefusal
	bindRefusal   *testApiRefusal
	onBind        func()
	generationsBy map[Id]int64
	// what it saw
	paths    []string
	bodies   [][]byte
	bearers  []string
	clients  []Id
	removed  []Id
	removers []string
}

// A refusal: its status and coded body.
type testApiRefusal struct {
	status int
	code   string
}

func newTestEnrollApi(t *testing.T) *testEnrollApi {
	return &testEnrollApi{t: t, networkId: NewId(), adminRefused: true, generationsBy: map[Id]int64{}}
}

// A JSON answer.
func testApiAnswer(status int, value any) (*http.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (self *testEnrollApi) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
		request.Body.Close()
	}
	bearer := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paths = append(self.paths, request.URL.Path)
	self.bodies = append(self.bodies, body)
	self.bearers = append(self.bearers, bearer)
	switch request.URL.Path {
	case "/network/enroll":
		if self.enrollRefusal != nil {
			return testApiAnswer(self.enrollRefusal.status, map[string]string{"error": "synthetic refusal", "code": self.enrollRefusal.code})
		}
		clientId := NewId()
		self.clients = append(self.clients, clientId)
		byJwt := testClientTokenOf(self.networkId, clientId)
		return testApiAnswer(http.StatusOK, map[string]any{
			"by_client_jwt":  byJwt,
			"client_id":      clientId,
			"approval_state": "approved",
			"admin_refused":  self.adminRefused,
		})
	case "/sidecar/bind":
		if self.onBind != nil {
			self.onBind()
		}
		if self.bindRefusal != nil {
			return testApiAnswer(self.bindRefusal.status, map[string]string{"error": "synthetic refusal", "code": self.bindRefusal.code})
		}
		wire := &struct {
			Binding []byte `json:"binding"`
		}{}
		if err := json.Unmarshal(body, wire); err != nil {
			return testApiAnswer(http.StatusBadRequest, map[string]string{"error": "bad", "code": "binding_invalid"})
		}
		binding, err := VerifySidecarIdentityBinding(wire.Binding)
		if err != nil || binding.NetworkId != self.networkId {
			return testApiAnswer(http.StatusBadRequest, map[string]string{"error": "bad", "code": "binding_invalid"})
		}
		if binding.Generation != self.generationsBy[binding.SidecarId]+1 {
			return testApiAnswer(http.StatusConflict, map[string]string{"error": "bad", "code": "generation_conflict"})
		}
		self.generationsBy[binding.SidecarId] = binding.Generation
		return testApiAnswer(http.StatusOK, map[string]int64{"generation": binding.Generation})
	case "/network/remove-client":
		wire := &struct {
			ClientId Id `json:"client_id"`
		}{}
		json.Unmarshal(body, wire)
		self.removed = append(self.removed, wire.ClientId)
		self.removers = append(self.removers, bearer)
		return testApiAnswer(http.StatusOK, map[string]any{})
	}
	return testApiAnswer(http.StatusNotFound, map[string]string{"error": "not found"})
}

// The paths requested, in order.
func (self *testEnrollApi) requestedPaths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.paths...)
}

// Every byte any request carried: bodies, bearers and paths.
func (self *testEnrollApi) everythingSent() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var sent strings.Builder
	for i := range self.paths {
		sent.WriteString(self.paths[i])
		sent.WriteString(self.bearers[i])
		sent.Write(self.bodies[i])
	}
	return sent.String()
}

// One enrollment's world: an open instance, a running unenrolled Sidecar whose api is the fake, and its platform.
type testEnrollWorld struct {
	instance *SidecarInstance
	backend  SidecarStoreBackend
	api      *testEnrollApi
	platform *testSidecarPlatform
	sidecar  *Sidecar
	log      *testLineLogger
}

func newTestEnrollWorld(t *testing.T) *testEnrollWorld {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	return newTestEnrollWorldOn(t, backend)
}

func newTestEnrollWorldOn(t *testing.T, backend SidecarStoreBackend) *testEnrollWorld {
	t.Helper()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	world := &testEnrollWorld{
		instance: instance,
		backend:  backend,
		api:      newTestEnrollApi(t),
		platform: newTestSidecarPlatform(),
		log:      &testLineLogger{},
	}
	settings := testSidecarSettings(world.platform)
	settings.Log = world.log
	world.sidecar = newTestRunningSidecar(t, instance, nil, settings)
	world.sidecar.sidecarApi.setTransport(world.api)
	world.sidecar.hostStores = func() []SidecarHostCredentialStore { return nil }
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 0))
	return world
}

// An enrollment with a plain auth key.
func (self *testEnrollWorld) enroll(ctx context.Context) error {
	return self.sidecar.Enroll(ctx, &SidecarEnrollCredential{AuthKey: testAuthKeyBearer()})
}

// An enrollment starts the new client's generation: the request sends the bearer with both marks and no egress,
// the binding names the new client at generation 1, and the keychain and sidecar.json hold the result.
func TestEnrollRunsTheNewGeneration(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	opened := world.platform.awaitOpened(t, 1)
	identity := world.sidecar.currentIdentity()
	if identity == nil || identity.NetworkId != world.api.networkId || opened.args.ClientId != connectIdOf(identity.ClientId) {
		t.Fatalf("identity %+v, client %s", identity, opened.args.ClientId)
	}
	if paths := world.api.requestedPaths(); strings.Join(paths, " ") != "/network/enroll /sidecar/bind" {
		t.Errorf("requests %v", paths)
	}
	enrollBody := map[string]any{}
	json.Unmarshal(world.api.bodies[0], &enrollBody)
	if enrollBody["admin_refused"] != true || enrollBody["strict_exp"] != true || enrollBody["declares_no_egress"] != true ||
		enrollBody["auth_key"] != testAuthKeyBearer() {
		t.Errorf("enroll body %v", enrollBody)
	}
	records := world.instance.Networks()
	if len(records) != 1 || records[0].NetworkId != world.api.networkId || records[0].SidecarId != identity.SidecarId ||
		records[0].ClientId != identity.ClientId {
		t.Errorf("sidecar.json records %+v", records)
	}
	secrets := world.instance.secrets(world.api.networkId, sidecarCoreSecretsNamespace)
	readerKey, err := secrets.Get(sidecarReaderKeyRecordName)
	if err != nil || len(readerKey) != 32 {
		t.Errorf("the first ReaderKey: %v", err)
	}
}

// D-CORE-7, §22.5: without admin_refused in the reply, nothing is kept, no binding is posted, and the new client is
// removed with its own token.
func TestEnrollFailsClosedWithoutAdminRefused(t *testing.T) {
	world := newTestEnrollWorld(t)
	world.api.adminRefused = false
	before := backendSnapshot(t, world.backend)
	err := world.enroll(context.Background())
	if !errors.Is(err, ErrSidecarEnrollNotAdminRefused) {
		t.Fatalf("%v", err)
	}
	if after := backendSnapshot(t, world.backend); !snapshotsEqual(before, after) {
		t.Error("a refused enrollment left something on disk")
	}
	if paths := world.api.requestedPaths(); strings.Join(paths, " ") != "/network/enroll /network/remove-client" {
		t.Errorf("requests %v", paths)
	}
	if len(world.api.removed) != 1 || world.api.removed[0] != world.api.clients[0] {
		t.Error("the new client was not the one removed")
	}
	if world.sidecar.Status().State != SidecarStateUnenrolled || len(world.platform.openedClients()) != 0 {
		t.Error("the refused enrollment started a client")
	}
}

// Two snapshots hold the same files and bytes.
func snapshotsEqual(a map[string][]byte, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, content := range a {
		if !bytes.Equal(content, b[name]) {
			return false
		}
	}
	return true
}

// A urn_ API key never enrolls, and nothing is sent (D-CORE-7).
func TestEnrollRefusesUrnKey(t *testing.T) {
	world := newTestEnrollWorld(t)
	err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: "urn_synthetic0000000000000000"})
	if !errors.Is(err, ErrAuthKeyIsApiKey) {
		t.Fatalf("%v", err)
	}
	if paths := world.api.requestedPaths(); len(paths) != 0 {
		t.Errorf("sent %v", paths)
	}
}

// A pre-approved key's bundle is refused whole until admission lands, and none of it reaches a request, a log or
// the error: not the text, nor either seed as raw, hex or base64 bytes.
func TestBundleNeverSent(t *testing.T) {
	world := newTestEnrollWorld(t)
	bundleText := encodeTestBundle(t, testBundleMessage())
	err := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: testAuthKeyBearer() + "#" + bundleText})
	if !errors.Is(err, ErrSidecarEnrollBundle) {
		t.Fatalf("%v", err)
	}
	err2 := world.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: testAuthKeyBearer(), Bundle: testAuthKeyBundle()})
	if !errors.Is(err2, ErrSidecarEnrollBundle) {
		t.Fatalf("%v", err2)
	}
	if paths := world.api.requestedPaths(); len(paths) != 0 {
		t.Errorf("sent %v", paths)
	}
	bundle := testAuthKeyBundle()
	everything := world.api.everythingSent() + world.log.text() + err.Error() + err2.Error()
	for _, needle := range []string{
		bundleText,
		string(bundle.DelegationSigningSeed), hex.EncodeToString(bundle.DelegationSigningSeed),
		base64.StdEncoding.EncodeToString(bundle.DelegationSigningSeed), base64.RawURLEncoding.EncodeToString(bundle.DelegationSigningSeed),
		string(bundle.DelegationReaderSeed), hex.EncodeToString(bundle.DelegationReaderSeed),
		base64.StdEncoding.EncodeToString(bundle.DelegationReaderSeed), base64.RawURLEncoding.EncodeToString(bundle.DelegationReaderSeed),
	} {
		if strings.Contains(everything, needle) {
			t.Errorf("found a bundle's bytes")
		}
	}
}

// The keychain gets nothing until api has recorded the binding: the bind handler finds no identity, and a refused
// bind leaves nothing on disk and removes the client.
func TestKeychainPersistedOnlyAfterBind(t *testing.T) {
	world := newTestEnrollWorld(t)
	before := backendSnapshot(t, world.backend)
	sawIdentity := false
	world.api.onBind = func() {
		if after := backendSnapshot(t, world.backend); !snapshotsEqual(before, after) {
			sawIdentity = true
		}
	}
	world.api.bindRefusal = &testApiRefusal{status: http.StatusConflict, code: SidecarApiCodeClientBound}
	err := world.enroll(context.Background())
	var apiErr *SidecarApiError
	if !errors.As(err, &apiErr) || apiErr.Code != SidecarApiCodeClientBound {
		t.Fatalf("%v", err)
	}
	if sawIdentity {
		t.Error("something was written before the binding was recorded")
	}
	if after := backendSnapshot(t, world.backend); !snapshotsEqual(before, after) {
		t.Error("a refused bind left something on disk")
	}
	if len(world.api.removed) != 1 {
		t.Error("the client of a refused bind was not removed")
	}

	world.api.bindRefusal = nil
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sawIdentity {
		t.Error("the keychain was written before the binding was recorded")
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
}

// After a refusal, enrolling again keeps the sidecar_id and identity key and binds generation 2 on a new client and
// ClientKey, and the old client is removed with its own token.
func TestReenrollKeepsSidecarId(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	first := world.sidecar.currentIdentity()
	firstClient := world.platform.awaitOpened(t, 1)
	if err := world.enroll(context.Background()); !errors.Is(err, ErrSidecarEnrolled) {
		t.Fatalf("an enrolled sidecar enrolled again: %v", err)
	}
	world.sidecar.runningGeneration().tokenManager.Load().end(SidecarReasonRefused)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 1))
	<-firstClient.closed

	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	second := world.sidecar.currentIdentity()
	if second.SidecarId != first.SidecarId || !bytes.Equal(second.IdentityPublicKey, first.IdentityPublicKey) {
		t.Error("re-enrollment changed the identity")
	}
	if second.ClientId == first.ClientId || bytes.Equal(second.ClientPublicKey, first.ClientPublicKey) {
		t.Error("re-enrollment kept the client or its key")
	}
	if second.Generation != 2 {
		t.Errorf("generation %d", second.Generation)
	}
	secondClient := world.platform.awaitOpened(t, 2)
	if secondClient.args.ClientId != connectIdOf(second.ClientId) {
		t.Error("the new generation's client is not the new client")
	}
	if len(world.api.removed) != 1 || world.api.removed[0] != first.ClientId {
		t.Fatalf("removed %v, want the first client", world.api.removed)
	}
	if removerNetwork, removerClient, ok := sidecarJwtClient(world.api.removers[0]); !ok ||
		removerNetwork != first.NetworkId || removerClient != first.ClientId {
		t.Error("the old client was not removed with its own token")
	}
}

// An ephemeral enrollment needs a keychain in memory: refused before anything is sent where a disk would hold it,
// and on a memory backend nothing reaches a file.
func TestEphemeralWritesNoFile(t *testing.T) {
	directory := t.TempDir()
	backend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := newTestEnrollWorldOn(t, backend)
	err = onDisk.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: testAuthKeyBearer(), Ephemeral: true})
	if !errors.Is(err, ErrSidecarEnrollEphemeral) {
		t.Fatalf("%v", err)
	}
	if paths := onDisk.api.requestedPaths(); len(paths) != 0 {
		t.Errorf("sent %v", paths)
	}

	inMemory := newTestEnrollWorld(t)
	if err := inMemory.sidecar.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: testAuthKeyBearer(), Ephemeral: true}); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, inMemory.sidecar, atStatus(SidecarStateOffline, 1))
	if !inMemory.instance.memoryOnly() {
		t.Error("the ephemeral instance is not in memory")
	}
}

// api's preview and no_genesis refusals reach ur as typed errors, with nothing kept.
func TestPreviewRefusalSurfaces(t *testing.T) {
	cases := []struct {
		refusal *testApiRefusal
		reason  string
	}{
		{refusal: &testApiRefusal{status: http.StatusForbidden, code: "not_preview"}, reason: SidecarEnrollPreview},
		{refusal: &testApiRefusal{status: http.StatusForbidden, code: "no_genesis"}, reason: SidecarEnrollNoGenesis},
		{refusal: &testApiRefusal{status: http.StatusTooManyRequests, code: "rate_limited"}, reason: SidecarEnrollRefused},
	}
	for _, c := range cases {
		world := newTestEnrollWorld(t)
		world.api.enrollRefusal = c.refusal
		before := backendSnapshot(t, world.backend)
		err := world.enroll(context.Background())
		var enrollErr *SidecarEnrollError
		if !errors.As(err, &enrollErr) || enrollErr.Reason != c.reason || enrollErr.Api.Code != c.refusal.code {
			t.Errorf("%s: %v", c.refusal.code, err)
		}
		if strings.Contains(err.Error(), "synthetic refusal") {
			t.Errorf("%s: the error repeats the server's text", c.refusal.code)
		}
		if after := backendSnapshot(t, world.backend); !snapshotsEqual(before, after) {
			t.Errorf("%s: a refusal left something on disk", c.refusal.code)
		}
	}
}

// D-TRUST-3: a readable network by_jwt in an app's .auth_state, or the extension in a browser profile, refuses
// enrollment before anything is sent; an .auth_state whose by_jwt is empty, as every one holds the key, does not.
func TestHostStoreRefusesEnroll(t *testing.T) {
	writeFile := func(path string, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		goos  string
		files map[string]string
		kinds []string
	}{
		{name: "empty", goos: "darwin", files: map[string]string{}, kinds: nil},
		{name: "empty by_jwt", goos: "darwin", files: map[string]string{
			"Documents/.by/.auth_state": `{"version":1,"by_jwt":"","by_client_jwt":"synthetic"}`,
		}, kinds: nil},
		{name: "documents", goos: "darwin", files: map[string]string{
			"Documents/.by/.auth_state": `{"version":1,"by_jwt":"synthetic.network.jwt"}`,
		}, kinds: []string{"app"}},
		{name: "container", goos: "darwin", files: map[string]string{
			"Library/Containers/network.ur/Data/Documents/.by/.auth_state": `{"by_jwt":"synthetic.network.jwt"}`,
		}, kinds: []string{"app"}},
		{name: "legacy", goos: "linux", files: map[string]string{
			".local/state/urnetwork/.by/.by_jwt": "synthetic.network.jwt\n",
		}, kinds: []string{"app"}},
		{name: "nested", goos: "linux", files: map[string]string{
			".local/state/urnetwork/app/.by/.auth_state": `{"by_jwt":"synthetic.network.jwt"}`,
		}, kinds: []string{"app"}},
		{name: "chrome", goos: "darwin", files: map[string]string{
			"Library/Application Support/Google/Chrome/Default/Extensions/abcdef/1.2.3_0/manifest.json": `{"name":"URnetwork VPN","version":"1.2.3"}`,
		}, kinds: []string{"extension"}},
		{name: "another extension", goos: "darwin", files: map[string]string{
			"Library/Application Support/Google/Chrome/Default/Extensions/abcdef/1.0_0/manifest.json": `{"name":"Another"}`,
		}, kinds: nil},
		{name: "firefox", goos: "linux", files: map[string]string{
			".mozilla/firefox/synthetic.default/extensions.json": `{"addons":[{"id":"urnetwork@bringyour.com"}]}`,
		}, kinds: []string{"extension"}},
	}
	for _, c := range cases {
		home := t.TempDir()
		for name, content := range c.files {
			writeFile(filepath.Join(home, name), content)
		}
		roots := &hostStoreRoots{goos: c.goos, home: home}
		stores := hostCredentialStoresIn(roots)
		kinds := []string{}
		for _, store := range stores {
			kinds = append(kinds, store.Kind)
		}
		if strings.Join(kinds, " ") != strings.Join(c.kinds, " ") {
			t.Errorf("%s: kinds %v, want %v", c.name, kinds, c.kinds)
		}
		if 0 < len(c.kinds) {
			world := newTestEnrollWorld(t)
			world.sidecar.hostStores = func() []SidecarHostCredentialStore {
				return hostCredentialStoresIn(roots)
			}
			if err := world.enroll(context.Background()); !errors.Is(err, ErrSidecarHostCredentialStore) {
				t.Errorf("%s: %v", c.name, err)
			}
			if paths := world.api.requestedPaths(); len(paths) != 0 {
				t.Errorf("%s: sent %v", c.name, paths)
			}
		}
	}
}

// An enrolled daemon alarms while a store holds a network credential, with no path in the event.
func TestEnrolledSidecarAlarmsForHostStore(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	alarms := make(chan SidecarEvent, 4)
	remove := world.sidecar.AddEventCallback(func(event SidecarEvent) {
		if event.Kind == SidecarEventCredentialStore {
			alarms <- event
		}
	})
	defer remove()
	world.sidecar.hostStores = func() []SidecarHostCredentialStore {
		return []SidecarHostCredentialStore{{Kind: "app"}}
	}
	world.sidecar.alarmHostCredentialStores()
	select {
	case event := <-alarms:
		if event.Path != "" {
			t.Error("the alarm names a path")
		}
	case <-time.After(sidecarTestTimeout):
		t.Fatal("no alarm")
	}
}

// A locked instance, or a lost keychain, enrolls nothing.
func TestEnrollRefusesALockedInstance(t *testing.T) {
	world := newTestEnrollWorld(t)
	world.instance.Lock()
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateLocked, 0))
	if err := world.enroll(context.Background()); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("%v", err)
	}
	if paths := world.api.requestedPaths(); len(paths) != 0 {
		t.Errorf("sent %v", paths)
	}
}
