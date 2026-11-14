// The fetch of a key set's files (DESIGN-DETAILS 3.2.7; §2.8 smtp-7) against a local TLS listener that
// serves a set as ur.io would and misbehaves on cue: a short file, a long one, one of another hash, one
// cut off and resumed, a redirect, and what each request carries. Then a host's check over it: phase 1
// fetched and verified once for every shape, no key file ever asked for, and a failed fetch backing the
// host off.

package smtpproof

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// What a request to the test listener carried.
type testKeyRequest struct {
	method string
	path   string
	header http.Header
}

// Key sets served over TLS at <url>/keys/<id in hex>/<name>, logging each request. serve, when set, may
// answer a request its own way.
type testKeyServer struct {
	server *httptest.Server

	stateLock sync.Mutex
	files     map[string][]byte
	requests  []*testKeyRequest
	serve     func(writer http.ResponseWriter, request *http.Request, name string, content []byte) bool
}

func testStartKeyServer(t *testing.T) *testKeyServer {
	t.Helper()
	keyServer := &testKeyServer{files: map[string][]byte{}}
	keyServer.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		key, _ := strings.CutPrefix(request.URL.Path, "/keys/")
		content, serve := func() ([]byte, func(writer http.ResponseWriter, request *http.Request, name string, content []byte) bool) {
			keyServer.stateLock.Lock()
			defer keyServer.stateLock.Unlock()
			keyServer.requests = append(keyServer.requests, &testKeyRequest{method: request.Method, path: request.URL.Path, header: request.Header.Clone()})
			return keyServer.files[key], keyServer.serve
		}()
		if content == nil {
			http.NotFound(writer, request)
			return
		}
		if serve != nil && serve(writer, request, filepath.Base(key), content) {
			return
		}
		http.ServeContent(writer, request, key, time.Time{}, bytes.NewReader(content))
	}))
	t.Cleanup(keyServer.server.Close)
	return keyServer
}

func (self *testKeyServer) add(id []byte, files map[string][]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for name, content := range files {
		self.files[hex.EncodeToString(id)+"/"+name] = content
	}
}

func (self *testKeyServer) setServe(serve func(writer http.ResponseWriter, request *http.Request, name string, content []byte) bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.serve = serve
}

// Requests for a file of that name so far.
func (self *testKeyServer) count(name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, request := range self.requests {
		if filepath.Base(request.path) == name {
			count += 1
		}
	}
	return count
}

func (self *testKeyServer) logged() []*testKeyRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// Key settings whose base is the listener's.
func (self *testKeyServer) settings() *KeySettings {
	settings := testKeySettings()
	settings.BaseUrl = self.server.URL + "/keys"
	return settings
}

// A fetch that trusts the listener's certificate and is otherwise newKeyFetch's.
func (self *testKeyServer) fetch(settings *KeySettings) *keyFetch {
	transport := self.server.Client().Transport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return newKeyFetchWithTransport(settings, transport)
}

// A host that fetches from the listener.
func (self *testKeyServer) host(t *testing.T, settings *KeySettings) *keyHost {
	t.Helper()
	host := newKeyHost(settings, t.TempDir())
	host.fetch = self.fetch(settings)
	return host
}

// One served file and the keySetFile keyset.json would give it.
func testServedFile(t *testing.T, keyServer *testKeyServer, name string, content []byte) ([]byte, *keySetFile) {
	t.Helper()
	id := bytes.Repeat([]byte{9}, 32)
	keyServer.add(id, map[string][]byte{name: content})
	file, err := writeKeySetFile(t.TempDir(), name, content)
	if err != nil {
		t.Fatal(err)
	}
	return id, file
}

func testFetchContent() []byte {
	return bytes.Repeat([]byte("a phase 2 contribution's octets, "), 1000)
}

// What a failed fetch must leave: no file, and no partial file.
func testExpectNothingFetched(t *testing.T, name string, path string) {
	t.Helper()
	for _, candidate := range []string{path, path + keyFetchPartialSuffix} {
		if _, err := os.Stat(candidate); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %s remains: %v", name, filepath.Base(candidate), err)
		}
	}
}

func TestFetchTakesAWholeFileOfItsHash(t *testing.T) {
	keyServer := testStartKeyServer(t)
	content := testFetchContent()
	id, file := testServedFile(t, keyServer, "shape-phase2-0.bin", content)
	path := filepath.Join(t.TempDir(), file.Name)
	if err := keyServer.fetch(keyServer.settings()).fetchFile(context.Background(), id, file, path); err != nil {
		t.Fatal(err)
	}
	fetched, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(fetched, content) {
		t.Errorf("fetched %d octets, %v", len(fetched), err)
	}
	if _, err := os.Stat(path + keyFetchPartialSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial file remains: %v", err)
	}
}

func TestFetchRefusesAShortALongAndAnotherFile(t *testing.T) {
	content := testFetchContent()
	for name, served := range map[string][]byte{
		"a short file":      content[:len(content)-1],
		"a long file":       append(slices.Clone(content), '!'),
		"another file":      append(slices.Clone(content[:len(content)-1]), '!'),
		"an empty response": {},
	} {
		keyServer := testStartKeyServer(t)
		id, file := testServedFile(t, keyServer, "shape-phase2-0.bin", content)
		keyServer.setServe(func(writer http.ResponseWriter, request *http.Request, _ string, _ []byte) bool {
			http.ServeContent(writer, request, "file", time.Time{}, bytes.NewReader(served))
			return true
		})
		path := filepath.Join(t.TempDir(), file.Name)
		if err := keyServer.fetch(keyServer.settings()).fetchFile(context.Background(), id, file, path); err == nil {
			t.Errorf("%s: fetched", name)
		}
		testExpectNothingFetched(t, name, path)
	}
}

// A connection cut midway keeps what arrived, and the next attempt asks for the rest alone.
func TestFetchResumesACutFile(t *testing.T) {
	keyServer := testStartKeyServer(t)
	content := testFetchContent()
	id, file := testServedFile(t, keyServer, "shape-phase2-0.bin", content)
	cut := len(content) / 3
	keyServer.setServe(func(writer http.ResponseWriter, request *http.Request, _ string, content []byte) bool {
		if request.Header.Get("Range") != "" {
			return false
		}
		writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
		writer.WriteHeader(http.StatusOK)
		writer.Write(content[:cut])
		writer.(http.Flusher).Flush()
		conn, _, err := http.NewResponseController(writer).Hijack()
		if err == nil {
			conn.Close()
		}
		return true
	})
	path := filepath.Join(t.TempDir(), file.Name)
	fetch := keyServer.fetch(keyServer.settings())
	if err := fetch.fetchFile(context.Background(), id, file, path); err == nil {
		t.Fatal("a cut file was taken")
	}
	partial, err := os.ReadFile(path + keyFetchPartialSuffix)
	if err != nil || !bytes.Equal(partial, content[:cut]) {
		t.Fatalf("kept %d octets, %v", len(partial), err)
	}
	if err := fetch.fetchFile(context.Background(), id, file, path); err != nil {
		t.Fatal(err)
	}
	fetched, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(fetched, content) {
		t.Errorf("resumed to %d octets, %v", len(fetched), err)
	}
	requests := keyServer.logged()
	if len(requests) != 2 || requests[1].header.Get("Range") != "bytes="+strconv.Itoa(cut)+"-"+strconv.Itoa(len(content)-1) {
		t.Errorf("requests %+v", requests)
	}
	// an answer that is no file keeps what a cut left, for the next attempt to resume
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+keyFetchPartialSuffix, content[:cut], 0o600); err != nil {
		t.Fatal(err)
	}
	keyServer.setServe(func(writer http.ResponseWriter, request *http.Request, _ string, _ []byte) bool {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return true
	})
	if err := fetch.fetchFile(context.Background(), id, file, path); err == nil {
		t.Fatal("took an answer that is no file")
	}
	if partial, err := os.ReadFile(path + keyFetchPartialSuffix); err != nil || !bytes.Equal(partial, content[:cut]) {
		t.Errorf("kept %d octets, %v", len(partial), err)
	}
	keyServer.setServe(nil)
	if err := fetch.fetchFile(context.Background(), id, file, path); err != nil {
		t.Fatal(err)
	}
	// a resumed file whose first octets were not the file's fails its hash, and starts again
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+keyFetchPartialSuffix, bytes.Repeat([]byte{'x'}, cut), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fetch.fetchFile(context.Background(), id, file, path); err == nil {
		t.Error("took a resumed file of other octets")
	}
	testExpectNothingFetched(t, "a resumed file of other octets", path)
}

// The fetch says nothing smtp-7 does not list: a plain GET with a generic client name, and nothing to
// follow elsewhere.
func TestFetchSendsNothingThatIdentifiesTheHost(t *testing.T) {
	keyServer := testStartKeyServer(t)
	id, file := testServedFile(t, keyServer, "shape-phase2-0.bin", testFetchContent())
	path := filepath.Join(t.TempDir(), file.Name)
	if err := keyServer.fetch(keyServer.settings()).fetchFile(context.Background(), id, file, path); err != nil {
		t.Fatal(err)
	}
	for _, request := range keyServer.logged() {
		if request.method != http.MethodGet {
			t.Errorf("method %s", request.method)
		}
		for name := range request.header {
			switch name {
			case "User-Agent", "Accept-Encoding", "Range":
			default:
				t.Errorf("header %s: %q", name, request.header.Get(name))
			}
		}
		if request.header.Get("User-Agent") != keyFetchUserAgent {
			t.Errorf("client name %q", request.header.Get("User-Agent"))
		}
		if encoding := request.header.Get("Accept-Encoding"); encoding != "" && encoding != "identity" {
			t.Errorf("Accept-Encoding %q", encoding)
		}
	}
	// a redirect is not followed: another host would see the fetch
	keyServer.setServe(func(writer http.ResponseWriter, request *http.Request, _ string, _ []byte) bool {
		http.Redirect(writer, request, "https://keys.example/elsewhere", http.StatusFound)
		return true
	})
	other := filepath.Join(t.TempDir(), file.Name)
	if err := keyServer.fetch(keyServer.settings()).fetchFile(context.Background(), id, file, other); err == nil {
		t.Error("followed a redirect")
	}
	// a base that is not plain https asks nothing at all
	before := len(keyServer.logged())
	for _, base := range []string{"http" + strings.TrimPrefix(keyServer.server.URL, "https") + "/keys", keyServer.server.URL + "/keys?x=1", ""} {
		settings := keyServer.settings()
		settings.BaseUrl = base
		if err := keyServer.fetch(settings).fetchFile(context.Background(), id, file, other); err == nil {
			t.Errorf("%q: fetched", base)
		}
	}
	if len(keyServer.logged()) != before {
		t.Error("a refused base was asked")
	}
}

func TestFetchRefusesAFilePastItsBound(t *testing.T) {
	keyServer := testStartKeyServer(t)
	id, file := testServedFile(t, keyServer, "shape-phase2-0.bin", testFetchContent())
	settings := keyServer.settings()
	settings.FetchFileMaxByteCount = file.ByteCount - 1
	err := keyServer.fetch(settings).fetchFile(context.Background(), id, file, filepath.Join(t.TempDir(), file.Name))
	if !isKeyRefusal(err) || len(keyServer.logged()) != 0 {
		t.Errorf("%v, %d requests", err, len(keyServer.logged()))
	}
}

func TestFetchTakesOnlyThePinnedManifest(t *testing.T) {
	keyServer := testStartKeyServer(t)
	made := testMakeKeySet(t, testFamilyKeySetCircuits(t)[:1])
	keyServer.add(made.id, made.files(t))
	fetch := keyServer.fetch(keyServer.settings())
	path := filepath.Join(t.TempDir(), keySetManifestName)
	if err := fetch.fetchManifest(context.Background(), made.id, path); err != nil {
		t.Fatal(err)
	}
	// keyset.json under another id is not that id's
	other := bytes.Repeat([]byte{3}, len(made.id))
	keyServer.add(other, map[string][]byte{keySetManifestName: made.files(t)[keySetManifestName]})
	otherPath := filepath.Join(t.TempDir(), keySetManifestName)
	if err := fetch.fetchManifest(context.Background(), other, otherPath); err == nil {
		t.Error("took a keyset.json that is not the pin's")
	}
	testExpectNothingFetched(t, "another pin", otherPath)
	// nor one past ManifestMaxByteCount
	settings := keyServer.settings()
	settings.ManifestMaxByteCount = int64(len(made.files(t)[keySetManifestName]) - 1)
	if err := keyServer.fetch(settings).fetchManifest(context.Background(), made.id, otherPath); err == nil {
		t.Error("took a keyset.json past its bound")
	}
}

// A host's check over the fetch: keyset.json by its pin, phase 1 fetched and verified once for every
// shape of the set, and for every set on the same phase 1, each phase 2 once, and no key file asked for:
// a published proving key is never read, and a verifying key is the edge's.
func TestPhase1IsVerifiedOnceForEveryShape(t *testing.T) {
	keyServer := testStartKeyServer(t)
	circuits := testFamilyKeySetCircuits(t)
	made := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	files := made.files(t)
	keyServer.add(made.id, files)
	// a set published as the landed ceremony did, with proving keys beside it
	for name, content := range files {
		if strings.HasSuffix(name, ".vk") {
			keyServer.add(made.id, map[string][]byte{strings.TrimSuffix(name, ".vk") + ".pk": content})
		}
	}
	settings := keyServer.settings()
	settings.KeepTranscripts = false
	host := keyServer.host(t, settings)
	keys := &proverKeys{host: host, proof: DefaultProofSettings(), domainSize: testKeySetDomainSize, circuits: circuits,
		suites: defaultTlsClientSettings().suites, sets: []*proverKeySet{{id: made.id}}}
	for calls := 0; ; calls += 1 {
		readiness, err := keys.prepare(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if readiness.Done {
			if len(readiness.KeySets) != 1 || !slices.Equal(readiness.KeySets[0].ReadySuites, []uint16{tlsSuiteChacha20Poly1305Sha256}) {
				t.Errorf("readiness %+v", readiness)
			}
			break
		}
		if 10 < calls {
			t.Fatal("never done")
		}
	}
	edge := made.open(t)
	phase1Name := edge.manifest.Phase1[0].Contributions[0].Name
	if count := keyServer.count(phase1Name); count != 1 {
		t.Errorf("phase 1 fetched %d times", count)
	}
	for _, entry := range edge.manifest.Shapes {
		if count := keyServer.count(entry.Contributions[0].Name); count != 1 {
			t.Errorf("%s fetched %d times", entry.Contributions[0].Name, count)
		}
	}
	for _, request := range keyServer.logged() {
		if strings.HasSuffix(request.path, ".pk") || strings.HasSuffix(request.path, ".vk") {
			t.Errorf("asked for %s", request.path)
		}
	}
	// the transcripts are gone once the keys are cached, and no proving key was ever written to the set
	entries, err := os.ReadDir(host.keySetDirectory(made.id))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != keySetManifestName {
			t.Errorf("%s remains", entry.Name())
		}
	}

	// a set extended over the same phase 1 fetches no phase 1, and the shapes it shared none at all
	extendedId, err := extendKeySetSetup(context.Background(), made.directory, DefaultProofSettings(), testKeySetDomainSize, circuits)
	if err != nil {
		t.Fatal(err)
	}
	extended := &testKeySetMade{directory: made.directory, id: extendedId, circuits: circuits}
	keyServer.add(extendedId, extended.files(t))
	before := len(keyServer.logged())
	keySet := testOpenOnHost(t, host, extendedId, circuits)
	for _, family := range []ShapeFamily{ShapeFamilyChacha20, ShapeFamilyAes128Gcm} {
		if err := keySet.EnsureKeys(context.Background(), family); err != nil {
			t.Fatalf("%s: %v", family, err)
		}
	}
	for _, request := range keyServer.logged()[before:] {
		name := filepath.Base(request.path)
		if name == phase1Name || strings.Contains(name, string(ShapeFamilyChacha20)) {
			t.Errorf("asked for %s again", name)
		}
	}
}

// A failed fetch backs the host off, FetchRetryInterval doubling, and a success brings it back.
func TestAFailedFetchBacksTheHostOff(t *testing.T) {
	keyServer := testStartKeyServer(t)
	circuits := testFamilyKeySetCircuits(t)
	made := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	keyServer.add(made.id, made.files(t))
	failures := 2
	keyServer.setServe(func(writer http.ResponseWriter, request *http.Request, name string, _ []byte) bool {
		if name != keySetManifestName || failures == 0 {
			return false
		}
		failures -= 1
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return true
	})
	settings := keyServer.settings()
	host := keyServer.host(t, settings)
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	var waits []time.Duration
	host.now = func() time.Time { return now }
	host.wait = func(ctx context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		now = now.Add(duration)
		return nil
	}
	keys := &proverKeys{host: host, proof: DefaultProofSettings(), domainSize: testKeySetDomainSize, circuits: circuits,
		suites: defaultTlsClientSettings().suites, sets: []*proverKeySet{{id: made.id}}}
	for i := 0; i < 2; i += 1 {
		readiness, err := keys.prepare(context.Background())
		if err == nil || readiness == nil || readiness.Done {
			t.Fatalf("attempt %d: %+v, %v", i, readiness, err)
		}
	}
	if readiness, err := keys.prepare(context.Background()); err != nil || len(readiness.KeySets) != 0 {
		t.Fatalf("after the failures: %+v, %v", readiness, err)
	}
	if !slices.Equal(waits, []time.Duration{settings.FetchRetryInterval, 2 * settings.FetchRetryInterval}) {
		t.Errorf("waits %v", waits)
	}
	// the success reset it: the next shape waits for nothing
	if _, err := keys.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 2 {
		t.Errorf("waits %v", waits)
	}
	// the interval stops doubling at its bound
	for i := 0; i < 20; i += 1 {
		host.failed(made.id)
	}
	if retry := host.retries[hex.EncodeToString(made.id)]; retry.interval != settings.FetchRetryMaxInterval {
		t.Errorf("interval %v", retry.interval)
	}
}

// A newer pin whose files are not published yet backs off alone: the older set is checked meanwhile, and
// the host proves under it.
func TestANewerSetWhoseFetchFailsLeavesTheOlderToBeChecked(t *testing.T) {
	keyServer := testStartKeyServer(t)
	circuits := testFamilyKeySetCircuits(t)
	older := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	newer := testMakeKeySet(t, circuits)
	keyServer.add(older.id, older.files(t))
	host := keyServer.host(t, keyServer.settings())
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	host.now = func() time.Time { return now }
	host.wait = func(ctx context.Context, duration time.Duration) error {
		now = now.Add(duration)
		return nil
	}
	keys := &proverKeys{host: host, proof: DefaultProofSettings(), domainSize: testKeySetDomainSize, circuits: circuits,
		suites: defaultTlsClientSettings().suites, sets: []*proverKeySet{{id: newer.id}, {id: older.id}}}
	prover := &Prover{settings: DefaultProverSettings(), backend: &proverKeysBackend{keys: keys}, keys: keys}
	if _, err := keys.prepare(context.Background()); err == nil {
		t.Fatal("the newer set's keyset.json was fetched")
	}
	for calls := 0; !bytes.Equal(prover.KeySet(), older.id); calls += 1 {
		if 20 < calls {
			t.Fatalf("the older set never became ready: %x", prover.KeySet())
		}
		keys.prepare(context.Background())
	}
	// once published, the newer set is checked and named
	keyServer.add(newer.id, newer.files(t))
	for calls := 0; !bytes.Equal(prover.KeySet(), newer.id); calls += 1 {
		if 40 < calls {
			t.Fatalf("the newer set never became ready: %x", prover.KeySet())
		}
		if _, err := keys.prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
