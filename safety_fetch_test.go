//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The classifier's files on a device (safety_fetch.go; SAFE-M13-05): fetched from a local TLS release host into the
// models' and the engine's safety directories, resumed after a cut, refusing a corrupted file, Ready only once every
// file is verified, the switch off and a file off its pin each answering unavailable, and a device that runs no
// classifier fetching nothing.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// A release host: each file by name under /files/, by Range from a byte on, and the faults a test sets.
type testSafetyReleaseHost struct {
	server *httptest.Server

	stateLock sync.Mutex
	files     map[string][]byte
	// a name's next answer stops after this many bytes, the connection dropped
	cutAt map[string]int
	// a name's answers carry one byte changed
	corrupt map[string]bool
	// each request: the name and its Range header
	requests []string
}

// A release host, closed at the test's end.
func newTestSafetyReleaseHost(t *testing.T) *testSafetyReleaseHost {
	t.Helper()
	host := &testSafetyReleaseHost{files: map[string][]byte{}, cutAt: map[string]int{}, corrupt: map[string]bool{}}
	host.server = httptest.NewTLSServer(http.HandlerFunc(host.serve))
	t.Cleanup(host.server.Close)
	return host
}

// Serves one file, whole or from a byte on.
func (self *testSafetyReleaseHost) serve(writer http.ResponseWriter, request *http.Request) {
	name := strings.TrimPrefix(request.URL.Path, "/files/")
	content, cut, corrupt := func() ([]byte, int, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, name+" "+request.Header.Get("Range"))
		cut := self.cutAt[name]
		delete(self.cutAt, name)
		return self.files[name], cut, self.corrupt[name]
	}()
	if content == nil {
		http.NotFound(writer, request)
		return
	}
	if corrupt {
		content = bytes.Clone(content)
		content[len(content)/2] ^= 0xff
	}
	start := 0
	if header := request.Header.Get("Range"); header != "" {
		from, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(header, "bytes="), "-"))
		if err != nil || len(content) <= from {
			writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		start = from
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(content)-1, len(content)))
		writer.Header().Set("Content-Length", strconv.Itoa(len(content)-start))
		writer.WriteHeader(http.StatusPartialContent)
	} else {
		writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
		writer.WriteHeader(http.StatusOK)
	}
	body := content[start:]
	if 0 < cut && cut < len(body) {
		writer.Write(body[:cut])
		writer.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	writer.Write(body)
}

// The requests so far, and forgets them.
func (self *testSafetyReleaseHost) taken() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := self.requests
	self.requests = nil
	return requests
}

// Sets a fault under the lock.
func (self *testSafetyReleaseHost) set(fault func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fault()
}

// The pin of content served as name.
func (self *testSafetyReleaseHost) pin(name string, content []byte) *SafetyManifestFile {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.files[name] = content
	digest := sha256.Sum256(content)
	return &SafetyManifestFile{Name: name, Url: self.server.URL + "/files/" + name, ByteCount: int64(len(content)), Sha256: hex.EncodeToString(digest[:])}
}

// The platform this test runs on, where it is a desktop that runs the ur-engine helper.
func testSafetyDesktopPlatform(t *testing.T) string {
	t.Helper()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !slices.Contains(inferDesktopPlatforms, platform) {
		t.Skipf("no classifier runtime runs on %s", platform)
	}
	return platform
}

// A manifest on host pinning the synthetic vocabulary and table, a model for each class, and a runtime for platform,
// its models' switches auto, read through the strict parse.
func testSafetyStoreManifest(t *testing.T, host *testSafetyReleaseHost, platform string, auto bool) *SafetyManifest {
	t.Helper()
	confusables, err := os.ReadFile(filepath.Join("testdata", "safety", "normalize", "confusables.txt"))
	if err != nil {
		t.Fatal(err)
	}
	vocabulary := host.pin("prompt-guard.spm.model", testSafetyModelWithCharsmap(t).proto())
	manifest := &SafetyManifest{
		Version:     1,
		Release:     "2026.11.27-test",
		Confusables: host.pin("confusables.txt", confusables),
		Runtimes: []*SafetyManifestRuntime{{Platform: platform, Version: "1.22.0", ApiVersion: 22,
			Library: host.pin("libonnxruntime.test", bytes.Repeat([]byte("runtime "), 4096))}},
		Models: []*SafetyManifestModel{
			{Name: SafetyModelPromptGuard22M, DeviceClasses: []InferDeviceClass{InferDeviceClassPhone}, ThresholdBasisPoints: 2000, Auto: auto,
				Model: host.pin("Llama-Prompt-Guard-2-22M-ur-int8.onnx", bytes.Repeat([]byte("22m weights "), 8192)), Vocabulary: vocabulary},
			{Name: SafetyModelPromptGuard86M, DeviceClasses: []InferDeviceClass{InferDeviceClassLaptop, InferDeviceClassDesktop}, ThresholdBasisPoints: 1800, Auto: auto,
				Model: host.pin("Llama-Prompt-Guard-2-86M-ur-int8.onnx", bytes.Repeat([]byte("86m weights "), 16384)), Vocabulary: vocabulary},
		},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSafetyManifest(data, DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// A store on host's transport for a device of class on platform; a desktop keeps an engine directory, a phone none.
func newTestSafetyStore(t *testing.T, host *testSafetyReleaseHost, manifest *SafetyManifest, platform string, class InferDeviceClass, local string) *SafetyModelStore {
	t.Helper()
	engineDirectory := ""
	if class != InferDeviceClassPhone {
		engineDirectory = InferEngineDirectory(local)
	}
	store, err := NewSafetyModelStore(&SafetyModelStoreArgs{
		Manifest: manifest,
		Device: func(ctx context.Context) (*InferDeviceCapabilities, error) {
			return &InferDeviceCapabilities{Platform: platform, Class: class, MemoryByteCount: 16 * 1024 * 1024 * 1024}, nil
		},
		ModelDirectory:  InferModelDirectory(local),
		EngineDirectory: engineDirectory,
		Transport:       host.server.Client().Transport,
		FreeByteCount: func(directory string) (int64, error) {
			return 1024 * 1024 * 1024 * 1024, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// A desktop's fetch: the runtime to the engine's safety directory, the 86M, its vocabulary and the table to the
// models', each reported to its whole size; Ready only after; the set's tokenizer and table parsed; the pins the engine
// scorer reads.
func TestSafetyModelStoreFetchesAndVerifies(t *testing.T) {
	platform := testSafetyDesktopPlatform(t)
	host := newTestSafetyReleaseHost(t)
	local := t.TempDir()
	store := newTestSafetyStore(t, host, testSafetyStoreManifest(t, host, platform, true), platform, InferDeviceClassDesktop, local)
	if store.Ready() {
		t.Fatal("ready before a fetch")
	}
	if _, err := store.Classifier(); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a classifier before a fetch: %v", err)
	}
	whole := map[string]int64{}
	err := store.Fetch(context.Background(), func(progress *SafetyFetchProgress) {
		if progress.FileCount != 4 {
			t.Errorf("a fetch of %d files", progress.FileCount)
		}
		whole[progress.File] = max(whole[progress.File], progress.DoneByteCount)
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := store.Classifier()
	if err != nil || !store.Ready() {
		t.Fatalf("after a fetch: %v", err)
	}
	if set.Release != "2026.11.27-test" || set.Model.Name != SafetyModelPromptGuard86M || set.Model.ThresholdBasisPoints != 1800 {
		t.Errorf("the set %+v", set)
	}
	if filepath.Dir(set.ModelPath) != filepath.Join(InferModelDirectory(local), "safety") || set.Runtime == nil ||
		filepath.Dir(set.Runtime.Path) != filepath.Join(InferEngineDirectory(local), "safety") || set.Runtime.ApiVersion != 22 {
		t.Errorf("the files at %s and %+v", set.ModelPath, set.Runtime)
	}
	if ids, err := set.Tokenizer.Encode("ab"); err != nil || !slices.Equal(ids, []int64{9}) || set.Confusables.EntryCount() != 13 {
		t.Errorf("the vocabulary and table: %v, %v, %d", ids, err, set.Confusables.EntryCount())
	}
	runtimeFile := store.manifest.RuntimeFor(platform).Library
	for _, file := range []*SafetyManifestFile{runtimeFile, store.manifest.Models[1].Model, store.manifest.Models[1].Vocabulary, store.manifest.Confusables} {
		if whole[file.Name] != file.ByteCount {
			t.Errorf("%s reported %d of %d bytes", file.Name, whole[file.Name], file.ByteCount)
		}
	}
	if sha, err := store.ModelSha256(context.Background(), set.ModelPath); err != nil || sha != set.ModelSha256 {
		t.Errorf("the model's pin: %s, %v", sha, err)
	}
	if _, err := store.ModelSha256(context.Background(), set.ModelPath+".other"); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("another path's pin: %v", err)
	}
	if runtime, err := store.Runtime(context.Background()); err != nil || runtime.Path != set.Runtime.Path {
		t.Errorf("the runtime: %+v, %v", runtime, err)
	}
	parts, _ := filepath.Glob(filepath.Join(local, "*", "safety", "*"+safetyPartSuffix))
	if len(parts) != 0 {
		t.Errorf("parts left: %v", parts)
	}
	// a second fetch keeps what is in place on its pin and asks the host for nothing
	host.taken()
	if err := store.Fetch(context.Background(), nil); err != nil || len(host.taken()) != 0 {
		t.Errorf("a second fetch: %v", err)
	}
}

// A phone fetches the 22M, its vocabulary and the table, and no runtime, which its app embeds.
func TestSafetyModelStoreOnAPhone(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	store := newTestSafetyStore(t, host, testSafetyStoreManifest(t, host, "linux/amd64", true), "ios/arm64", InferDeviceClassPhone, t.TempDir())
	if err := store.Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	set, err := store.Classifier()
	if err != nil || set.Model.Name != SafetyModelPromptGuard22M || set.Runtime != nil {
		t.Fatalf("a phone's set %+v, %v", set, err)
	}
	for _, request := range host.taken() {
		if strings.HasPrefix(request, "libonnxruntime") {
			t.Errorf("a phone fetched the runtime")
		}
	}
	if _, err := store.Runtime(context.Background()); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a phone's runtime: %v", err)
	}
}

// A cut leaves its part, which the next fetch resumes from the byte it reached, by a Range request.
func TestSafetyModelStoreResumesAfterACut(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	manifest := testSafetyStoreManifest(t, host, "linux/amd64", true)
	model := manifest.ModelFor(InferDeviceClassPhone).Model
	half := int(model.ByteCount / 2)
	host.set(func() { host.cutAt[model.Name] = half })
	local := t.TempDir()
	store := newTestSafetyStore(t, host, manifest, "ios/arm64", InferDeviceClassPhone, local)
	if err := store.Fetch(context.Background(), nil); !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "resumes") {
		t.Fatalf("a cut fetch: %v", err)
	}
	part := filepath.Join(InferModelDirectory(local), "safety", model.Name+safetyPartSuffix)
	if info, err := os.Stat(part); err != nil || info.Size() != int64(half) {
		t.Fatalf("the part after the cut: %v", err)
	}
	if store.Ready() {
		t.Fatal("ready with a part")
	}
	host.taken()
	if err := store.Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(host.taken(), fmt.Sprintf("%s bytes=%d-", model.Name, half)) {
		t.Errorf("the fetch did not resume at byte %d", half)
	}
	if !store.Ready() {
		t.Error("not ready after the resumed fetch")
	}
}

// A file whose bytes miss their pin is deleted, part and all, and never loaded; the next fetch starts it over.
func TestSafetyModelStoreRefusesACorruptedFile(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	manifest := testSafetyStoreManifest(t, host, "linux/amd64", true)
	model := manifest.ModelFor(InferDeviceClassPhone).Model
	host.set(func() { host.corrupt[model.Name] = true })
	local := t.TempDir()
	store := newTestSafetyStore(t, host, manifest, "ios/arm64", InferDeviceClassPhone, local)
	if err := store.Fetch(context.Background(), nil); !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "not the release's file") {
		t.Fatalf("a corrupted file: %v", err)
	}
	directory := filepath.Join(InferModelDirectory(local), "safety")
	for _, name := range []string{model.Name, model.Name + safetyPartSuffix} {
		if _, err := os.Stat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is left: %v", name, err)
		}
	}
	if _, err := store.Classifier(); store.Ready() || !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a classifier from a corrupted file: %v", err)
	}
	host.set(func() { delete(host.corrupt, model.Name) })
	host.taken()
	if err := store.Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(host.taken(), model.Name+" ") {
		t.Errorf("the fetch did not start the file over")
	}
}

// A release whose switch is off: verified, yet unavailable. A file off its pin once verified: unavailable at the next
// check, and fetched again.
func TestSafetyModelStoreSwitchOffAndAFileOffItsPin(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	off := newTestSafetyStore(t, host, testSafetyStoreManifest(t, host, "linux/amd64", false), "ios/arm64", InferDeviceClassPhone, t.TempDir())
	if err := off.Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := off.Classifier(); !off.Ready() || !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "automatic approvals off") {
		t.Errorf("the switch off: %v", err)
	}
	local := t.TempDir()
	store := newTestSafetyStore(t, host, testSafetyStoreManifest(t, host, "linux/amd64", true), "ios/arm64", InferDeviceClassPhone, local)
	if err := store.Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	set, err := store.Classifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(set.ModelPath, []byte("other weights"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(context.Background()); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a check of a file off its pin: %v", err)
	}
	if _, err := store.Classifier(); store.Ready() || !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "not on its pin") {
		t.Errorf("after a file left its pin: %v", err)
	}
	if _, err := store.ModelSha256(context.Background(), set.ModelPath); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("the pin of a file off its pin: %v", err)
	}
	host.taken()
	if err := store.Fetch(context.Background(), nil); err != nil || !store.Ready() {
		t.Fatalf("a fetch over a file off its pin: %v", err)
	}
	if !slices.Contains(host.taken(), set.Model.Model.Name+" ") {
		t.Errorf("the file off its pin was not fetched again")
	}
}

// A device that runs no classifier fetches nothing and is unavailable, saying why; and a build pinning no classifier,
// or none for this platform, is unavailable without asking the host.
func TestSafetyModelStoreUnavailableWithoutABuild(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	manifest := testSafetyStoreManifest(t, host, "linux/amd64", true)
	excluded, err := NewSafetyModelStore(&SafetyModelStoreArgs{
		Manifest: manifest,
		Device: func(ctx context.Context) (*InferDeviceCapabilities, error) {
			return &InferDeviceCapabilities{Platform: "linux/amd64", Class: InferDeviceClassDesktop}, nil
		},
		ModelDirectory: InferModelDirectory(t.TempDir()),
		Excluded:       "a tagged sidecar runs no classifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := excluded.Fetch(context.Background(), nil); !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "tagged") {
		t.Errorf("an excluded device's fetch: %v", err)
	}
	if _, err := excluded.Classifier(); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("an excluded device's classifier: %v", err)
	}
	source, err := SafetyReleaseManifest(DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*SafetyModelStore{
		newTestSafetyStore(t, host, source, "ios/arm64", InferDeviceClassPhone, t.TempDir()),
		newTestSafetyStore(t, host, manifest, "windows/amd64", InferDeviceClassDesktop, t.TempDir()),
	} {
		if err := store.Fetch(context.Background(), nil); !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "pins no classifier") {
			t.Errorf("no build: %v", err)
		}
	}
	if requests := host.taken(); len(requests) != 0 {
		t.Errorf("requests reached the host: %v", requests)
	}
}

// What one store fetched another verifies in place, with no network: a daemon's start.
func TestSafetyModelStoreChecksFilesInPlace(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	manifest := testSafetyStoreManifest(t, host, "linux/amd64", true)
	local := t.TempDir()
	if err := newTestSafetyStore(t, host, manifest, "ios/arm64", InferDeviceClassPhone, local).Fetch(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	host.taken()
	restarted := newTestSafetyStore(t, host, manifest, "ios/arm64", InferDeviceClassPhone, local)
	if err := restarted.Check(context.Background()); err != nil || !restarted.Ready() {
		t.Fatalf("a check in place: %v", err)
	}
	if requests := host.taken(); len(requests) != 0 {
		t.Errorf("a check reached the host: %v", requests)
	}
}

// A redirect to a host the settings do not name is refused, and so is one off https.
func TestSafetyModelStoreRefusesARedirectElsewhere(t *testing.T) {
	host := newTestSafetyReleaseHost(t)
	manifest := testSafetyStoreManifest(t, host, "linux/amd64", true)
	store := newTestSafetyStore(t, host, manifest, "ios/arm64", InferDeviceClassPhone, t.TempDir())
	request, err := http.NewRequest(http.MethodGet, "https://elsewhere.example/model.onnx", nil)
	if err != nil {
		t.Fatal(err)
	}
	from, _ := http.NewRequest(http.MethodGet, host.server.URL+"/files/model.onnx", nil)
	if err := store.checkRedirect(request, []*http.Request{from}); err == nil {
		t.Error("a redirect to another host")
	}
	request.URL.Scheme = "http"
	request.URL.Host = from.URL.Host
	if err := store.checkRedirect(request, []*http.Request{from}); err == nil {
		t.Error("a redirect off https")
	}
	request, _ = http.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/release/model.onnx", nil)
	if err := store.checkRedirect(request, []*http.Request{from}); err != nil {
		t.Errorf("a redirect to a release host the settings name: %v", err)
	}
}
