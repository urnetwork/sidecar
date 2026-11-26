//go:build !ios_extension && !sidecar_http && !js

package sidecar

// Pulling a local model (infer_pull.go; INFER-M11-06, CO-49): through INFER-M11-11's chunked download against local
// test servers for the api and the hub (infer_download_test.go's world), resumed at the first chunk missing; the
// engine's files whole from a local release server, a file off its pin deleted and refused; progress by the engine's
// bytes, then the model's chunks; a model the device cannot run never pulled; a removal leaving nothing; and a local
// call over the pulled model sending no request anywhere (IC-5).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The engine library a desktop pull takes, and what the local release server answers for it.
type testInferRelease struct {
	content []byte
	file    *InferManifestFile

	stateLock sync.Mutex
	// what the server sends in place of the library, nil for the library
	served []byte
	count  int
}

// A release server for world, reached as release.example through world's transport, serving one engine library.
func newTestInferRelease(t *testing.T, world *testInferDownloadWorld) *testInferRelease {
	t.Helper()
	content := bytes.Repeat([]byte("engine library "), 1000)
	sum := sha256.Sum256(content)
	release := &testInferRelease{
		content: content,
		file: &InferManifestFile{
			Name:      "libLiteRtLm.dylib",
			Url:       "https://release.example/v0.19.1/libLiteRtLm.dylib",
			ByteCount: int64(len(content)),
			Sha256:    hex.EncodeToString(sum[:]),
		},
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release.stateLock.Lock()
		release.count += 1
		served := release.content
		if release.served != nil {
			served = release.served
		}
		release.stateLock.Unlock()
		// no credential reaches the release
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			http.Error(w, "credential", http.StatusBadRequest)
			return
		}
		w.Write(served)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	// every httptest server presents the same certificate, which world's transport trusts
	world.addresses["release.example"] = server.Listener.Addr().String()
	return release
}

// How often the release was asked.
func (self *testInferRelease) requests() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.count
}

// A manifest of one local model, test-model, whose file is world's, and desktops' engines of library, phones' of none.
func testInferPullManifest(world *testInferDownloadWorld, library *InferManifestFile) *InferManifest {
	model := testInferManifestModel("test-model", 1, 32*1024)
	model.Accelerators = []InferAccelerator{InferAcceleratorCpu}
	model.DecodeRates = nil
	model.Files = []*InferManifestModelFile{world.file}
	engines := []*InferManifestEngine{
		{Platform: "android/arm64", Version: "v0.19.1"},
		{Platform: "ios/arm64", Version: "v0.19.1"},
	}
	if library != nil {
		engines = append(engines, &InferManifestEngine{Platform: "darwin/arm64", Version: "v0.19.1", Libraries: []*InferManifestFile{library}})
	}
	return &InferManifest{Version: 1, Engines: engines, Models: []*InferManifestModel{model}}
}

// A pull of world's model for device, into fresh directories, an engine directory where engine.
func newTestInferPull(t *testing.T, world *testInferDownloadWorld, manifest *InferManifest, device *InferDeviceCapabilities, engine bool) (*InferPull, string) {
	t.Helper()
	engineDirectory := ""
	if engine {
		engineDirectory = filepath.Join(t.TempDir(), "engine")
	}
	pull, err := NewInferPull(&InferPullArgs{
		ApiUrl:          "https://api.example",
		Transport:       world.transport,
		ModelDirectory:  filepath.Join(t.TempDir(), "models"),
		EngineDirectory: engineDirectory,
		Manifest:        manifest,
		Device: func(ctx context.Context) (*InferDeviceCapabilities, error) {
			return device.clone(), nil
		},
		Settings:      world.settings,
		Log:           NewNoopLogger(),
		FreeByteCount: func(directory string) (int64, error) { return 1024 * 1024 * 1024 * 1024, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return pull, engineDirectory
}

// Progress heard, in order.
type testInferPullHeard struct {
	stateLock sync.Mutex
	progress  []*InferPullProgress
}

func (self *testInferPullHeard) listener(progress *InferPullProgress) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *progress
	self.progress = append(self.progress, &copied)
}

func (self *testInferPullHeard) all() []*InferPullProgress {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.progress)
}

// A pull takes the model through the chunked download; one stopped mid-file resumes at the first chunk not done,
// fetching none done again and the index not again, and the file opens whole only then.
func TestPullModelThroughChunkedDownload(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*4096+100, 4096)
	world.settings.ModelChunkFetchConcurrency = 1
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 8, false)
	pull, _ := newTestInferPull(t, world, testInferPullManifest(world, nil), device, false)
	// the connection is cut at chunk 2: its answer is held until the pull has given up on it
	ctx, cancel := context.WithCancel(context.Background())
	released := make(chan struct{})
	world.setGate(func(asked string) {
		if asked == "api chunk 2" {
			cancel()
			<-released
		}
	})
	err := pull.Pull(ctx, "local-test-model-off", nil)
	close(released)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a pull stopped mid-file answered %v", err)
	}
	if state := pull.FileState(world.file); state != InferPullFilePart {
		t.Errorf("a pull stopped mid-file left %s", state)
	}
	if _, err := pull.WholePath(context.Background(), world.file); !errors.Is(err, ErrInferModelNotWhole) {
		t.Errorf("a part opened: %v", err)
	}
	world.setGate(nil)
	heard := &testInferPullHeard{}
	if err := pull.Pull(context.Background(), "local-test-model", heard.listener); err != nil {
		t.Fatal(err)
	}
	counts := world.chunkCounts("api")
	for chunk := range 5 {
		want := 1
		if chunk == 2 {
			want = 2
		}
		if counts[chunk] != want {
			t.Errorf("chunk %d asked %d times, want %d (%v)", chunk, counts[chunk], want, counts)
		}
	}
	if world.countOf("api index") != 1 {
		t.Errorf("the index was asked %d times", world.countOf("api index"))
	}
	progress := heard.all()
	if len(progress) == 0 || progress[0].DoneChunkCount != 2 || progress[0].ChunkCount != 5 || progress[0].Name != "local-test-model-off" {
		t.Fatalf("the resumed pull began at %+v", progress)
	}
	path, err := pull.WholePath(context.Background(), world.file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, world.content) || pull.FileState(world.file) != InferPullFileWhole {
		t.Errorf("the whole file differs (%v)", err)
	}
}

// An engine file off its pin is deleted and refused, download_corrupt, before the model is asked for; the right bytes
// are moved into place once their SHA-256 matches, and a file in place on its pin is not fetched again, while one off
// it is deleted and fetched again.
func TestPullEngineFileRefusesAndDeletesMismatch(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4096+1, 4096)
	release := newTestInferRelease(t, world)
	device := testInferDevice("darwin/arm64", InferDeviceClassDesktop, 32, true)
	pull, engineDirectory := newTestInferPull(t, world, testInferPullManifest(world, release.file), device, true)
	altered := bytes.Clone(release.content)
	altered[len(altered)/2] ^= 1
	release.served = altered
	err := pull.Pull(context.Background(), "local-test-model-off", nil)
	var downloadErr *InferDownloadError
	if !errors.As(err, &downloadErr) || downloadErr.Code != InferDownloadErrorCorrupt || downloadErr.Sha256 != release.file.Sha256 {
		t.Fatalf("an altered engine file: %v", err)
	}
	entries, _ := os.ReadDir(engineDirectory)
	if len(entries) != 0 {
		t.Errorf("an altered engine file left %v", entries)
	}
	if world.requestCount() != 0 {
		t.Errorf("the model was asked for after its engine failed: %d requests", world.requestCount())
	}
	// a longer answer is refused too, never cut to fit
	release.served = append(bytes.Clone(release.content), 'x')
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); !errors.Is(err, ErrInferDownloadCorrupt) {
		t.Fatalf("a longer engine file: %v", err)
	}
	release.served = nil
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(engineDirectory, release.file.Name)
	if data, err := os.ReadFile(library); err != nil || !bytes.Equal(data, release.content) {
		t.Fatalf("the library in place differs (%v)", err)
	}
	asked := release.requests()
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); err != nil || release.requests() != asked {
		t.Errorf("a library on its pin was fetched again (%v)", err)
	}
	if err := os.WriteFile(library, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); err != nil || release.requests() != asked+1 {
		t.Errorf("a library off its pin was kept (%v)", err)
	}
	if data, _ := os.ReadFile(library); !bytes.Equal(data, release.content) {
		t.Error("the library off its pin was not replaced")
	}
}

// Progress: the engine's file by bytes first, whole once, then the model by chunks done, in order, each naming its
// place among the pull's files.
func TestPullProgressEvents(t *testing.T) {
	world := newTestInferDownloadWorld(t, 3*4096+7, 4096)
	world.settings.ModelChunkFetchConcurrency = 1
	release := newTestInferRelease(t, world)
	device := testInferDevice("darwin/arm64", InferDeviceClassDesktop, 32, true)
	pull, _ := newTestInferPull(t, world, testInferPullManifest(world, release.file), device, true)
	heard := &testInferPullHeard{}
	if err := pull.Pull(context.Background(), "local-test-model-off", heard.listener); err != nil {
		t.Fatal(err)
	}
	progress := heard.all()
	engineDone := slices.IndexFunc(progress, func(p *InferPullProgress) bool {
		return p.Phase == InferPullPhaseEngine && p.DoneChunkCount == 1
	})
	if engineDone < 0 || progress[engineDone].DoneByteCount != release.file.ByteCount || progress[engineDone].FileIndex != 1 ||
		progress[engineDone].Source != "release" {
		t.Fatalf("no engine file finished: %+v", progress)
	}
	model := []int{}
	lastBytes := int64(-1)
	for i, p := range progress {
		if p.FileCount != 2 || p.Name != "local-test-model-off" {
			t.Errorf("progress %d names %+v", i, p)
		}
		switch p.Phase {
		case InferPullPhaseEngine:
			if engineDone < i {
				t.Errorf("engine progress after the engine file finished: %+v", p)
			}
			if p.DoneByteCount < lastBytes {
				t.Errorf("engine bytes went back: %+v", p)
			}
			lastBytes = p.DoneByteCount
		case InferPullPhaseModel:
			if i < engineDone || p.FileIndex != 2 || p.ChunkCount != 4 || p.Sha256 != world.file.Sha256 {
				t.Errorf("model progress %+v", p)
			}
			model = append(model, p.DoneChunkCount)
		}
	}
	if !slices.Equal(model, []int{0, 1, 2, 3, 4}) {
		t.Errorf("chunks done heard %v", model)
	}
}

// A model this device lacks the memory for is refused with the catalog's reason and nothing is asked; a name that is
// no local model's is refused too.
func TestPullRefusesAModelTheDeviceCannotRun(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4096, 4096)
	small := testInferDevice("android/arm64", InferDeviceClassPhone, 0, false)
	small.MemoryByteCount = 512 * 1024 * 1024
	pull, _ := newTestInferPull(t, world, testInferPullManifest(world, nil), small, false)
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); !errors.Is(err, ErrInferModelUnavailable) ||
		!strings.Contains(err.Error(), "memory") {
		t.Errorf("a model past this device's memory: %v", err)
	}
	if err := pull.Pull(context.Background(), "chutes-qwen3.8-27b-tee-high", nil); !errors.Is(err, ErrInferModelUnknown) {
		t.Errorf("a remote model was pulled: %v", err)
	}
	if world.requestCount() != 0 {
		t.Errorf("a refused pull asked %d times", world.requestCount())
	}
}

// Remove leaves nothing of the model: no whole file, part, list or kept index, so it reads absent and opens nowhere.
func TestPullRemoveDeletesEveryState(t *testing.T) {
	world := newTestInferDownloadWorld(t, 2*4096, 4096)
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 8, false)
	pull, _ := newTestInferPull(t, world, testInferPullManifest(world, nil), device, false)
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); err != nil {
		t.Fatal(err)
	}
	if err := pull.Remove(context.Background(), "local-test-model-off"); err != nil {
		t.Fatal(err)
	}
	if state := pull.FileState(world.file); state != InferPullFileAbsent {
		t.Errorf("a removed model reads %s", state)
	}
	if _, err := pull.WholePath(context.Background(), world.file); !errors.Is(err, ErrInferModelNotWhole) {
		t.Errorf("a removed model opened: %v", err)
	}
	entries, err := os.ReadDir(pull.download.directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a removal left %v", entries)
	}
}

// A local call over a pulled model reaches the app's engine and sends no request to the api, the hub or anything
// else (IC-5): the servers see nothing while it runs.
func TestLocalInferenceMakesNoServerRequest(t *testing.T) {
	world := newTestInferDownloadWorld(t, 2*4096, 4096)
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 8, false)
	manifest := testInferPullManifest(world, nil)
	pull, _ := newTestInferPull(t, world, manifest, device, false)
	if err := pull.Pull(context.Background(), "local-test-model-off", nil); err != nil {
		t.Fatal(err)
	}
	before := world.requestCount()
	host := newTestInferHost(device, "")
	router, err := newInferRouter(&inferRouterArgs{Settings: world.settings, Manifest: manifest, Checker: &testInferPassChecker{}})
	if err != nil {
		t.Fatal(err)
	}
	engine := newInferHostEngine(&inferHostEngineArgs{Host: host, Models: pull, Settings: world.settings})
	defer engine.close()
	router.setLocalEngine(engine)
	events, err := router.Infer(context.Background(), testInferRequest("local-test-model-off", ""))
	if err != nil {
		t.Fatal(err)
	}
	if all := testInferDrain(t, events); all[len(all)-1].Kind != InferEventEnd || testInferText(all) != "hello" {
		t.Fatalf("the local call ended %+v", all[len(all)-1])
	}
	if after := world.requestCount(); after != before {
		t.Errorf("a local call sent %d requests", after-before)
	}
	loads, _, _, _ := host.taken()
	if len(loads) != 1 || filepath.Base(loads[0].path) != world.file.Sha256 {
		t.Errorf("the host loaded %+v, not the whole file", loads)
	}
}
