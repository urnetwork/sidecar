//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A synthetic SHA-256 for seed.
func testInferSha256(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// A file of name, served from a synthetic host.
func testInferManifestFile(name string, byteCount int64) InferManifestFile {
	return InferManifestFile{
		Name:      name,
		Url:       "https://models.example/releases/" + name,
		ByteCount: byteCount,
		Sha256:    testInferSha256(name),
	}
}

// A local model of model needing minMemoryGib, with one file for every platform and a GPU build for the phones.
func testInferManifestModel(model string, minMemoryGib int64, contextWindow int64) *InferManifestModel {
	return &InferManifestModel{
		Model:              model,
		Efforts:            []InferEffort{InferEffortOff},
		DefaultEffort:      InferEffortOff,
		ContextWindow:      contextWindow,
		MaxOutput:          contextWindow / 4,
		Tools:              true,
		StructuredOutput:   true,
		Modalities:         []InferModality{InferModalityText, InferModalityImage},
		License:            "Apache-2.0",
		MinMemoryByteCount: minMemoryGib * 1024 * 1024 * 1024,
		Accelerators:       []InferAccelerator{InferAcceleratorCpu, InferAcceleratorGpu},
		Files: []*InferManifestModelFile{
			{
				InferManifestFile: testInferManifestFile(model+".litertlm", minMemoryGib*512*1024*1024),
			},
			{
				InferManifestFile: testInferManifestFile(model+"-gpu.litertlm", minMemoryGib*480*1024*1024),
				Accelerator:       InferAcceleratorGpu,
				Platforms:         []string{"ios/arm64", "android/arm64"},
			},
		},
		DecodeRates: []*InferDecodeRate{
			{Device: "reference phone", Accelerator: InferAcceleratorGpu, TokensPerSecond: 52},
		},
	}
}

// A whole manifest, synthetic: §6.5's four Gemma 4 defaults, and engines pinned for every platform but windows/amd64.
func testInferManifest() *InferManifest {
	library := func(platform string) []*InferManifestFile {
		file := testInferManifestFile("libengine-"+strings.ReplaceAll(platform, "/", "-")+".bin", 40*1024*1024)
		return []*InferManifestFile{&file}
	}
	gpuPlugin := testInferManifestFile("libengine-gpu-darwin.bin", 20*1024*1024)
	dawn := testInferManifestFile("libdawn-darwin.bin", 10*1024*1024)
	return &InferManifest{
		Version: 1,
		Engines: []*InferManifestEngine{
			{
				Platform:   "darwin/arm64",
				Version:    "v0.19.1",
				Libraries:  library("darwin/arm64"),
				GpuPlugins: []*InferManifestFile{&gpuPlugin},
				Dawn:       &dawn,
			},
			{Platform: "linux/amd64", Version: "v0.19.1", Libraries: library("linux/amd64")},
			{Platform: "linux/arm64", Version: "v0.19.0", Libraries: library("linux/arm64")},
			{Platform: "ios/arm64", Version: "v0.19.1"},
			{Platform: "android/arm64", Version: "v0.19.1"},
		},
		Models: []*InferManifestModel{
			testInferManifestModel("gemma-4-e2b", 4, 32*1024),
			testInferManifestModel("gemma-4-e4b", 8, 32*1024),
			testInferManifestModel("gemma-4-12b", 16, 128*1024),
			testInferManifestModel("gemma-4-26b-a4b", 32, 128*1024),
		},
	}
}

// The manifest's JSON.
func testInferManifestJson(t *testing.T, manifest *InferManifest) []byte {
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A whole manifest parses to what was written.
func TestInferManifestParses(t *testing.T) {
	settings := DefaultInferSettings()
	manifest, err := ParseInferManifest(testInferManifestJson(t, testInferManifest()), settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Engines) != 5 || len(manifest.Models) != 4 {
		t.Fatalf("%d engines, %d models", len(manifest.Engines), len(manifest.Models))
	}
	engine := manifest.Engine("darwin/arm64")
	if engine == nil || engine.Version != "v0.19.1" || engine.Dawn == nil || len(engine.GpuPlugins) != 1 {
		t.Fatalf("darwin/arm64's engine read as %+v", engine)
	}
	if manifest.Engine("windows/amd64") != nil {
		t.Fatal("an engine the manifest does not pin")
	}
	model := manifest.Model("gemma-4-e4b")
	if model == nil || model.MinMemoryByteCount != 8*1024*1024*1024 || len(model.Files) != 2 ||
		model.Files[1].Accelerator != InferAcceleratorGpu || model.Files[0].Sha256 != testInferSha256("gemma-4-e4b.litertlm") {
		t.Fatalf("gemma-4-e4b read as %+v", model)
	}
	if manifest.Model("gemma-4-e4b-off") != nil {
		t.Fatal("a model found by its canonical name rather than its model part")
	}
}

// Each fault refuses the whole manifest: a file without a hash, an unknown platform or one with no engine build, and
// every other way an entry is not whole, as well as JSON that is not exactly one strict document.
func TestInferManifestRefuses(t *testing.T) {
	settings := DefaultInferSettings()
	cases := []struct {
		why    string
		change func(manifest *InferManifest)
	}{
		{why: "a file without a hash", change: func(m *InferManifest) { m.Models[0].Files[0].Sha256 = "" }},
		{why: "an engine file without a hash", change: func(m *InferManifest) { m.Engines[0].Libraries[0].Sha256 = "" }},
		{why: "Dawn without a hash", change: func(m *InferManifest) { m.Engines[0].Dawn.Sha256 = "" }},
		{why: "a hash in capitals", change: func(m *InferManifest) {
			m.Models[0].Files[0].Sha256 = strings.ToUpper(m.Models[0].Files[0].Sha256)
		}},
		{why: "a short hash", change: func(m *InferManifest) { m.Models[0].Files[0].Sha256 = m.Models[0].Files[0].Sha256[:62] }},
		{why: "an unknown platform", change: func(m *InferManifest) { m.Engines[1].Platform = "plan9/amd64" }},
		{why: "macOS on Intel", change: func(m *InferManifest) { m.Engines[1].Platform = "darwin/amd64" }},
		{why: "Windows on arm64", change: func(m *InferManifest) { m.Engines[1].Platform = "windows/arm64" }},
		{why: "a file for an unknown platform", change: func(m *InferManifest) {
			m.Models[0].Files[1].Platforms = []string{"plan9/amd64"}
		}},
		{why: "a file for macOS on Intel", change: func(m *InferManifest) {
			m.Models[0].Files[1].Platforms = []string{"darwin/amd64"}
		}},
		{why: "a platform twice", change: func(m *InferManifest) { m.Engines[2].Platform = "linux/amd64" }},
		{why: "no engine version", change: func(m *InferManifest) { m.Engines[0].Version = "" }},
		{why: "a desktop engine with no library", change: func(m *InferManifest) { m.Engines[1].Libraries = nil }},
		{why: "an http url", change: func(m *InferManifest) {
			m.Models[0].Files[0].Url = "http://models.example/a.litertlm"
		}},
		{why: "a url with a user", change: func(m *InferManifest) {
			m.Models[0].Files[0].Url = "https://user:pass@models.example/a.litertlm"
		}},
		{why: "a url with no host", change: func(m *InferManifest) { m.Models[0].Files[0].Url = "https:///a.litertlm" }},
		{why: "a file name that is a path", change: func(m *InferManifest) { m.Models[0].Files[0].Name = "../a.litertlm" }},
		{why: "a hidden file name", change: func(m *InferManifest) { m.Models[0].Files[0].Name = ".a" }},
		{why: "an empty file", change: func(m *InferManifest) { m.Models[0].Files[0].ByteCount = 0 }},
		{why: "a file past the bound", change: func(m *InferManifest) {
			m.Models[0].Files[0].ByteCount = settings.ManifestFileMaxByteCount + 1
		}},
		{why: "a file name twice", change: func(m *InferManifest) { m.Models[0].Files[1].Name = m.Models[0].Files[0].Name }},
		{why: "a model twice", change: func(m *InferManifest) { m.Models[1].Model = m.Models[0].Model }},
		{why: "a model part in capitals", change: func(m *InferManifest) { m.Models[0].Model = "Gemma-4-E2B" }},
		{why: "a model part with a doubled hyphen", change: func(m *InferManifest) { m.Models[0].Model = "gemma--4" }},
		{why: "a model whose names pass the bound", change: func(m *InferManifest) {
			m.Models[0].Model = strings.Repeat("g", settings.NameMaxByteCount)
		}},
		{why: "no effort", change: func(m *InferManifest) { m.Models[0].Efforts = nil }},
		{why: "an unknown effort", change: func(m *InferManifest) { m.Models[0].Efforts = []InferEffort{"none"} }},
		{why: "an effort twice", change: func(m *InferManifest) {
			m.Models[0].Efforts = []InferEffort{InferEffortOff, InferEffortOff}
		}},
		{why: "a default effort not listed", change: func(m *InferManifest) { m.Models[0].DefaultEffort = InferEffortHigh }},
		{why: "no context window", change: func(m *InferManifest) { m.Models[0].ContextWindow = 0 }},
		{why: "an output past the window", change: func(m *InferManifest) {
			m.Models[0].MaxOutput = m.Models[0].ContextWindow + 1
		}},
		{why: "no text modality", change: func(m *InferManifest) { m.Models[0].Modalities = []InferModality{InferModalityImage} }},
		{why: "an unknown modality", change: func(m *InferManifest) {
			m.Models[0].Modalities = []InferModality{InferModalityText, "audio"}
		}},
		{why: "no license", change: func(m *InferManifest) { m.Models[0].License = "" }},
		{why: "no minimum memory", change: func(m *InferManifest) { m.Models[0].MinMemoryByteCount = 0 }},
		{why: "no accelerator", change: func(m *InferManifest) { m.Models[0].Accelerators = nil }},
		{why: "an unknown accelerator", change: func(m *InferManifest) {
			m.Models[0].Accelerators = []InferAccelerator{InferAcceleratorCpu, "tpu"}
		}},
		{why: "a file for an accelerator not listed", change: func(m *InferManifest) {
			m.Models[0].Accelerators = []InferAccelerator{InferAcceleratorCpu}
		}},
		{why: "no file", change: func(m *InferManifest) { m.Models[0].Files = nil }},
		{why: "a decode rate of zero", change: func(m *InferManifest) { m.Models[0].DecodeRates[0].TokensPerSecond = 0 }},
		{why: "a decode rate with no device", change: func(m *InferManifest) { m.Models[0].DecodeRates[0].Device = "" }},
		{why: "another version", change: func(m *InferManifest) { m.Version = 2 }},
		{why: "an empty engine entry", change: func(m *InferManifest) { m.Engines = append(m.Engines, nil) }},
		{why: "an empty model entry", change: func(m *InferManifest) { m.Models = append(m.Models, nil) }},
	}
	for _, c := range cases {
		manifest := testInferManifest()
		c.change(manifest)
		if _, err := ParseInferManifest(testInferManifestJson(t, manifest), settings); !errors.Is(err, ErrInferManifestInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}

	whole := string(testInferManifestJson(t, testInferManifest()))
	raws := []struct {
		why  string
		data string
	}{
		{why: "a member twice", data: `{"version":1,"version":1,"engines":[],"models":[]}`},
		{why: "a member twice in an entry", data: strings.Replace(whole, `"license":"Apache-2.0"`,
			`"license":"Apache-2.0","license":"MIT"`, 1)},
		{why: "an unknown member", data: `{"version":1,"engines":[],"models":[],"extra":true}`},
		{why: "an unknown member in an entry", data: strings.Replace(whole, `"license":"Apache-2.0"`,
			`"license":"Apache-2.0","weights":"open"`, 1)},
		{why: "data after the document", data: whole + `{}`},
		{why: "two documents", data: whole + " " + whole},
		{why: "no document", data: ``},
		{why: "not an object", data: `[1]`},
		{why: "invalid utf-8", data: "{\"version\":1,\"engines\":[],\"models\":[],\"x\":\"\xff\"}"},
		{why: "a version as text", data: `{"version":"1","engines":[],"models":[]}`},
		{why: "a null model entry", data: `{"version":1,"engines":[],"models":[null]}`},
	}
	for _, c := range raws {
		if _, err := ParseInferManifest([]byte(c.data), settings); !errors.Is(err, ErrInferManifestInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}

	small := DefaultInferSettings()
	small.ManifestMaxByteCount = len(whole) - 1
	if _, err := ParseInferManifest([]byte(whole), small); !errors.Is(err, ErrInferManifestInvalid) {
		t.Errorf("a manifest past its bound: %v", err)
	}
	small.ManifestMaxByteCount = len(whole)
	if _, err := ParseInferManifest([]byte(whole), small); err != nil {
		t.Errorf("a manifest at its bound: %v", err)
	}
}

// This build's own manifest parses, and as a source build it carries the format and no entry: it lists, recommends
// and pulls nothing local, and says why.
func TestInferReleaseManifestIsASourceBuilds(t *testing.T) {
	settings := DefaultInferSettings()
	manifest, err := InferReleaseManifest(settings)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != inferManifestVersion || len(manifest.Engines) != 0 || len(manifest.Models) != 0 {
		t.Fatalf("a source build's manifest holds entries: %+v", manifest)
	}
	catalog, err := NewInferLocalCatalog(manifest, &InferDeviceCapabilities{
		Platform:        "darwin/arm64",
		Class:           InferDeviceClassDesktop,
		MemoryByteCount: 64 * 1024 * 1024 * 1024,
		UnifiedMemory:   true,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Entries()) != 0 || catalog.LocalUnavailable() == "" {
		t.Fatalf("a source build's catalog: %d entries, local unavailable %q", len(catalog.Entries()), catalog.LocalUnavailable())
	}
	if name, entry := catalog.Recommended(); name != "" || entry != nil {
		t.Fatalf("a source build recommends %s", name)
	}
}
