//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// A remote entry, whole: a TEE entry for a TEE label, else a direct one, its default its last effort.
func testInferRemoteEntry(provider string, model string, label ComputeLabel, efforts ...InferEffort) *InferCatalogEntry {
	kind := InferCatalogKindDirect
	if label.Tee() {
		kind = InferCatalogKindTee
	}
	return &InferCatalogEntry{
		Provider:         provider,
		Model:            model,
		Kind:             kind,
		Label:            label,
		Efforts:          efforts,
		DefaultEffort:    efforts[len(efforts)-1],
		ContextWindow:    128 * 1024,
		MaxOutput:        32 * 1024,
		Tools:            true,
		StructuredOutput: true,
		Modalities:       []InferModality{InferModalityText},
		License:          "Apache-2.0",
		Remote: &InferRemoteModel{
			ProviderModelId:              model,
			InputNanoUsdPerMillion:       45 * 1000 * 1000,
			OutputNanoUsdPerMillion:      300 * 1000 * 1000,
			CachedInputNanoUsdPerMillion: 15 * 1000 * 1000,
		},
	}
}

// A search endpoint, whole, at $0.012 a search.
func testInferSearchEntry(engine string, kind string) *InferCatalogEntry {
	return &InferCatalogEntry{
		Provider: engine,
		Kind:     InferCatalogKindSearch,
		Label:    ComputeLabelNone,
		Search:   &InferSearchEndpoint{Kind: kind, NanoUsdPerSearch: 12 * 1000 * 1000},
	}
}

// A device's capabilities, its memory in GiB.
func testInferDevice(platform string, class InferDeviceClass, memoryGib int64, unified bool, accelerators ...InferAccelerator) *InferDeviceCapabilities {
	return &InferDeviceCapabilities{
		Platform:        platform,
		Class:           class,
		MemoryByteCount: memoryGib * 1024 * 1024 * 1024,
		UnifiedMemory:   unified,
		Accelerators:    accelerators,
	}
}

// The local view of manifest for device.
func testInferLocalCatalog(t *testing.T, manifest *InferManifest, device *InferDeviceCapabilities) *InferCatalog {
	t.Helper()
	catalog, err := NewInferLocalCatalog(manifest, device, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// No catalog holds two entries of one name or one model, whichever way they would arrive: two entries of a model,
// two of one model part that ends in an effort word, two search endpoints of one id, or a join that repeats one; and
// no remote entry passes for a local one (§6.3).
func TestInferCatalogRefusesCollidingNames(t *testing.T) {
	settings := DefaultInferSettings()
	sets := []struct {
		why     string
		entries []*InferCatalogEntry
	}{
		{why: "one model twice", entries: []*InferCatalogEntry{
			testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh),
			testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortLow),
		}},
		{why: "one model with no alias twice", entries: []*InferCatalogEntry{
			testInferRemoteEntry("chutes", "qwen4-max", ComputeLabelAp, InferEffortHigh),
			testInferRemoteEntry("chutes", "qwen4-max", ComputeLabelAp, InferEffortLow),
		}},
		{why: "one search id twice", entries: []*InferCatalogEntry{
			testInferSearchEntry("parallel", "fast"),
			testInferSearchEntry("parallel", "fast"),
		}},
		{why: "a remote entry of the local provider", entries: []*InferCatalogEntry{
			testInferRemoteEntry("local", "gemma-4-e4b", ComputeLabelNone, InferEffortOff),
		}},
		{why: "a remote entry labeled local", entries: []*InferCatalogEntry{
			testInferRemoteEntry("chutes", "gemma-4-e4b", ComputeLabelLocal, InferEffortOff),
		}},
	}
	for _, set := range sets {
		if _, err := NewInferCatalog(set.entries, settings); !errors.Is(err, ErrInferCatalogInvalid) {
			t.Errorf("%s: %v", set.why, err)
		}
	}
	local := &InferCatalogEntry{
		Provider:      "local",
		Model:         "gemma-4-e4b",
		Kind:          InferCatalogKindLocal,
		Label:         ComputeLabelLocal,
		Efforts:       []InferEffort{InferEffortOff},
		DefaultEffort: InferEffortOff,
		ContextWindow: 32 * 1024,
		MaxOutput:     8 * 1024,
		Modalities:    []InferModality{InferModalityText},
		Local:         &InferLocalModel{},
	}
	if _, err := NewInferCatalog([]*InferCatalogEntry{local}, settings); !errors.Is(err, ErrInferCatalogInvalid) {
		t.Errorf("a local entry from outside the manifest: %v", err)
	}

	catalog := testInferLocalCatalog(t, testInferManifest(), testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true))
	joined, err := catalog.Join([]*InferCatalogEntry{testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joined.Join([]*InferCatalogEntry{testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortLow)}); !errors.Is(err, ErrInferCatalogInvalid) {
		t.Errorf("a join that repeats a model: %v", err)
	}
	for _, entry := range []*InferCatalogEntry{
		local,
		testInferRemoteEntry("local", "gemma-4-e4b", ComputeLabelNone, InferEffortOff),
		testInferRemoteEntry("chutes", "other", ComputeLabelLocal, InferEffortOff),
	} {
		if _, err := catalog.Join([]*InferCatalogEntry{entry}); !errors.Is(err, ErrInferCatalogInvalid) {
			t.Errorf("a joined entry calling itself local, %s-%s: %v", entry.Provider, entry.Model, err)
		}
	}
	// the local view's own models stay its, untouched by a failed join
	if _, err := joined.Resolve("local-gemma-4-e4b-off", ""); err != nil {
		t.Errorf("the local view after a refused join: %v", err)
	}
}

// A name that reads both ways is a full name first, and a model whose own id ends in an effort word takes no alias
// (§6.3): beside a model qwen4, chutes-qwen4-max is qwen4 at max, never qwen4-max's alias, and without qwen4 it names
// nothing at all.
func TestInferNameReadingBothWaysIsFull(t *testing.T) {
	settings := DefaultInferSettings()
	qwen4 := testInferRemoteEntry("chutes", "qwen4", ComputeLabelAp, InferEffortHigh, InferEffortMax)
	qwen4Max := testInferRemoteEntry("chutes", "qwen4-max", ComputeLabelAp, InferEffortLow, InferEffortHigh)
	catalog, err := NewInferCatalog([]*InferCatalogEntry{qwen4, qwen4Max}, settings)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := catalog.Resolve("chutes-qwen4-max", string(InferEffortLow))
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Entry.Model != "qwen4" || resolution.Effort != InferEffortMax || resolution.Alias ||
		resolution.Name != "chutes-qwen4-max" {
		t.Fatalf("chutes-qwen4-max resolved to %s at %s, alias %t", resolution.Entry.Model, resolution.Effort, resolution.Alias)
	}
	resolution, err = catalog.Resolve("chutes-qwen4-max-high", "")
	if err != nil || resolution.Entry.Model != "qwen4-max" || resolution.Effort != InferEffortHigh {
		t.Fatalf("chutes-qwen4-max-high resolved to %+v, %v", resolution, err)
	}
	if alias := qwen4Max.Alias(); alias != "" {
		t.Fatalf("qwen4-max takes the alias %s", alias)
	}
	if alias := qwen4.Alias(); alias != "chutes-qwen4" {
		t.Fatalf("qwen4's alias is %q", alias)
	}
	resolution, err = catalog.Resolve("chutes-qwen4", string(InferEffortXhigh))
	if err != nil || resolution.Entry.Model != "qwen4" || !resolution.Alias || resolution.Effort != InferEffortHigh {
		t.Fatalf("chutes-qwen4 at xhigh resolved to %+v, %v", resolution, err)
	}

	alone, err := NewInferCatalog([]*InferCatalogEntry{qwen4Max}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alone.Resolve("chutes-qwen4-max", ""); !errors.Is(err, ErrInferModelUnknown) {
		t.Fatalf("chutes-qwen4-max named qwen4-max: %v", err)
	}
}

// An alias takes the request's effort mapped to the nearest the model lists, the lower of two equally near, else the
// model's default; a full name's own effort wins over the request's and must be one the model lists (§6.3, Q-INFER-5).
func TestInferAliasMapsToNearestEffort(t *testing.T) {
	settings := DefaultInferSettings()
	entry := testInferRemoteEntry("engy", "deepseek-v4.1-flash", ComputeLabelNone,
		InferEffortOff, InferEffortLow, InferEffortMax, InferEffortHigh)
	catalog, err := NewInferCatalog([]*InferCatalogEntry{entry}, settings)
	if err != nil {
		t.Fatal(err)
	}
	aliases := []struct {
		request string
		want    InferEffort
	}{
		{request: "", want: InferEffortHigh},
		{request: "none", want: InferEffortOff},
		{request: "off", want: InferEffortOff},
		{request: "minimal", want: InferEffortOff},
		{request: "low", want: InferEffortLow},
		{request: "medium", want: InferEffortLow},
		{request: "high", want: InferEffortHigh},
		{request: "xhigh", want: InferEffortHigh},
		{request: "max", want: InferEffortMax},
	}
	for _, c := range aliases {
		resolution, err := catalog.Resolve("engy-deepseek-v4.1-flash", c.request)
		if err != nil {
			t.Errorf("the alias at %q: %v", c.request, err)
			continue
		}
		if resolution.Effort != c.want || !resolution.Alias || resolution.Name != "engy-deepseek-v4.1-flash-"+string(c.want) {
			t.Errorf("the alias at %q ran at %s as %s", c.request, resolution.Effort, resolution.Name)
		}
	}
	for _, request := range []string{"", "max", "none", "ultra"} {
		resolution, err := catalog.Resolve("engy-deepseek-v4.1-flash-low", request)
		if err != nil || resolution.Effort != InferEffortLow || resolution.Alias {
			t.Errorf("a full name at low, the request %q: %+v, %v", request, resolution, err)
		}
	}
	if _, err := catalog.Resolve("engy-deepseek-v4.1-flash", "ultra"); !errors.Is(err, ErrInferEffortUnknown) {
		t.Errorf("an alias with an unknown request effort: %v", err)
	}
	for _, effort := range []InferEffort{InferEffortMinimal, InferEffortMedium, InferEffortXhigh} {
		if _, err := catalog.Resolve("engy-deepseek-v4.1-flash-"+string(effort), ""); !errors.Is(err, ErrInferEffortUnlisted) {
			t.Errorf("a full name at the unlisted %s: %v", effort, err)
		}
	}
	if _, err := catalog.Resolve("engy-nothing-high", ""); !errors.Is(err, ErrInferModelUnknown) {
		t.Errorf("an unknown model: %v", err)
	}
	if _, err := catalog.Resolve("Engy-deepseek-v4.1-flash-high", ""); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Errorf("a name outside the grammar: %v", err)
	}
}

// §6.5's defaults by device class and memory: phones the E2B from 6 GiB, laptops the E4B from 16 GiB, desktops the
// 12B from 32 GiB and the 26B A4B from 48 GiB of unified memory, each class falling to the largest default it fits,
// and none where nothing fits, the platform has no engine build, or the manifest pins no engine for it.
func TestInferRecommendedPerDeviceClass(t *testing.T) {
	manifest := testInferManifest()
	cases := []struct {
		device *InferDeviceCapabilities
		want   string
	}{
		{device: testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu), want: "local-gemma-4-e2b-off"},
		{device: testInferDevice("android/arm64", InferDeviceClassPhone, 6, false, InferAcceleratorGpu), want: "local-gemma-4-e2b-off"},
		{device: testInferDevice("android/arm64", InferDeviceClassPhone, 16, false), want: "local-gemma-4-e2b-off"},
		{device: testInferDevice("android/arm64", InferDeviceClassPhone, 4, false), want: ""},
		{device: testInferDevice("darwin/arm64", InferDeviceClassLaptop, 16, true, InferAcceleratorGpu), want: "local-gemma-4-e4b-off"},
		{device: testInferDevice("darwin/arm64", InferDeviceClassLaptop, 64, true, InferAcceleratorGpu), want: "local-gemma-4-e4b-off"},
		{device: testInferDevice("linux/amd64", InferDeviceClassLaptop, 8, false), want: "local-gemma-4-e2b-off"},
		{device: testInferDevice("linux/amd64", InferDeviceClassLaptop, 5, false), want: ""},
		{device: testInferDevice("linux/amd64", InferDeviceClassDesktop, 32, false), want: "local-gemma-4-12b-off"},
		{device: testInferDevice("linux/arm64", InferDeviceClassDesktop, 96, false), want: "local-gemma-4-12b-off"},
		{device: testInferDevice("darwin/arm64", InferDeviceClassDesktop, 48, true, InferAcceleratorGpu), want: "local-gemma-4-26b-a4b-off"},
		{device: testInferDevice("darwin/arm64", InferDeviceClassDesktop, 24, true), want: "local-gemma-4-e4b-off"},
		{device: testInferDevice("darwin/arm64", InferDeviceClassDesktop, 4, true), want: ""},
		{device: testInferDevice("darwin/amd64", InferDeviceClassDesktop, 64, false), want: ""},
		{device: testInferDevice("windows/arm64", InferDeviceClassLaptop, 32, false), want: ""},
		{device: testInferDevice("windows/amd64", InferDeviceClassDesktop, 64, false), want: ""},
		{device: testInferDevice("linux/amd64", "watch", 64, false), want: ""},
	}
	for _, c := range cases {
		catalog := testInferLocalCatalog(t, manifest, c.device)
		name, entry := catalog.Recommended()
		if name != c.want {
			t.Errorf("%s %s with %d GiB, unified %t: %q, want %q", c.device.Platform, c.device.Class,
				c.device.MemoryByteCount/(1024*1024*1024), c.device.UnifiedMemory, name, c.want)
			continue
		}
		if name != "" && (entry == nil || entry.Kind != InferCatalogKindLocal || entry.Unavailable != "" ||
			entry.Name(InferEffortOff) != name) {
			t.Errorf("%s recommended with the entry %+v", name, entry)
		}
		if name == "" && entry != nil {
			t.Errorf("no name recommended, but an entry %+v", entry)
		}
	}

	// a release without the largest default gives the best that remains
	without := testInferManifest()
	without.Models = slices.DeleteFunc(without.Models, func(model *InferManifestModel) bool {
		return model.Model == "gemma-4-26b-a4b"
	})
	catalog := testInferLocalCatalog(t, without, testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true))
	if name, _ := catalog.Recommended(); name != "local-gemma-4-12b-off" {
		t.Errorf("without the 26B A4B: %q", name)
	}
	// a default whose model this device lacks the memory for is passed over
	heavy := testInferManifest()
	heavy.Models[3].MinMemoryByteCount = 56 * 1024 * 1024 * 1024
	catalog = testInferLocalCatalog(t, heavy, testInferDevice("darwin/arm64", InferDeviceClassDesktop, 48, true))
	if name, _ := catalog.Recommended(); name != "local-gemma-4-12b-off" {
		t.Errorf("with a 26B A4B past the device's memory: %q", name)
	}
	// a catalog with no device recommends nothing
	remote, err := NewInferCatalog(nil, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	if name, entry := remote.Recommended(); name != "" || entry != nil {
		t.Errorf("a catalog with no device recommends %q", name)
	}
	// no default, no recommendation
	settings := DefaultInferSettings()
	settings.LocalDefaults = nil
	catalog, err = NewInferLocalCatalog(manifest, testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true), settings)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := catalog.Recommended(); name != "" {
		t.Errorf("no default recommends %q", name)
	}
}

// A local model the device lacks the memory for is listed unavailable with the reason, which Resolve answers with,
// while the models it fits stay usable; a device whose memory is unknown may use none.
func TestInferLocalEntryUnavailableForMemory(t *testing.T) {
	catalog := testInferLocalCatalog(t, testInferManifest(), testInferDevice("linux/amd64", InferDeviceClassLaptop, 12, false))
	entries := catalog.Entries()
	if len(entries) != 4 {
		t.Fatalf("%d local entries, want every model listed", len(entries))
	}
	available := map[string]bool{}
	for _, entry := range entries {
		available[entry.Model] = entry.Unavailable == ""
	}
	if !available["gemma-4-e2b"] || !available["gemma-4-e4b"] || available["gemma-4-12b"] || available["gemma-4-26b-a4b"] {
		t.Fatalf("available on 12 GiB: %v", available)
	}
	for _, entry := range entries {
		if entry.Model == "gemma-4-12b" && (!strings.Contains(entry.Unavailable, "16.0 GiB") ||
			!strings.Contains(entry.Unavailable, "12.0 GiB")) {
			t.Errorf("the 12B's reason: %q", entry.Unavailable)
		}
	}
	if _, err := catalog.Resolve("local-gemma-4-12b-off", ""); !errors.Is(err, ErrInferModelUnavailable) ||
		!strings.Contains(err.Error(), "16.0 GiB") {
		t.Errorf("the 12B on 12 GiB: %v", err)
	}
	if resolution, err := catalog.Resolve("local-gemma-4-e4b", ""); err != nil || resolution.Name != "local-gemma-4-e4b-off" {
		t.Errorf("the E4B on 12 GiB: %+v, %v", resolution, err)
	}

	unknown := testInferLocalCatalog(t, testInferManifest(), testInferDevice("linux/amd64", InferDeviceClassLaptop, 0, false))
	for _, entry := range unknown.Entries() {
		if entry.Unavailable == "" {
			t.Errorf("%s usable on a device of unknown memory", entry.Model)
		}
	}
	if name, _ := unknown.Recommended(); name != "" {
		t.Errorf("a device of unknown memory recommended %s", name)
	}
}

// A platform with no engine build lists no local entry at all, and says so (§6.5), as does a platform the manifest
// pins no engine for, a device of unknown platform and a manifest of no model.
func TestInferLocalCatalogWithoutAnEngine(t *testing.T) {
	cases := []struct {
		device *InferDeviceCapabilities
		reason string
	}{
		{device: testInferDevice("darwin/amd64", InferDeviceClassDesktop, 64, false), reason: "darwin/amd64"},
		{device: testInferDevice("windows/arm64", InferDeviceClassLaptop, 32, false), reason: "windows/arm64"},
		{device: testInferDevice("windows/amd64", InferDeviceClassDesktop, 64, false), reason: "pins no local engine"},
		{device: testInferDevice("", InferDeviceClassDesktop, 64, false), reason: "platform is unknown"},
		{device: nil, reason: "platform is unknown"},
	}
	for _, c := range cases {
		catalog := testInferLocalCatalog(t, testInferManifest(), c.device)
		if len(catalog.Entries()) != 0 || !strings.Contains(catalog.LocalUnavailable(), c.reason) {
			t.Errorf("%+v: %d entries, %q", c.device, len(catalog.Entries()), catalog.LocalUnavailable())
		}
		if _, err := catalog.Resolve("local-gemma-4-e2b-off", ""); !errors.Is(err, ErrInferModelUnknown) {
			t.Errorf("%+v resolved a local model: %v", c.device, err)
		}
	}
	empty := testInferManifest()
	empty.Models = nil
	catalog := testInferLocalCatalog(t, empty, testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true))
	if len(catalog.Entries()) != 0 || !strings.Contains(catalog.LocalUnavailable(), "no local model") {
		t.Errorf("a manifest of no model: %q", catalog.LocalUnavailable())
	}
	if _, err := NewInferLocalCatalog(nil, nil, DefaultInferSettings()); !errors.Is(err, ErrInferCatalogInvalid) {
		t.Errorf("no manifest: %v", err)
	}
}

// The local view takes only a whole manifest, however it was made: one not parsed is checked as a parse would.
func TestInferLocalCatalogRefusesAManifestNotWhole(t *testing.T) {
	device := testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true)
	changes := []func(manifest *InferManifest){
		func(m *InferManifest) { m.Models[0].Files[0].Sha256 = "" },
		func(m *InferManifest) { m.Models[0].Files[0] = nil },
		func(m *InferManifest) { m.Engines[0].Platform = "darwin/amd64" },
		func(m *InferManifest) { m.Models[1].Model = m.Models[0].Model },
		func(m *InferManifest) { m.Version = 0 },
	}
	for i, change := range changes {
		manifest := testInferManifest()
		change(manifest)
		if _, err := NewInferLocalCatalog(manifest, device, DefaultInferSettings()); !errors.Is(err, ErrInferManifestInvalid) {
			t.Errorf("change %d: %v", i, err)
		}
	}
}

// A local model with no build for the device's platform, or none for its accelerators, is listed unavailable with
// the reason; a device's CPU counts though it lists none, and only the files that serve its platform are its entry's.
func TestInferLocalEntryUnavailableWithoutABuild(t *testing.T) {
	manifest := testInferManifest()
	phoneOnly := manifest.Models[0]
	phoneOnly.Files = phoneOnly.Files[1:]
	phoneOnly.Files[0].Platforms = []string{"android/arm64"}
	gpuOnly := manifest.Models[1]
	gpuOnly.Accelerators = []InferAccelerator{InferAcceleratorGpu}
	gpuOnly.Files = gpuOnly.Files[1:]
	gpuOnly.Files[0].Platforms = nil
	gpuOnly.DecodeRates = nil
	if _, err := ParseInferManifest(testInferManifestJson(t, manifest), DefaultInferSettings()); err != nil {
		t.Fatal(err)
	}

	catalog := testInferLocalCatalog(t, manifest, testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true))
	reasons := map[string]string{}
	files := map[string][]string{}
	for _, entry := range catalog.Entries() {
		reasons[entry.Model] = entry.Unavailable
		for _, file := range entry.Local.Files {
			files[entry.Model] = append(files[entry.Model], file.Name)
		}
	}
	if !strings.Contains(reasons["gemma-4-e2b"], "platform") {
		t.Errorf("a model built for Android alone, on iOS: %q", reasons["gemma-4-e2b"])
	}
	if !strings.Contains(reasons["gemma-4-e4b"], "accelerators") {
		t.Errorf("a GPU model on a phone listing no GPU: %q", reasons["gemma-4-e4b"])
	}
	if len(files["gemma-4-e2b"]) != 0 {
		t.Errorf("an iOS entry carries Android's files: %v", files["gemma-4-e2b"])
	}

	withGpu := testInferLocalCatalog(t, manifest, testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu))
	if _, err := withGpu.Resolve("local-gemma-4-e4b-off", ""); err != nil {
		t.Errorf("a GPU model on a phone with a GPU: %v", err)
	}
	laptop := testInferLocalCatalog(t, testInferManifest(), testInferDevice("linux/amd64", InferDeviceClassLaptop, 16, false))
	for _, entry := range laptop.Entries() {
		if len(entry.Local.Files) != 1 || entry.Local.Files[0].Accelerator != "" {
			t.Errorf("%s on Linux carries %d files", entry.Model, len(entry.Local.Files))
		}
		if entry.Model == "gemma-4-e2b" && entry.Unavailable != "" {
			t.Errorf("a CPU model on a device listing no accelerator: %q", entry.Unavailable)
		}
	}
}

// The list filters to local models, to TEE models or a floor, or to chosen providers (§6.3, §16.4): local entries
// pass every floor and provider list, search endpoints are no inference and pass, and where no remote entry remains
// the catalog says why.
func TestInferCatalogFilter(t *testing.T) {
	local := testInferLocalCatalog(t, testInferManifest(), testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true))
	catalog, err := local.Join([]*InferCatalogEntry{
		testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelAp, InferEffortLow, InferEffortHigh),
		testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh),
		testInferSearchEntry("parallel", "fast"),
	})
	if err != nil {
		t.Fatal(err)
	}
	providers := func(catalog *InferCatalog) []string {
		seen := []string{}
		for _, entry := range catalog.Entries() {
			if !slices.Contains(seen, entry.Provider) {
				seen = append(seen, entry.Provider)
			}
		}
		return seen
	}
	cases := []struct {
		why    string
		filter *InferCatalogFilter
		want   []string
		reason string
	}{
		{why: "no filter", filter: nil, want: []string{"local", "chutes", "engy", "parallel"}},
		{why: "an empty filter", filter: &InferCatalogFilter{}, want: []string{"local", "chutes", "engy", "parallel"}},
		{why: "local alone", filter: &InferCatalogFilter{LocalOnly: true}, want: []string{"local"}, reason: "local models alone"},
		{why: "a floor of AP", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{
			Floor: ComputeLabelAp, Providers: []string{"*"}}}, want: []string{"local", "chutes", "parallel"}},
		{why: "tee_only", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{
			Floor: ComputeLabelNone, Providers: []string{"*"}, TeeOnly: true}}, want: []string{"local", "chutes", "parallel"}},
		{why: "a floor of A1", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{
			Floor: ComputeLabelA1, Providers: []string{"*"}}}, want: []string{"local", "parallel"}, reason: "A1"},
		{why: "engy alone", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{
			Floor: ComputeLabelNone, Providers: []string{"engy"}}}, want: []string{"local", "engy", "parallel"}},
		{why: "no provider", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{
			Floor: ComputeLabelNone, Providers: []string{}}}, want: []string{"local", "parallel"}, reason: "allowed provider"},
		{why: "the zero assurance", filter: &InferCatalogFilter{Assurance: &ComputeAssurance{}},
			want: []string{"local", "parallel"}, reason: "no assurance floor"},
	}
	for _, c := range cases {
		filtered := catalog.Filter(c.filter)
		if got := providers(filtered); !slices.Equal(got, c.want) {
			t.Errorf("%s kept %v, want %v", c.why, got, c.want)
		}
		if (c.reason == "") != (filtered.RemoteUnavailable() == "") || !strings.Contains(filtered.RemoteUnavailable(), c.reason) {
			t.Errorf("%s says %q, want %q", c.why, filtered.RemoteUnavailable(), c.reason)
		}
		// the filtered catalog resolves what it kept and nothing else
		_, err := filtered.Resolve("engy-glm-5.2-high", "")
		if slices.Contains(c.want, "engy") != (err == nil) {
			t.Errorf("%s resolved engy's model: %v", c.why, err)
		}
		if _, err := filtered.Resolve("local-gemma-4-e4b-off", ""); err != nil {
			t.Errorf("%s lost a local model: %v", c.why, err)
		}
		if filtered.Device() == nil || filtered.LocalUnavailable() != catalog.LocalUnavailable() {
			t.Errorf("%s lost the local view", c.why)
		}
	}
	// a catalog that held no remote entry gives no reason of its own
	if reason := local.Filter(&InferCatalogFilter{LocalOnly: true}).RemoteUnavailable(); reason != "" {
		t.Errorf("a local view filtered says %q", reason)
	}
}

// Nothing a caller holds changes a catalog: the entries it was given, the entries it gives out, the resolution's
// entry, the device.
func TestInferCatalogEntriesAreCopies(t *testing.T) {
	settings := DefaultInferSettings()
	given := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh)
	catalog, err := NewInferCatalog([]*InferCatalogEntry{given}, settings)
	if err != nil {
		t.Fatal(err)
	}
	given.Efforts[0] = InferEffortMax
	given.Remote.InputNanoUsdPerMillion = 0
	given.Unavailable = "changed"
	out := catalog.Entries()[0]
	out.Efforts[1] = InferEffortLow
	out.Remote.OutputNanoUsdPerMillion = 0
	resolution, err := catalog.Resolve("engy-glm-5.2-off", "")
	if err != nil {
		t.Fatal(err)
	}
	resolution.Entry.Modalities[0] = InferModalityImage
	again := catalog.Entries()[0]
	if !slices.Equal(again.Efforts, []InferEffort{InferEffortOff, InferEffortHigh}) || again.Unavailable != "" ||
		again.Remote.InputNanoUsdPerMillion == 0 || again.Remote.OutputNanoUsdPerMillion == 0 ||
		again.Modalities[0] != InferModalityText {
		t.Fatalf("the catalog changed: %+v %+v", again, again.Remote)
	}

	device := testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu)
	manifest := testInferManifest()
	local := testInferLocalCatalog(t, manifest, device)
	device.MemoryByteCount = 1
	device.Accelerators[0] = InferAcceleratorNpu
	manifest.Models[0].Files[0].Sha256 = ""
	local.Device().Accelerators[0] = InferAcceleratorNpu
	entry := local.Entries()[0]
	entry.Local.Files[0].Name = "changed"
	if local.Device().MemoryByteCount != 8*1024*1024*1024 || local.Device().Accelerators[0] != InferAcceleratorGpu {
		t.Fatalf("the device changed: %+v", local.Device())
	}
	if files := local.Entries()[0].Local.Files; files[0].Name != "gemma-4-e2b.litertlm" || files[0].Sha256 == "" {
		t.Fatalf("a local entry's files changed: %+v", files[0])
	}
}

// A model's tool budget is a quarter of its window (§6.3, §7.4), set by the catalog whatever an entry held.
func TestInferCatalogToolBudgetIsAQuarterOfTheWindow(t *testing.T) {
	entry := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh)
	entry.ToolBudget = 1
	catalog, err := NewInferCatalog([]*InferCatalogEntry{entry}, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	if budget := catalog.Entries()[0].ToolBudget; budget != 32*1024 {
		t.Errorf("a 128K window's tool budget is %d", budget)
	}
	local := testInferLocalCatalog(t, testInferManifest(), testInferDevice("android/arm64", InferDeviceClassPhone, 8, false))
	if budget := local.Entries()[0].ToolBudget; budget != 8*1024 {
		t.Errorf("a 32K local window's tool budget is %d", budget)
	}
	settings := DefaultInferSettings()
	settings.ToolBudgetWindowDivisor = 0
	catalog, err = NewInferCatalog([]*InferCatalogEntry{entry}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if budget := catalog.Entries()[0].ToolBudget; budget != 0 {
		t.Errorf("no divisor gave a tool budget of %d", budget)
	}
}

// An entry that is not whole, or whose name or kind would claim what its label denies, refuses the catalog (D-INFER-1,
// Q-PROV-8): a none model carrying a TEE mark, a TEE kind not labeled as one, a direct kind labeled as one, and the
// rest of an entry's fields.
func TestInferCatalogRefusesEntriesThatAreNotWhole(t *testing.T) {
	settings := DefaultInferSettings()
	cases := []struct {
		why    string
		change func(entry *InferCatalogEntry)
	}{
		{why: "a none model with a TEE mark", change: func(e *InferCatalogEntry) { e.Model = "glm-5.2-tee" }},
		{why: "a none model with a tdx mark", change: func(e *InferCatalogEntry) { e.Model = "tdx-glm-5.2" }},
		{why: "a none model with a confidential mark", change: func(e *InferCatalogEntry) { e.Model = "glm-confidential-5" }},
		{why: "a TEE kind labeled none", change: func(e *InferCatalogEntry) { e.Kind = InferCatalogKindTee }},
		{why: "a direct kind labeled AP", change: func(e *InferCatalogEntry) { e.Label = ComputeLabelAp }},
		{why: "an unknown kind", change: func(e *InferCatalogEntry) { e.Kind = "cloud" }},
		{why: "an unknown label", change: func(e *InferCatalogEntry) { e.Label = "A3" }},
		{why: "no remote fields", change: func(e *InferCatalogEntry) { e.Remote = nil }},
		{why: "local fields on a remote entry", change: func(e *InferCatalogEntry) { e.Local = &InferLocalModel{} }},
		{why: "search fields on a model", change: func(e *InferCatalogEntry) { e.Search = &InferSearchEndpoint{Kind: "fast"} }},
		{why: "a provider that is no slug", change: func(e *InferCatalogEntry) { e.Provider = "En-gy" }},
		{why: "a model part outside the grammar", change: func(e *InferCatalogEntry) { e.Model = "GLM/5.2" }},
		{why: "no effort", change: func(e *InferCatalogEntry) { e.Efforts = nil }},
		{why: "an effort twice", change: func(e *InferCatalogEntry) { e.Efforts = []InferEffort{InferEffortHigh, InferEffortHigh} }},
		{why: "an unknown effort", change: func(e *InferCatalogEntry) { e.Efforts = []InferEffort{"none", InferEffortHigh} }},
		{why: "a default not listed", change: func(e *InferCatalogEntry) { e.DefaultEffort = InferEffortLow }},
		{why: "no window", change: func(e *InferCatalogEntry) { e.ContextWindow = 0 }},
		{why: "an output past the window", change: func(e *InferCatalogEntry) { e.MaxOutput = e.ContextWindow + 1 }},
		{why: "no text modality", change: func(e *InferCatalogEntry) { e.Modalities = []InferModality{InferModalityImage} }},
		{why: "a negative price", change: func(e *InferCatalogEntry) { e.Remote.InputNanoUsdPerMillion = -1 }},
		{why: "a name past the bound", change: func(e *InferCatalogEntry) {
			e.Model = strings.Repeat("g", settings.NameMaxByteCount-len("engy--high")+1)
		}},
	}
	for _, c := range cases {
		entry := testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh)
		c.change(entry)
		if _, err := NewInferCatalog([]*InferCatalogEntry{entry}, settings); !errors.Is(err, ErrInferCatalogInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}
	searches := []struct {
		why    string
		change func(entry *InferCatalogEntry)
	}{
		{why: "a search labeled AP", change: func(e *InferCatalogEntry) { e.Label = ComputeLabelAp }},
		{why: "a search with a negative price", change: func(e *InferCatalogEntry) { e.Search.NanoUsdPerSearch = -1 }},
		{why: "a search with a model part", change: func(e *InferCatalogEntry) { e.Model = "fast" }},
		{why: "a search with remote fields", change: func(e *InferCatalogEntry) { e.Remote = &InferRemoteModel{} }},
		{why: "a search with no search fields", change: func(e *InferCatalogEntry) { e.Search = nil }},
		{why: "a search whose engine is no slug", change: func(e *InferCatalogEntry) { e.Provider = "par-allel" }},
		{why: "a search whose kind is outside the grammar", change: func(e *InferCatalogEntry) { e.Search.Kind = "Fast" }},
	}
	for _, c := range searches {
		entry := testInferSearchEntry("parallel", "fast")
		c.change(entry)
		if _, err := NewInferCatalog([]*InferCatalogEntry{entry}, settings); !errors.Is(err, ErrInferCatalogInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}
	if _, err := NewInferCatalog([]*InferCatalogEntry{nil}, settings); !errors.Is(err, ErrInferCatalogInvalid) {
		t.Errorf("an empty entry: %v", err)
	}
	// a TEE label keeps its provider's own marks
	chutes := testInferRemoteEntry("chutes", "glm-5.2-tee", ComputeLabelAp, InferEffortHigh)
	if _, err := NewInferCatalog([]*InferCatalogEntry{chutes}, settings); err != nil {
		t.Errorf("a TEE model with its provider's mark: %v", err)
	}
}

// Each entry's names, alias, disclosure id and search id (§6.3, §2.8).
func TestInferCatalogEntryNames(t *testing.T) {
	local := testInferLocalCatalog(t, testInferManifest(), testInferDevice("darwin/arm64", InferDeviceClassDesktop, 64, true))
	catalog, err := local.Join([]*InferCatalogEntry{
		testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelAp, InferEffortLow, InferEffortHigh),
		testInferSearchEntry("parallel", "fast"),
	})
	if err != nil {
		t.Fatal(err)
	}
	type names struct {
		names      []string
		alias      string
		disclosure string
		searchId   string
	}
	want := map[string]names{
		"local-gemma-4-e4b": {
			names:      []string{"local-gemma-4-e4b-off"},
			alias:      "local-gemma-4-e4b",
			disclosure: "inference:local",
		},
		"chutes-qwen3.8-27b-tee": {
			names:      []string{"chutes-qwen3.8-27b-tee-low", "chutes-qwen3.8-27b-tee-high"},
			alias:      "chutes-qwen3.8-27b-tee",
			disclosure: "inference:chutes",
		},
		"parallel-": {
			names:      []string{},
			disclosure: "search:parallel",
			searchId:   "search/parallel/fast",
		},
	}
	seen := 0
	for _, entry := range catalog.Entries() {
		w, ok := want[entry.Provider+"-"+entry.Model]
		if !ok {
			continue
		}
		seen += 1
		if !slices.Equal(entry.Names(), w.names) || entry.Alias() != w.alias || entry.DisclosureId() != w.disclosure ||
			entry.SearchId() != w.searchId {
			t.Errorf("%s-%s: names %v, alias %q, disclosure %q, search id %q", entry.Provider, entry.Model, entry.Names(),
				entry.Alias(), entry.DisclosureId(), entry.SearchId())
		}
	}
	if seen != len(want) {
		t.Fatalf("saw %d of %d entries", seen, len(want))
	}
	endpoint, err := catalog.SearchEndpoint("search/parallel/fast")
	if err != nil || endpoint.Search.NanoUsdPerSearch != 12*1000*1000 {
		t.Fatalf("the search endpoint: %+v, %v", endpoint, err)
	}
	if _, err := catalog.SearchEndpoint("search/parallel/turbo"); !errors.Is(err, ErrInferModelUnknown) {
		t.Errorf("an unlisted search endpoint: %v", err)
	}
	if _, err := catalog.SearchEndpoint("chutes-qwen3.8-27b-tee-high"); !errors.Is(err, ErrInferSearchIdInvalid) {
		t.Errorf("a model name as a search id: %v", err)
	}
	if _, err := catalog.Resolve("search/parallel/fast", ""); !errors.Is(err, ErrInferModelNameInvalid) {
		t.Errorf("a search id as a model name: %v", err)
	}
}

// The catalog's JSON holds its entries and its reasons, and an entry's holds §6.3's fields.
func TestInferCatalogJson(t *testing.T) {
	catalog := testInferLocalCatalog(t, testInferManifest(), testInferDevice("linux/amd64", InferDeviceClassLaptop, 12, false))
	filtered := catalog.Filter(&InferCatalogFilter{LocalOnly: true})
	data, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	decoded := struct {
		Entries []*InferCatalogEntry `json:"entries"`
	}{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) != 4 || decoded.Entries[0].Label != ComputeLabelLocal || decoded.Entries[0].Local == nil ||
		decoded.Entries[2].Unavailable == "" || decoded.Entries[0].ToolBudget != 8*1024 {
		t.Fatalf("the catalog's JSON: %s", data)
	}
	none := testInferLocalCatalog(t, testInferManifest(), testInferDevice("darwin/amd64", InferDeviceClassLaptop, 12, false))
	data, err = json.Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"local_unavailable":"no local engine is built for darwin/amd64`) {
		t.Fatalf("the reason is not in the JSON: %s", data)
	}
}
