//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The release's classifier pins (safety_manifest.go; SAFE-M13-05): a whole manifest read, the model per device class
// and the runtime per platform, each refusal, and the source build's manifest naming nothing.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole manifest in testdata.
func testSafetyManifestData(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "safety", "manifest", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The manifest read whole: the release, the table, a runtime for each desktop, and the 22M on phones and the 86M on
// laptops and desktops, each with its threshold and switch.
func TestSafetyManifestParses(t *testing.T) {
	manifest, err := ParseSafetyManifest(testSafetyManifestData(t), DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Release != "2026.11.27-test" || manifest.Confusables == nil || len(manifest.Runtimes) != 4 || len(manifest.Models) != 2 {
		t.Fatalf("%+v", manifest)
	}
	for class, want := range map[InferDeviceClass]string{
		InferDeviceClassPhone:   SafetyModelPromptGuard22M,
		InferDeviceClassLaptop:  SafetyModelPromptGuard86M,
		InferDeviceClassDesktop: SafetyModelPromptGuard86M,
	} {
		if model := manifest.ModelFor(class); model == nil || model.Name != want {
			t.Errorf("a %s runs %+v, want %s", class, model, want)
		}
	}
	if model := manifest.ModelFor(InferDeviceClassPhone); model.ThresholdBasisPoints != 2000 || !model.Auto {
		t.Errorf("the 22M's threshold %d and switch %v", model.ThresholdBasisPoints, model.Auto)
	}
	if model := manifest.ModelFor(InferDeviceClassDesktop); model.ThresholdBasisPoints != 1800 || model.Auto {
		t.Errorf("the 86M's threshold %d and switch %v", model.ThresholdBasisPoints, model.Auto)
	}
	if runtime := manifest.RuntimeFor("darwin/arm64"); runtime == nil || runtime.ApiVersion != 22 || runtime.Version != "1.22.0" {
		t.Errorf("darwin's runtime %+v", runtime)
	}
	for _, platform := range []string{"ios/arm64", "android/arm64", "darwin/amd64", "windows/arm64"} {
		if manifest.RuntimeFor(platform) != nil {
			t.Errorf("a runtime for %s", platform)
		}
	}
}

// Each refusal, from the whole manifest with one fault.
func TestSafetyManifestRefusals(t *testing.T) {
	whole := testSafetyManifestData(t)
	edit := func(change func(manifest map[string]any)) []byte {
		manifest := map[string]any{}
		if err := json.Unmarshal(whole, &manifest); err != nil {
			t.Fatal(err)
		}
		change(manifest)
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	model := func(manifest map[string]any, index int) map[string]any {
		return manifest["models"].([]any)[index].(map[string]any)
	}
	runtime := func(manifest map[string]any, index int) map[string]any {
		return manifest["runtimes"].([]any)[index].(map[string]any)
	}
	settings := DefaultSafetySettings()
	cases := []struct {
		name string
		data []byte
	}{
		{name: "a threshold above 5,000", data: edit(func(manifest map[string]any) { model(manifest, 0)["threshold_basis_points"] = 5001 })},
		{name: "a threshold of nothing", data: edit(func(manifest map[string]any) { model(manifest, 0)["threshold_basis_points"] = 0 })},
		{name: "a missing model file", data: edit(func(manifest map[string]any) { delete(model(manifest, 0), "model") })},
		{name: "a missing vocabulary", data: edit(func(manifest map[string]any) { delete(model(manifest, 1), "vocabulary") })},
		{name: "an unknown model name", data: edit(func(manifest map[string]any) { model(manifest, 0)["name"] = "Prompt-Guard-3-ur-int8" })},
		{name: "a model twice", data: edit(func(manifest map[string]any) {
			model(manifest, 1)["name"] = model(manifest, 0)["name"]
		})},
		{name: "a class two models run", data: edit(func(manifest map[string]any) { model(manifest, 1)["device_classes"] = []string{"phone"} })},
		{name: "an unknown class", data: edit(func(manifest map[string]any) { model(manifest, 0)["device_classes"] = []string{"watch"} })},
		{name: "no class", data: edit(func(manifest map[string]any) { model(manifest, 0)["device_classes"] = []string{} })},
		{name: "a runtime for a phone", data: edit(func(manifest map[string]any) { runtime(manifest, 0)["platform"] = "ios/arm64" })},
		{name: "a runtime for a platform with no helper", data: edit(func(manifest map[string]any) { runtime(manifest, 0)["platform"] = "darwin/amd64" })},
		{name: "two runtimes for one platform", data: edit(func(manifest map[string]any) { runtime(manifest, 1)["platform"] = "darwin/arm64" })},
		{name: "a runtime with no API version", data: edit(func(manifest map[string]any) { runtime(manifest, 0)["api_version"] = 0 })},
		{name: "a runtime with no version", data: edit(func(manifest map[string]any) { runtime(manifest, 0)["version"] = "latest" })},
		{name: "an http url", data: edit(func(manifest map[string]any) {
			model(manifest, 0)["model"].(map[string]any)["url"] = "http://release.example/model.onnx"
		})},
		{name: "a model past its size", data: edit(func(manifest map[string]any) {
			model(manifest, 0)["model"].(map[string]any)["byte_count"] = settings.ModelMaxByteCount + 1
		})},
		{name: "a file of no bytes", data: edit(func(manifest map[string]any) {
			model(manifest, 0)["model"].(map[string]any)["byte_count"] = 0
		})},
		{name: "a file with no SHA-256", data: edit(func(manifest map[string]any) {
			model(manifest, 0)["model"].(map[string]any)["sha256"] = "not a hash"
		})},
		{name: "a file named as a path", data: edit(func(manifest map[string]any) {
			model(manifest, 0)["model"].(map[string]any)["name"] = "../model.onnx"
		})},
		{name: "a name under two pins", data: edit(func(manifest map[string]any) {
			vocabulary := map[string]any{}
			for key, value := range model(manifest, 1)["vocabulary"].(map[string]any) {
				vocabulary[key] = value
			}
			vocabulary["sha256"] = strings.Repeat("ab", 32)
			model(manifest, 1)["vocabulary"] = vocabulary
		})},
		{name: "models without confusables", data: edit(func(manifest map[string]any) { delete(manifest, "confusables") })},
		{name: "no release", data: edit(func(manifest map[string]any) { manifest["release"] = "" })},
		{name: "an unknown member", data: edit(func(manifest map[string]any) { manifest["threshold_override"] = 9000 })},
		{name: "version 2", data: edit(func(manifest map[string]any) { manifest["version"] = 2 })},
		{name: "a member twice", data: []byte(strings.Replace(string(whole), `"version": 1,`, `"version": 1, "version": 1,`, 1))},
		{name: "not one value", data: append(append([]byte{}, whole...), []byte("{}")...)},
	}
	for _, c := range cases {
		manifest, err := ParseSafetyManifest(c.data, settings)
		if manifest != nil || !errors.Is(err, ErrSafetyManifestInvalid) || !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
		}
	}
	small := DefaultSafetySettings()
	small.ManifestMaxByteCount = len(whole) - 1
	if _, err := ParseSafetyManifest(whole, small); !errors.Is(err, ErrSafetyManifestInvalid) {
		t.Errorf("past its bytes: %v", err)
	}
}

// The source build's manifest pins nothing: no model for any class, no runtime.
func TestSafetyReleaseManifestPinsNothingInASourceBuild(t *testing.T) {
	manifest, err := SafetyReleaseManifest(DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []InferDeviceClass{InferDeviceClassPhone, InferDeviceClassLaptop, InferDeviceClassDesktop} {
		if manifest.ModelFor(class) != nil {
			t.Errorf("a source build pins a model for a %s", class)
		}
	}
	if len(manifest.Runtimes) != 0 || manifest.Confusables != nil {
		t.Errorf("a source build pins %+v", manifest)
	}
}
