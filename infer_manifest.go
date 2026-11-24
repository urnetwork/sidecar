//go:build !ios_extension && !sidecar_http

// The release manifest (DESIGN-COMPUTE §6.3, §6.5): infer_manifest.json, embedded in each build of ur and the sdk and
// so signed with the release it ships in (DESIGN §4.10's SHA256SUMS). It names every local model the build offers,
// with its files' URLs, sizes and SHA-256s, and, per platform, the LiteRT-LM version the build pins (Q-INFER-2): on
// the desktops, where the ur-engine helper loads it, the engine's libraries, its GPU plugins and, where the version
// needs it, Dawn's WebGPU library (#4611), each with its SHA-256; on the phones, whose apps bundle the engine, the
// version alone. A downloader checks every file against its SHA-256 before it is moved into place and again before
// load (INFER-M11-06), and the helper loads no library off its pin (INFER-M11-04), so the manifest, not the host a
// file comes from, is what a device trusts.
//
// Its entries are the release pipeline's, read at release time from LiteRT-LM's release and Hugging Face's
// litert-community (External). A source build carries the format and no entry, so it lists, recommends and pulls
// nothing local.
//
// The file is a format, so its parse is strict: one JSON value in at most the settings' ManifestMaxByteCount, no
// member twice and none unknown, this version, and every entry whole: a hash on every file, an https URL, a known
// platform on every engine and no platform or model twice. macOS on Intel and Windows on arm64 have no engine build
// and get remote models only (§6.5), so an entry for either is refused, as is any other platform the design names
// none for. A refusal names the first fault it met and never the document's bytes.
//
// A parsed manifest is read only, so safe for concurrent use.

package sidecar

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
)

// This build's manifest. A source build's holds the format and no entry; the release pipeline writes its entries.
//
//go:embed infer_manifest.json
var inferManifestJson []byte

// The format's version, which the file's version member carries.
const inferManifestVersion = 1

// The platforms a manifest may name, as GOOS/GOARCH: the desktops whose ur runs the ur-engine helper, whose engine
// entries list its files (§6.5), and the phones, whose apps bundle the engine, whose entries pin its version alone.
// The macOS app reads darwin/arm64's version and bundles its own copy.
var (
	inferDesktopPlatforms = []string{"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"}
	inferPhonePlatforms   = []string{"ios/arm64", "android/arm64"}
	// No engine is built for these, and they get remote models only (§6.5).
	inferUnbuiltPlatforms = []string{"darwin/amd64", "windows/arm64"}
)

// What runs a local model, as the manifest and a device's capabilities name it.
type InferAccelerator string

const (
	InferAcceleratorCpu InferAccelerator = "cpu"
	InferAcceleratorGpu InferAccelerator = "gpu"
	InferAcceleratorNpu InferAccelerator = "npu"
)

var inferAccelerators = []InferAccelerator{InferAcceleratorCpu, InferAcceleratorGpu, InferAcceleratorNpu}

// What a model takes in (§6.3).
type InferModality string

const (
	InferModalityText  InferModality = "text"
	InferModalityImage InferModality = "image"
)

var inferModalities = []InferModality{InferModalityText, InferModalityImage}

// A file's name in the state directory: a letter or digit first, then letters, digits, ".", "_" and "-", so no name
// is a path, hidden, "." or "..".
var inferManifestFileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// A SHA-256, in lowercase hex.
var inferManifestSha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// A pinned engine version: LiteRT-LM's, such as v0.19.1.
var inferManifestEngineVersionPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.]+)?$`)

// A manifest that does not parse, or an entry in it that is not whole. The message names the first fault, and never
// repeats the document's bytes.
var ErrInferManifestInvalid = errors.New("release manifest refused")

// infer_manifest.json's content.
type InferManifest struct {
	// The format's version, 1.
	Version int `json:"version"`
	// The engine each platform pins, one entry a platform.
	Engines []*InferManifestEngine `json:"engines"`
	// The local models the release offers, one entry a model.
	Models []*InferManifestModel `json:"models"`
}

// The LiteRT-LM build one platform pins (§6.5, Q-INFER-2).
type InferManifestEngine struct {
	// GOOS/GOARCH: a desktop's or a phone's.
	Platform string `json:"platform"`
	// LiteRT-LM's version, pinned for this platform alone, so a release that breaks one platform keeps the last good
	// one there (Q-INFER-2).
	Version string `json:"version"`
	// The engine's C library, which the helper loads with purego; at least one on a desktop, none on a phone.
	Libraries []*InferManifestFile `json:"libraries"`
	// The closed GPU plugins, if any.
	GpuPlugins []*InferManifestFile `json:"gpu_plugins"`
	// Dawn's WebGPU library, where the version needs it even for CPU or Metal (#4611).
	Dawn *InferManifestFile `json:"dawn,omitempty"`
}

// One file a device downloads and checks before it moves it into place and again before load.
type InferManifestFile struct {
	// Its name in the state directory.
	Name string `json:"name"`
	// Where it is fetched from, https only. The SHA-256, not the host, is what the device trusts.
	Url string `json:"url"`
	// Its size in bytes, which bounds the download (INFER-M11-06).
	ByteCount int64 `json:"byte_count"`
	// Its SHA-256, in lowercase hex.
	Sha256 string `json:"sha256"`
}

// One file of a local model: a build for one accelerator, or every, on some platforms, or every.
type InferManifestModelFile struct {
	InferManifestFile
	// The accelerator the build is for, one of its model's; empty for any, such as one file every accelerator loads.
	Accelerator InferAccelerator `json:"accelerator,omitempty"`
	// The platforms it is for; empty for every platform.
	Platforms []string `json:"platforms,omitempty"`
}

// Whether the file serves platform.
func (self *InferManifestModelFile) servesPlatform(platform string) bool {
	return len(self.Platforms) == 0 || slices.Contains(self.Platforms, platform)
}

// A decode rate measured on a reference device (§6.5's table).
type InferDecodeRate struct {
	// The reference device, as the release measured it.
	Device string `json:"device"`
	// What it ran on.
	Accelerator InferAccelerator `json:"accelerator"`
	// Decoded tokens a second.
	TokensPerSecond float64 `json:"tokens_per_second"`
}

// One local model the release offers, named local-<model>-<effort> (§6.3), its catalog fields beside its files.
type InferManifestModel struct {
	// The model part: [a-z0-9.-], such as gemma-4-e4b.
	Model string `json:"model"`
	// The efforts it takes, off alone if it has no reasoning (§6.3).
	Efforts []InferEffort `json:"efforts"`
	// The effort an alias without one runs at (Q-INFER-5), one of Efforts.
	DefaultEffort InferEffort `json:"default_effort"`
	// Its context window, in tokens.
	ContextWindow int64 `json:"context_window"`
	// The most tokens one answer may hold, at most the window.
	MaxOutput int64 `json:"max_output"`
	// Whether it calls tools; a small model's tool use is weaker, and the catalog says so (§6.5).
	Tools bool `json:"tools"`
	// Whether it gives structured output, LiteRT-LM's LLGuidance mode (§6.5).
	StructuredOutput bool `json:"structured_output"`
	// What it takes in: text, and image where it reads images.
	Modalities []InferModality `json:"modalities"`
	// Its weights' license, as an SPDX id where there is one, such as Apache-2.0.
	License string `json:"license"`
	// The least memory a device needs to run it, in bytes.
	MinMemoryByteCount int64 `json:"min_memory_byte_count"`
	// What it runs on.
	Accelerators []InferAccelerator `json:"accelerators"`
	// Its files, at least one.
	Files []*InferManifestModelFile `json:"files"`
	// Decode rates measured on reference devices.
	DecodeRates []*InferDecodeRate `json:"decode_rates"`
}

// This build's manifest, parsed from the copy embedded in it.
func InferReleaseManifest(settings *InferSettings) (*InferManifest, error) {
	return ParseInferManifest(inferManifestJson, settings)
}

// The manifest data holds, refused with ErrInferManifestInvalid unless it is one JSON value of at most the settings'
// ManifestMaxByteCount, with no member twice or unknown, of this version, every entry whole (see the file's comment).
func ParseInferManifest(data []byte, settings *InferSettings) (*InferManifest, error) {
	if settings.ManifestMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInferManifestInvalid, settings.ManifestMaxByteCount)
	}
	// RFC 8785's reading refuses a member twice, invalid UTF-8 and anything after the one value, which the decoder
	// below would pass
	if _, err := CanonicalJson(data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInferManifestInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	manifest := &InferManifest{}
	if err := decoder.Decode(manifest); err != nil {
		return nil, fmt.Errorf("%w: does not decode", ErrInferManifestInvalid)
	}
	if err := manifest.validate(settings); err != nil {
		return nil, err
	}
	return manifest, nil
}

// The engine entry for platform, or nil where the manifest pins none.
func (self *InferManifest) Engine(platform string) *InferManifestEngine {
	for _, engine := range self.Engines {
		if engine.Platform == platform {
			return engine
		}
	}
	return nil
}

// The local model whose model part is model, or nil.
func (self *InferManifest) Model(model string) *InferManifestModel {
	for _, m := range self.Models {
		if m.Model == model {
			return m
		}
	}
	return nil
}

// A manifest fault, wrapping ErrInferManifestInvalid.
func inferManifestFault(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInferManifestInvalid, fmt.Sprintf(format, a...))
}

// Nil when the manifest is whole, else its first fault.
func (self *InferManifest) validate(settings *InferSettings) error {
	if self.Version != inferManifestVersion {
		return inferManifestFault("version %d, not %d", self.Version, inferManifestVersion)
	}
	platforms := map[string]bool{}
	for _, engine := range self.Engines {
		if engine == nil {
			return inferManifestFault("an empty engine entry")
		}
		if err := engine.validate(settings); err != nil {
			return err
		}
		if platforms[engine.Platform] {
			return inferManifestFault("the platform %s twice", engine.Platform)
		}
		platforms[engine.Platform] = true
	}
	models := map[string]bool{}
	for _, model := range self.Models {
		if model == nil {
			return inferManifestFault("an empty model entry")
		}
		if err := model.validate(settings); err != nil {
			return err
		}
		// one model part, one entry: no device accepts two entries of one name (§6.3)
		if models[model.Model] {
			return inferManifestFault("the model %s twice", model.Model)
		}
		models[model.Model] = true
	}
	return nil
}

// Nil when platform is one an entry may name, else why not.
func inferManifestPlatformFault(platform string) string {
	switch {
	case slices.Contains(inferDesktopPlatforms, platform) || slices.Contains(inferPhonePlatforms, platform):
		return ""
	case slices.Contains(inferUnbuiltPlatforms, platform):
		return "a platform with no engine build (" + platform + "), which gets remote models only"
	}
	return "an unknown platform"
}

// Nil when the engine entry is whole.
func (self *InferManifestEngine) validate(settings *InferSettings) error {
	if fault := inferManifestPlatformFault(self.Platform); fault != "" {
		return inferManifestFault("an engine for %s", fault)
	}
	if !inferManifestEngineVersionPattern.MatchString(self.Version) {
		return inferManifestFault("the engine for %s pins no version", self.Platform)
	}
	if slices.Contains(inferDesktopPlatforms, self.Platform) && len(self.Libraries) == 0 {
		return inferManifestFault("the engine for %s lists no library", self.Platform)
	}
	files := slices.Concat(self.Libraries, self.GpuPlugins)
	if self.Dawn != nil {
		files = append(files, self.Dawn)
	}
	names := map[string]bool{}
	for _, file := range files {
		if file == nil {
			return inferManifestFault("the engine for %s lists an empty file", self.Platform)
		}
		if fault := file.fault(settings); fault != "" {
			return inferManifestFault("the engine for %s lists %s", self.Platform, fault)
		}
		if names[file.Name] {
			return inferManifestFault("the engine for %s lists the file %s twice", self.Platform, file.Name)
		}
		names[file.Name] = true
	}
	return nil
}

// Empty when the file is whole, else what it lacks.
func (self *InferManifestFile) fault(settings *InferSettings) string {
	if !inferManifestFileNamePattern.MatchString(self.Name) {
		return "a file whose name is not a plain file name"
	}
	location, err := url.Parse(self.Url)
	if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || location.Fragment != "" {
		return "the file " + self.Name + " with no https URL"
	}
	if self.ByteCount <= 0 || settings.ManifestFileMaxByteCount < self.ByteCount {
		return fmt.Sprintf("the file %s with a size outside 1 to %d bytes", self.Name, settings.ManifestFileMaxByteCount)
	}
	if !inferManifestSha256Pattern.MatchString(self.Sha256) {
		return "the file " + self.Name + " with no SHA-256"
	}
	return ""
}

// Nil when the model entry is whole.
func (self *InferManifestModel) validate(settings *InferSettings) error {
	if fault := inferModelPartFault(self.Model); fault != "" {
		return inferManifestFault("a model with %s", fault)
	}
	fault := func(format string, a ...any) error {
		return inferManifestFault("the model %s: %s", self.Model, fmt.Sprintf(format, a...))
	}
	if settings.NameMaxByteCount < len(computeLocalProvider)+len(self.Model)+inferEffortMaxByteCount()+2 {
		return fault("a name longer than %d bytes", settings.NameMaxByteCount)
	}
	if len(self.Efforts) == 0 {
		return fault("no effort")
	}
	for i, effort := range self.Efforts {
		if !effort.Valid() {
			return fault("an unknown effort")
		}
		if slices.Contains(self.Efforts[:i], effort) {
			return fault("the effort %s twice", effort)
		}
	}
	if !slices.Contains(self.Efforts, self.DefaultEffort) {
		return fault("a default effort it does not list")
	}
	if self.ContextWindow <= 0 || self.MaxOutput <= 0 || self.ContextWindow < self.MaxOutput {
		return fault("a context window and maximum output that are not positive, the output within the window")
	}
	if !slices.Contains(self.Modalities, InferModalityText) {
		return fault("no text modality")
	}
	for i, modality := range self.Modalities {
		if !slices.Contains(inferModalities, modality) || slices.Contains(self.Modalities[:i], modality) {
			return fault("an unknown or repeated modality")
		}
	}
	if self.License == "" {
		return fault("no license")
	}
	if self.MinMemoryByteCount <= 0 {
		return fault("no minimum memory")
	}
	if len(self.Accelerators) == 0 {
		return fault("no accelerator")
	}
	for i, accelerator := range self.Accelerators {
		if !slices.Contains(inferAccelerators, accelerator) || slices.Contains(self.Accelerators[:i], accelerator) {
			return fault("an unknown or repeated accelerator")
		}
	}
	if len(self.Files) == 0 {
		return fault("no file")
	}
	names := map[string]bool{}
	for _, file := range self.Files {
		if file == nil {
			return fault("an empty file")
		}
		if fileFault := file.fault(settings); fileFault != "" {
			return fault("%s", fileFault)
		}
		if names[file.Name] {
			return fault("the file %s twice", file.Name)
		}
		names[file.Name] = true
		if file.Accelerator != "" && !slices.Contains(self.Accelerators, file.Accelerator) {
			return fault("the file %s for an accelerator the model does not list", file.Name)
		}
		for i, platform := range file.Platforms {
			if platformFault := inferManifestPlatformFault(platform); platformFault != "" {
				return fault("the file %s for %s", file.Name, platformFault)
			}
			if slices.Contains(file.Platforms[:i], platform) {
				return fault("the file %s names a platform twice", file.Name)
			}
		}
	}
	for _, rate := range self.DecodeRates {
		if rate == nil || rate.Device == "" || !slices.Contains(self.Accelerators, rate.Accelerator) ||
			!(0 < rate.TokensPerSecond) || math.IsInf(rate.TokensPerSecond, 0) {
			return fault("a decode rate with no device, an accelerator it does not list, or no positive rate")
		}
	}
	return nil
}
