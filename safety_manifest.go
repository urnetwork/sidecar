//go:build !ios_extension && !sidecar_http

// The release's classifier pins (DESIGN-COMPUTE §27.5's Shipping and Falling back; SAFE-M13-05): safety_manifest.json,
// embedded in each build of ur and the sdk beside infer_manifest.json, and so signed with the release it ships in, as
// §6.5's manifest is (DESIGN §4.10's SHA256SUMS; the apps' stores). Its entries are the release pipeline's: URnetwork
// exports and quantizes each model from Meta's published weights, names it as the Llama 4 Community License asks, and
// publishes each file with the release's assets (External). A source build carries the format and no entry, so it
// pins no classifier, and every verdict asks.
//
// What it pins:
//
//   - the release it belongs to, which every auto_verdict entry names (§27.9);
//   - Unicode's confusables.txt for the release's Unicode version, the normalized view's skeletons (QD-1368);
//   - ONNX Runtime's C library per desktop platform, with its version and the OrtApi version the binding asks for,
//     which the ur-engine helper loads (SAFE-M13-03); the apps embed their own reduced runtime and fetch none;
//   - each model, Llama Prompt Guard 2's 22M or 86M at int8 (Q-SAFE-1, QD-1345): its file, its SentencePiece
//     vocabulary, the device classes that run it (the 22M on phones, the 86M on laptops and desktops, Macs and
//     enclaves among them), its calibrated threshold in basis points, and its auto switch, off for a release whose
//     model has not passed the bench (§18), so its devices ask.
//
// Every file carries its https url on URnetwork's release host, its size and its SHA-256, and a device loads none until
// its bytes match (SafetyModelStore). The threshold and the switch come from here alone, never from a server's answer
// or a setting (Q-SAFE-6): a model or a threshold changes only with a release.
//
// The parse is strict, as §6.5's is: one JSON value within ManifestMaxByteCount, no member twice or unknown, this
// version, and every entry whole: a known model name, no class run by two models, a threshold from 1 to
// MaxThresholdBasisPoints, every file named, plain, on https, within its kind's size bound and pinned, a name two
// entries share pinned alike, runtimes only for the desktops that run the helper, and confusables wherever a model is
// named. A refusal names its first fault, matches ErrSafetyManifestInvalid and ErrSafetyUnavailable, and never repeats
// the document's bytes.
//
// A parsed manifest is read only, so safe for concurrent use.

package sidecar

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
)

// This build's classifier pins. A source build's holds the format and no entry.
//
//go:embed safety_manifest.json
var safetyManifestJson []byte

// The format's version, which the file's version member carries.
const safetyManifestVersion = 1

// The models a manifest may name: Llama Prompt Guard 2 as URnetwork's release exports it at int8, "Llama" first in each
// name, as the license asks of a model made from it.
const (
	SafetyModelPromptGuard22M = "Llama-Prompt-Guard-2-22M-ur-int8"
	SafetyModelPromptGuard86M = "Llama-Prompt-Guard-2-86M-ur-int8"
)

// The model names a manifest may give.
var safetyManifestModelNames = []string{SafetyModelPromptGuard22M, SafetyModelPromptGuard86M}

// A release's version, as `ur version` prints it: yyyy.m.d and the build's code.
var safetyManifestReleasePattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}-[0-9A-Za-z][0-9A-Za-z.+-]*$`)

// ONNX Runtime's version, as its release names it.
var safetyManifestRuntimeVersionPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.]+)?$`)

// A manifest that does not parse, or an entry in it that is not whole. Every refusal also matches
// ErrSafetyUnavailable.
var ErrSafetyManifestInvalid = errors.New("safety manifest refused")

// A manifest refusal, naming the first fault.
func safetyManifestFault(format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrSafetyUnavailable, ErrSafetyManifestInvalid, fmt.Sprintf(format, a...))
}

// safety_manifest.json's content (see the file comment).
type SafetyManifest struct {
	// The format's version, 1.
	Version int `json:"version"`
	// The ur release this manifest ships in; empty in a source build, which names nothing.
	Release string `json:"release"`
	// Unicode's confusables.txt; required wherever a model is named.
	Confusables *SafetyManifestFile `json:"confusables,omitempty"`
	// ONNX Runtime's C library per desktop platform.
	Runtimes []*SafetyManifestRuntime `json:"runtimes"`
	// The classifier's models.
	Models []*SafetyManifestModel `json:"models"`
}

// One file a device downloads and checks before it loads it.
type SafetyManifestFile struct {
	// Its name in the state directory: a letter or digit first, then letters, digits, ".", "_" and "-".
	Name string `json:"name"`
	// Where it is fetched from, https only: URnetwork's release host, which sees a download as it sees an update's.
	Url string `json:"url"`
	// Its size in bytes, which bounds the download.
	ByteCount int64 `json:"byte_count"`
	// Its SHA-256, in lowercase hex.
	Sha256 string `json:"sha256"`
}

// ONNX Runtime's build for one desktop platform.
type SafetyManifestRuntime struct {
	// GOOS/GOARCH, one of the desktops whose ur runs the ur-engine helper.
	Platform string `json:"platform"`
	// ONNX Runtime's version, such as 1.22.0.
	Version string `json:"version"`
	// The OrtApi version the binding asks the library for, which a library older than it refuses.
	ApiVersion uint32 `json:"api_version"`
	// The C library.
	Library *SafetyManifestFile `json:"library"`
}

// One classifier model.
type SafetyManifestModel struct {
	// One of SafetyModelPromptGuard22M and SafetyModelPromptGuard86M.
	Name string `json:"name"`
	// The device classes that run it, each run by one model at most.
	DeviceClasses []InferDeviceClass `json:"device_classes"`
	// The calibrated threshold, in basis points: a verdict allows only under it (§27.6).
	ThresholdBasisPoints int `json:"threshold_basis_points"`
	// Whether its devices decide automatically at all; off where the model failed the bench.
	Auto bool `json:"auto"`
	// The exported model, ONNX at int8.
	Model *SafetyManifestFile `json:"model"`
	// Its SentencePiece vocabulary.
	Vocabulary *SafetyManifestFile `json:"vocabulary"`
}

// This build's pins, parsed from the copy embedded in it.
func SafetyReleaseManifest(settings *SafetySettings) (*SafetyManifest, error) {
	return ParseSafetyManifest(safetyManifestJson, settings)
}

// The manifest data holds, refused as the file comment says.
func ParseSafetyManifest(data []byte, settings *SafetySettings) (*SafetyManifest, error) {
	if settings.ManifestMaxByteCount < len(data) {
		return nil, safetyManifestFault("longer than %d bytes", settings.ManifestMaxByteCount)
	}
	// RFC 8785's reading refuses a member twice, invalid UTF-8 and anything after the one value
	if _, err := CanonicalJson(data); err != nil {
		return nil, safetyManifestFault("%s", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	manifest := &SafetyManifest{}
	if err := decoder.Decode(manifest); err != nil {
		return nil, safetyManifestFault("does not decode")
	}
	if err := manifest.validate(settings); err != nil {
		return nil, err
	}
	return manifest, nil
}

// Nil when the manifest is whole, else its first fault.
func (self *SafetyManifest) validate(settings *SafetySettings) error {
	if self.Version != safetyManifestVersion {
		return safetyManifestFault("version %d, not %d", self.Version, safetyManifestVersion)
	}
	if len(self.Models) == 0 && len(self.Runtimes) == 0 && self.Confusables == nil {
		// a source build's: the format and nothing pinned
		return nil
	}
	if !safetyManifestReleasePattern.MatchString(self.Release) {
		return safetyManifestFault("no release named")
	}
	// one name is one file, which two entries may share, as the two models share one vocabulary, but under one pin
	names := map[string]SafetyManifestFile{}
	file := func(what string, file *SafetyManifestFile, maxByteCount int64) error {
		if file == nil {
			return safetyManifestFault("%s has no file", what)
		}
		if !inferManifestFileNamePattern.MatchString(file.Name) {
			return safetyManifestFault("%s's file has no plain name", what)
		}
		if other, ok := names[file.Name]; ok && other != *file {
			return safetyManifestFault("the file %s under two pins", file.Name)
		}
		names[file.Name] = *file
		location, err := url.Parse(file.Url)
		if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || location.Fragment != "" {
			return safetyManifestFault("%s's file %s has no https url", what, file.Name)
		}
		if file.ByteCount <= 0 || maxByteCount < file.ByteCount {
			return safetyManifestFault("%s's file %s is not 1 to %d bytes", what, file.Name, maxByteCount)
		}
		if !inferManifestSha256Pattern.MatchString(file.Sha256) {
			return safetyManifestFault("%s's file %s has no SHA-256", what, file.Name)
		}
		return nil
	}
	if 0 < len(self.Models) && self.Confusables == nil {
		return safetyManifestFault("models with no confusables table")
	}
	if self.Confusables != nil {
		if err := file("the confusables table", self.Confusables, int64(settings.ConfusablesMaxByteCount)); err != nil {
			return err
		}
	}
	platforms := map[string]bool{}
	for _, runtime := range self.Runtimes {
		if runtime == nil {
			return safetyManifestFault("an empty runtime entry")
		}
		if !slices.Contains(inferDesktopPlatforms, runtime.Platform) {
			return safetyManifestFault("a runtime for %q, which runs no ur-engine helper", runtime.Platform)
		}
		if platforms[runtime.Platform] {
			return safetyManifestFault("two runtimes for %s", runtime.Platform)
		}
		platforms[runtime.Platform] = true
		if !safetyManifestRuntimeVersionPattern.MatchString(runtime.Version) || runtime.ApiVersion == 0 {
			return safetyManifestFault("the runtime for %s pins no version", runtime.Platform)
		}
		if err := file("the runtime for "+runtime.Platform, runtime.Library, settings.RuntimeMaxByteCount); err != nil {
			return err
		}
	}
	classes := map[InferDeviceClass]bool{}
	models := map[string]bool{}
	for _, model := range self.Models {
		if model == nil {
			return safetyManifestFault("an empty model entry")
		}
		if !slices.Contains(safetyManifestModelNames, model.Name) {
			return safetyManifestFault("a model named %q, which no release exports", model.Name)
		}
		if models[model.Name] {
			return safetyManifestFault("the model %s twice", model.Name)
		}
		models[model.Name] = true
		if len(model.DeviceClasses) == 0 {
			return safetyManifestFault("the model %s runs on no device class", model.Name)
		}
		for _, class := range model.DeviceClasses {
			if !slices.Contains([]InferDeviceClass{InferDeviceClassPhone, InferDeviceClassLaptop, InferDeviceClassDesktop}, class) {
				return safetyManifestFault("the model %s for the unknown class %q", model.Name, class)
			}
			if classes[class] {
				return safetyManifestFault("two models for the class %s", class)
			}
			classes[class] = true
		}
		if model.ThresholdBasisPoints < 1 || settings.MaxThresholdBasisPoints < model.ThresholdBasisPoints {
			return safetyManifestFault("the model %s's threshold %d, not 1 to %d", model.Name, model.ThresholdBasisPoints, settings.MaxThresholdBasisPoints)
		}
		if err := file("the model "+model.Name, model.Model, settings.ModelMaxByteCount); err != nil {
			return err
		}
		if err := file("the model "+model.Name+"'s vocabulary", model.Vocabulary, int64(settings.VocabularyMaxByteCount)); err != nil {
			return err
		}
	}
	return nil
}

// The model a device of class runs, or nil where the release pins none for it.
func (self *SafetyManifest) ModelFor(class InferDeviceClass) *SafetyManifestModel {
	for _, model := range self.Models {
		if slices.Contains(model.DeviceClasses, class) {
			return model
		}
	}
	return nil
}

// The runtime a desktop of platform loads, or nil where the release pins none for it.
func (self *SafetyManifest) RuntimeFor(platform string) *SafetyManifestRuntime {
	for _, runtime := range self.Runtimes {
		if runtime.Platform == platform {
			return runtime
		}
	}
	return nil
}
