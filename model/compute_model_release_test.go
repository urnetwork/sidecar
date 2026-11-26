package model

// The release tooling's half in model (CSRV-M11-02; DESIGN-COMPUTE §6.5; DESIGN §4.10): a draft manifest parses
// without its index pins and is held to every other rule of the format; the pinned draft parses as a released manifest
// and never moves a pin; and a release's SHA256SUMS is taken only under the release key's signature, in shasum's form.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
)

// The draft fixture's bytes.
func testComputeModelDraftJson(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testComputeModelVectorDirectory, "draft.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A draft parses with no pin on its files, which read empty, and its two files once each though one is listed twice;
// ParseInferManifest refuses the same bytes for the missing pins.
func TestComputeModelDraftManifestParsesWithoutPins(t *testing.T) {
	inferSettings := testComputeModelInferSettings()
	data := testComputeModelDraftJson(t)
	manifest, err := ParseComputeModelDraftManifest(data, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	files := ComputeModelManifestFiles(manifest)
	if len(manifest.Models) != 2 || len(files) != 2 {
		t.Fatalf("%d models, %d files", len(manifest.Models), len(files))
	}
	for _, model := range manifest.Models {
		for _, file := range model.Files {
			if file.IndexSha256 != "" {
				t.Fatalf("%s reads the pin %s", file.Name, file.IndexSha256)
			}
		}
	}
	if _, err := sidecar.ParseInferManifest(data, inferSettings); !errors.Is(err, sidecar.ErrInferManifestInvalid) {
		t.Fatalf("a released manifest's parse took the draft: %v", err)
	}
}

// A draft is held to every rule but the pins: a member unknown or twice, a file with no SHA-256, a url that is not
// https, a malformed pin and one file under two pins are each refused as the format refuses them.
func TestComputeModelDraftManifestRefusesWhatTheFormatRefuses(t *testing.T) {
	inferSettings := testComputeModelInferSettings()
	draft := string(testComputeModelDraftJson(t))
	cases := map[string]string{
		"an unknown member": strings.Replace(draft, `"version": 1,`, `"version": 1, "mirror": true,`, 1),
		"a member twice":    strings.Replace(draft, `"version": 1,`, `"version": 1, "version": 1,`, 1),
		"no SHA-256":        strings.Replace(draft, `"sha256": "35aeff7e048974ee23c365c8faf6bcb868ca0529c69309a00f6cde98bfbf89ce"`, `"sha256": ""`, 1),
		"no https":          strings.Replace(draft, `"url": "https://hub.example/litert-community/test-mirror-a`, `"url": "http://hub.example/litert-community/test-mirror-a`, 1),
		"a malformed pin": strings.Replace(draft, `"byte_count": 2621440,`,
			`"byte_count": 2621440, "index_sha256": "abc",`, 1),
		"one file under two pins": strings.Replace(draft, `"accelerator": "gpu"
        }`, `"accelerator": "gpu",
          "index_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }`, 1),
		"a second version": strings.Replace(draft, `"version": 1,`, `"version": 2,`, 1),
	}
	for name, text := range cases {
		if text == draft {
			t.Fatalf("%s: the case changed nothing", name)
		}
		if _, err := ParseComputeModelDraftManifest([]byte(text), inferSettings); !errors.Is(err, sidecar.ErrInferManifestInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	small := testComputeModelInferSettings()
	small.ManifestMaxByteCount = len(draft) - 1
	if _, err := ParseComputeModelDraftManifest([]byte(draft), small); !errors.Is(err, sidecar.ErrInferManifestInvalid) {
		t.Errorf("a draft past its bound: %v", err)
	}
}

// The pinned draft carries every pin and parses as a released manifest; a file with no pin in the map, or already
// pinning another, is refused; the draft parsed is left as it was.
func TestComputeModelDraftManifestPinned(t *testing.T) {
	inferSettings := testComputeModelInferSettings()
	manifest, err := ParseComputeModelDraftManifest(testComputeModelDraftJson(t), inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	files := ComputeModelManifestFiles(manifest)
	pins := map[string]string{}
	for _, file := range files {
		pins[file.Sha256] = testComputeModelSha256([]byte("index of " + file.Sha256))
	}
	data, err := ComputeModelDraftManifestPinned(manifest, pins, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	released, err := sidecar.ParseInferManifest(data, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	for _, model := range released.Models {
		for _, file := range model.Files {
			if file.IndexSha256 != pins[file.Sha256] {
				t.Fatalf("%s pins %s", file.Name, file.IndexSha256)
			}
		}
	}
	if files[0].IndexSha256 != "" {
		t.Fatal("pinning changed the draft parsed")
	}

	missing := map[string]string{files[0].Sha256: pins[files[0].Sha256]}
	if _, err := ComputeModelDraftManifestPinned(manifest, missing, inferSettings); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("a file with no pin: %v", err)
	}
	moved := map[string]string{}
	for sha256Text := range pins {
		moved[sha256Text] = testComputeModelSha256([]byte("another index of " + sha256Text))
	}
	if _, err := ComputeModelDraftManifestPinned(released, moved, inferSettings); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("a pin moved: %v", err)
	}
	again, err := ComputeModelDraftManifestPinned(released, pins, inferSettings)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatalf("pinning a pinned manifest again: %v", err)
	}
}

// A test release key, the same every run.
func testComputeModelReleaseKey(t *testing.T, label string) ssh.Signer {
	t.Helper()
	seed := sha256.Sum256([]byte("urnetwork-sidecar test model release key " + label))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// The sums signed by signer under namespace.
func testComputeModelReleaseSign(t *testing.T, signer ssh.Signer, namespace string, sums []byte) []byte {
	t.Helper()
	signature, err := sidecar.ComputeSshsigSign(bytes.NewReader(make([]byte, 64)), signer, namespace, sums)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// Sums the release key signed read each file's hash by name; with no key pinned, by another key, under another
// namespace or over other bytes they are refused, as is each line not in shasum's form and sums past their bound.
func TestComputeModelReleaseSumsTakeOnlyTheReleaseKeysSignature(t *testing.T) {
	settings := DefaultComputeModelMirrorSettings()
	release := testComputeModelReleaseKey(t, "release")
	pinned := []ssh.PublicKey{release.PublicKey()}
	manifestSha256 := testComputeModelSha256([]byte("a manifest"))
	sums := []byte(testComputeModelSha256([]byte("ur")) + "  ur-2026.11.26-1-linux-amd64.tar.gz\n" +
		manifestSha256 + "  infer_manifest.json\n" +
		testComputeModelSha256([]byte("release")) + "  ur-release.json\n")
	signature := testComputeModelReleaseSign(t, release, "ur-release", sums)

	releaseSums, err := VerifyComputeModelReleaseSums(sums, signature, pinned, settings)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := releaseSums.Lists(manifestSha256); !ok || name != "infer_manifest.json" {
		t.Fatalf("the manifest's hash reads %q, %t", name, ok)
	}
	if _, ok := releaseSums.Lists(testComputeModelSha256([]byte("a draft"))); ok {
		t.Fatal("the sums list a hash they do not hold")
	}

	refusals := map[string]error{}
	_, refusals["no key"] = VerifyComputeModelReleaseSums(sums, signature, nil, settings)
	_, refusals["another key"] = VerifyComputeModelReleaseSums(sums, signature, []ssh.PublicKey{testComputeModelReleaseKey(t, "other").PublicKey()}, settings)
	_, refusals["another namespace"] = VerifyComputeModelReleaseSums(sums, testComputeModelReleaseSign(t, release, sidecar.ComputePolicyNamespace, sums), pinned, settings)
	_, refusals["other bytes"] = VerifyComputeModelReleaseSums(append(bytes.Clone(sums), sums[:80]...), signature, pinned, settings)
	for name, err := range refusals {
		if !errors.Is(err, ErrComputeModelReleaseRefused) || !errors.Is(err, sidecar.ErrComputeReleaseSignatureRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !errors.Is(refusals["no key"], sidecar.ErrComputeReleaseKeyAbsent) {
		t.Errorf("no key: %v", refusals["no key"])
	}

	line := manifestSha256 + "  infer_manifest.json\n"
	for name, bad := range map[string]string{
		"no final newline":  strings.TrimSuffix(line, "\n"),
		"an empty line":     line + "\n" + line,
		"one space":         manifestSha256 + " infer_manifest.json\n",
		"binary mode":       manifestSha256 + " *infer_manifest.json\n",
		"uppercase hex":     strings.ToUpper(manifestSha256) + "  infer_manifest.json\n",
		"a path":            manifestSha256 + "  ../infer_manifest.json\n",
		"a hidden name":     manifestSha256 + "  .infer_manifest.json\n",
		"a name twice":      line + testComputeModelSha256([]byte("b")) + "  infer_manifest.json\n",
		"a carriage return": manifestSha256 + "  infer_manifest.json\r\n",
		"empty":             "",
	} {
		_, err := VerifyComputeModelReleaseSums([]byte(bad), testComputeModelReleaseSign(t, release, "ur-release", []byte(bad)), pinned, settings)
		if !errors.Is(err, ErrComputeModelReleaseRefused) || errors.Is(err, sidecar.ErrComputeReleaseSignatureRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}

	small := DefaultComputeModelMirrorSettings()
	small.ReleaseSumsMaxByteCount = int64(len(sums) - 1)
	if _, err := VerifyComputeModelReleaseSums(sums, signature, pinned, small); !errors.Is(err, ErrComputeModelReleaseRefused) {
		t.Errorf("sums past their bound: %v", err)
	}
	small = DefaultComputeModelMirrorSettings()
	small.ReleaseSignatureMaxByteCount = int64(len(signature) - 1)
	if _, err := VerifyComputeModelReleaseSums(sums, signature, pinned, small); !errors.Is(err, ErrComputeModelReleaseRefused) {
		t.Errorf("a signature past its bound: %v", err)
	}
}
