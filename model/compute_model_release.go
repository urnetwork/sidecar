// The release's tooling around the api's model mirror (DESIGN-COMPUTE §6.5's mirror row, §14.5; DESIGN §4.10; CO-49;
// CSRV-M11-02): the draft manifest, whose model files take their index pins from the mirror before the release is
// signed, and the release's signed SHA256SUMS, which must list a released manifest before the mirror serves its files.
//
// A draft is infer_manifest.json before its index pins: INFER-M11-10's format, every member as a released manifest has
// it, but a model file may lack its index_sha256, which the tooling's index step writes from the mirror. A draft is
// held to every other rule of the format by ParseInferManifest itself: each missing pin stands in as a placeholder no
// index hashes to, derived from the file's SHA-256 so one file keeps one pin, and is cleared again after the parse.
// The pinned draft is written as indented JSON of the same members, and must parse under ParseInferManifest, every
// pin in place, before it is the release's manifest. The release's pipeline signs it after (DESIGN §4.10).
//
// SHA256SUMS is `shasum -a 256`'s text form, as build/all/ursums writes it: one line a file, its lowercase hex SHA-256,
// two spaces and its plain name, each line ended by a newline. The release key signs it under ur-release
// (sidecar.VerifyComputeReleaseSignature); the mirror serves a released manifest's files only once those signed sums
// list the manifest's own SHA-256, so an unsigned or draft manifest serves nothing. A build pins no release key until
// the key ceremony, so until then every manifest is refused.
//
// Every function here is a function of its arguments, so safe for concurrent use.

package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
)

// The label a missing pin's placeholder is derived under.
const computeModelDraftPinLabel = "urnetwork compute model draft pin "

// A release's sums or their signature refused: past their bounds, not shasum's form, not signed by the release key, or
// not listing what they must. Wrapped beside the signature's own refusal where that is the reason.
var ErrComputeModelReleaseRefused = errors.New("release sums refused")

// The manifest data holds, a draft: as sidecar.ParseInferManifest, but a model file may carry no index_sha256, which
// reads empty. Refused with sidecar.ErrInferManifestInvalid as ParseInferManifest refuses.
func ParseComputeModelDraftManifest(data []byte, inferSettings *sidecar.InferSettings) (*sidecar.InferManifest, error) {
	if inferSettings.ManifestMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: longer than %d bytes", sidecar.ErrInferManifestInvalid, inferSettings.ManifestMaxByteCount)
	}
	// RFC 8785's reading refuses a member twice, invalid UTF-8 and anything after the one value
	if _, err := sidecar.CanonicalJson(data); err != nil {
		return nil, fmt.Errorf("%w: %w", sidecar.ErrInferManifestInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	manifest := &sidecar.InferManifest{}
	if err := decoder.Decode(manifest); err != nil {
		return nil, fmt.Errorf("%w: does not decode", sidecar.ErrInferManifestInvalid)
	}
	placeholders := map[*sidecar.InferManifestModelFile]bool{}
	for _, model := range manifest.Models {
		if model == nil {
			continue
		}
		for _, file := range model.Files {
			if file != nil && file.IndexSha256 == "" {
				placeholder := sha256.Sum256([]byte(computeModelDraftPinLabel + file.Sha256))
				file.IndexSha256 = hex.EncodeToString(placeholder[:])
				placeholders[file] = true
			}
		}
	}
	held, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: does not encode", sidecar.ErrInferManifestInvalid)
	}
	if _, err := sidecar.ParseInferManifest(held, inferSettings); err != nil {
		return nil, err
	}
	for file := range placeholders {
		file.IndexSha256 = ""
	}
	return manifest, nil
}

// The model files a manifest names, one for each SHA-256, in the order of their first entry: one SHA-256 is one file,
// which the manifest's parse holds to one size and one index pin.
func ComputeModelManifestFiles(manifest *sidecar.InferManifest) []*sidecar.InferManifestModelFile {
	files := []*sidecar.InferManifestModelFile{}
	listed := map[string]bool{}
	for _, model := range manifest.Models {
		if model == nil {
			continue
		}
		for _, file := range model.Files {
			if file == nil || listed[file.Sha256] {
				continue
			}
			listed[file.Sha256] = true
			files = append(files, file)
		}
	}
	return files
}

// The draft's bytes with every model file's index_sha256 set from sha256IndexSha256s, by the file's SHA-256: indented
// JSON with a final newline, held to parse under sidecar.ParseInferManifest. Refused where a file has no pin in the map,
// or already carries another than the map's, so the tooling never moves a pin silently. manifest is left as it was.
func ComputeModelDraftManifestPinned(manifest *sidecar.InferManifest, sha256IndexSha256s map[string]string, inferSettings *sidecar.InferSettings) ([]byte, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: does not encode", sidecar.ErrInferManifestInvalid)
	}
	pinned := &sidecar.InferManifest{}
	if err := json.Unmarshal(encoded, pinned); err != nil {
		return nil, fmt.Errorf("%w: does not decode", sidecar.ErrInferManifestInvalid)
	}
	for _, model := range pinned.Models {
		if model == nil {
			continue
		}
		for _, file := range model.Files {
			if file == nil {
				continue
			}
			indexSha256, ok := sha256IndexSha256s[file.Sha256]
			if !ok || !computeModelSha256Valid(indexSha256) {
				return nil, computeModelMirrorRefusal("no index pin for %s", file.Sha256)
			}
			if file.IndexSha256 != "" && file.IndexSha256 != indexSha256 {
				return nil, computeModelMirrorRefusal("%s already pins the index %s, and the mirror's is %s", file.Sha256, file.IndexSha256, indexSha256)
			}
			file.IndexSha256 = indexSha256
		}
	}
	data, err := json.MarshalIndent(pinned, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: does not encode", sidecar.ErrInferManifestInvalid)
	}
	data = append(data, '\n')
	if _, err := sidecar.ParseInferManifest(data, inferSettings); err != nil {
		return nil, err
	}
	return data, nil
}

// A release's SHA256SUMS whose signature verified: each file's lowercase hex SHA-256 to the name it is listed under.
type ComputeModelReleaseSums struct {
	sha256Names map[string]string
	names       map[string]bool
}

// The sums of a release, once signature, an armored SSHSIG over sums' exact bytes, verifies under ur-release by one of
// releaseKeys, and sums is shasum's text form: one line a file, a lowercase hex SHA-256, two spaces and a plain name,
// no name twice. Refused with ErrComputeModelReleaseRefused past the settings' bounds, with the signature's own refusal
// beside it, sidecar.ErrComputeReleaseKeyAbsent where releaseKeys is empty, and for any line not of that form.
func VerifyComputeModelReleaseSums(sums []byte, signature []byte, releaseKeys []ssh.PublicKey, settings *ComputeModelMirrorSettings) (*ComputeModelReleaseSums, error) {
	if settings.ReleaseSumsMaxByteCount < int64(len(sums)) || settings.ReleaseSignatureMaxByteCount < int64(len(signature)) {
		return nil, fmt.Errorf("%w: past %d bytes of sums or %d of signature", ErrComputeModelReleaseRefused,
			settings.ReleaseSumsMaxByteCount, settings.ReleaseSignatureMaxByteCount)
	}
	if err := sidecar.VerifyComputeReleaseSignature(sums, signature, releaseKeys); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrComputeModelReleaseRefused, err)
	}
	refuse := func(line int, why string) error {
		return fmt.Errorf("%w: line %d %s", ErrComputeModelReleaseRefused, line, why)
	}
	text, ok := bytes.CutSuffix(sums, []byte("\n"))
	if !ok || len(text) == 0 {
		return nil, refuse(1, "is not ended by a newline")
	}
	releaseSums := &ComputeModelReleaseSums{
		sha256Names: map[string]string{},
		names:       map[string]bool{},
	}
	for index, line := range strings.Split(string(text), "\n") {
		sha256Text, name, ok := strings.Cut(line, "  ")
		switch {
		case !ok || !computeModelSha256Valid(sha256Text):
			return nil, refuse(index+1, "is not a lowercase hex SHA-256, two spaces and a name")
		case !computeModelHubSegmentPlain(name) || strings.HasPrefix(name, "."):
			return nil, refuse(index+1, "names no plain file")
		case releaseSums.names[name]:
			return nil, refuse(index+1, "names a file twice")
		}
		releaseSums.names[name] = true
		if _, listed := releaseSums.sha256Names[sha256Text]; !listed {
			releaseSums.sha256Names[sha256Text] = name
		}
	}
	return releaseSums, nil
}

// The name the sums list a file of this lowercase hex SHA-256 under, the first where several files share it; false
// where they list none.
func (self *ComputeModelReleaseSums) Lists(sha256Text string) (string, bool) {
	name, ok := self.sha256Names[sha256Text]
	return name, ok
}
