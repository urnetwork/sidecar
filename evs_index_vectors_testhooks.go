//go:build sidecar_testhooks && !ios_extension

// The index vectors as a module that requires this one builds them (SEARCH-M10-41; D-TEST-15, FI-22, §4.7): sdk's
// sidecar_index_vectors_test.go calls this in the binary sdk builds, where the module graph that selects the apps'
// golang.org/x/text is sdk's, not this repository's, so a leg whose graph picks another x/text, or a toolchain whose
// tables differ, fails there as it fails here. The root's own tests reproduce every file under testdata/index/; this
// reproduces the three whose bytes ride on x/text and the codecs alone: normalize, slot and shard.
//
// Nothing here holds or derives a key. Only the sidecar_testhooks build has it, which no release leg is (§22.4).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed testdata/index/normalize/vectors.json testdata/index/slot/vectors.json testdata/index/shard/vectors.json
var testHookIndexVectorFiles embed.FS

// The vector files TestHookIndexVectorFindings reads.
const (
	testHookNormalizeVectorPath = "testdata/index/normalize/vectors.json"
	testHookSlotVectorPath      = "testdata/index/slot/vectors.json"
	testHookShardVectorPath     = "testdata/index/shard/vectors.json"
)

// The tables this build links: norm.Version, cases.UnicodeVersion, unicode.Version and golang.org/x/text's module
// version, unreplaced, as runtime/debug reports it ("" where it is absent or replaced).
func TestHookIndexLinkedTables() (normVersion string, casesVersion string, unicodeVersion string, textModuleVersion string) {
	tables := indexLinkedTables()
	return tables.normVersion, tables.casesVersion, tables.unicodeVersion, tables.textModuleVersion
}

// What this build gives of testdata/index's normalize, slot and shard vectors, a finding each difference: the linked
// tables against normalizer 1's and against those the normalize vectors were written under; each text normalized,
// and its body's key set, to the bytes and hashes the vectors hold; each slot and whole shard decoded by the canonical
// decoders and encoded again to its bytes and hash. Empty is the pass.
func TestHookIndexVectorFindings() []string {
	findings := []string{}
	tables := indexLinkedTables()
	if !tables.isNormalizerOne() {
		findings = append(findings, fmt.Sprintf("this build links %s, %s, %s and x/text %q, not normalizer 1's %s and %s",
			tables.normVersion, tables.casesVersion, tables.unicodeVersion, tables.textModuleVersion,
			indexNormalizerUnicodeVersion, indexNormalizerTextModuleVersion))
		return findings
	}
	findings = append(findings, testHookNormalizeVectorFindings(tables)...)
	findings = append(findings, testHookCodecVectorFindings(testHookSlotVectorPath, func(file []byte, sum []byte, companion bool) ([]byte, error) {
		slot, err := indexDecodeSlot(file, sum, companion, DefaultIndexFormatSettings())
		if err != nil {
			return nil, err
		}
		return indexEncodeSlot(slot, companion, DefaultIndexFormatSettings())
	})...)
	findings = append(findings, testHookCodecVectorFindings(testHookShardVectorPath, func(file []byte, sum []byte, companion bool) ([]byte, error) {
		shard, err := indexDecodeShard(file, sum, companion)
		if err != nil {
			return nil, err
		}
		return indexNewShardBuilder(companion).encode(shard)
	})...)
	return findings
}

// The normalize vectors under tables.
func testHookNormalizeVectorFindings(tables indexTables) []string {
	findings := []string{}
	encoded, err := testHookIndexVectorFiles.ReadFile(testHookNormalizeVectorPath)
	if err != nil {
		return []string{err.Error()}
	}
	file := struct {
		NormVersion       string `json:"norm_version"`
		CasesVersion      string `json:"cases_version"`
		UnicodeVersion    string `json:"unicode_version"`
		TextModuleVersion string `json:"text_module_version"`
		Vectors           []struct {
			Name             string `json:"name"`
			TextHex          string `json:"text_hex"`
			NormalizedHex    string `json:"normalized_hex"`
			NormalizedSha256 string `json:"normalized_sha256"`
			KeySetSha256     string `json:"key_set_sha256"`
		} `json:"vectors"`
	}{}
	if err := json.Unmarshal(encoded, &file); err != nil {
		return []string{fmt.Sprintf("%s: %v", testHookNormalizeVectorPath, err)}
	}
	if file.NormVersion != tables.normVersion || file.CasesVersion != tables.casesVersion ||
		file.UnicodeVersion != tables.unicodeVersion || file.TextModuleVersion != tables.textModuleVersion {
		findings = append(findings, fmt.Sprintf("the normalize vectors were written under %s %s %s %s, and this build links %s %s %s %s",
			file.NormVersion, file.CasesVersion, file.UnicodeVersion, file.TextModuleVersion,
			tables.normVersion, tables.casesVersion, tables.unicodeVersion, tables.textModuleVersion))
	}
	if len(file.Vectors) == 0 {
		findings = append(findings, testHookNormalizeVectorPath+" holds no vector")
	}
	normalizer, err := indexNewNormalizer(tables)
	if err != nil {
		return append(findings, err.Error())
	}
	for _, vector := range file.Vectors {
		text, err := hex.DecodeString(vector.TextHex)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", vector.Name, err))
			continue
		}
		normalized, err := normalizer.normalize(text)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", vector.Name, err))
			continue
		}
		normalizedSum := sha256.Sum256(normalized)
		if hex.EncodeToString(normalized) != vector.NormalizedHex || hex.EncodeToString(normalizedSum[:]) != vector.NormalizedSha256 {
			findings = append(findings, fmt.Sprintf("%s normalizes to %x", vector.Name, normalized))
		}
		if len(text) == 0 {
			// a field with no text adds no key, so the vector's key set is of none
			continue
		}
		keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: bytes.NewReader(text)}})
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", vector.Name, err))
			continue
		}
		encodedKeys, err := keys.appendEncoded(nil)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: %v", vector.Name, err))
			continue
		}
		keySetSum := sha256.Sum256(encodedKeys)
		if hex.EncodeToString(keySetSum[:]) != vector.KeySetSha256 {
			findings = append(findings, fmt.Sprintf("%s's key set hashes to %x", vector.Name, keySetSum))
		}
	}
	return findings
}

// Each whole file of a codec vector file decoded and encoded again by roundTrip, to the bytes and hash it holds.
func testHookCodecVectorFindings(path string, roundTrip func(file []byte, sum []byte, companion bool) ([]byte, error)) []string {
	findings := []string{}
	encoded, err := testHookIndexVectorFiles.ReadFile(path)
	if err != nil {
		return []string{err.Error()}
	}
	vectors := []struct {
		Name      string `json:"name"`
		Companion bool   `json:"companion"`
		Hex       string `json:"hex"`
		Sha256    string `json:"sha256"`
	}{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}
	whole := 0
	for _, vector := range vectors {
		file, err := hex.DecodeString(vector.Hex)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s's %s: %v", path, vector.Name, err))
			continue
		}
		sum := sha256.Sum256(file)
		if hex.EncodeToString(sum[:]) != vector.Sha256 {
			findings = append(findings, fmt.Sprintf("%s's %s hashes to %x", path, vector.Name, sum))
		}
		if !bytes.HasPrefix(file, []byte(indexFileMagic)) {
			// a table cut out of a shard, which is no file of its own
			continue
		}
		whole += 1
		again, err := roundTrip(file, sum[:], vector.Companion)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s's %s: %v", path, vector.Name, err))
			continue
		}
		if !bytes.Equal(again, file) {
			findings = append(findings, fmt.Sprintf("%s's %s encodes again to other bytes", path, vector.Name))
		}
	}
	if whole == 0 {
		findings = append(findings, path+" holds no whole file")
	}
	return findings
}
