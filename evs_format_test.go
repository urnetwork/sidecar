// §22.5's §11 T1 rows for the small format functions: token, ref id, digest and chain vectors byte-equal on every
// leg, wasm's included; NFC and NFD names as two paths; main's ref id from any reader; RFC 9162's known answers and
// the adjacent-leaf property; Padmé's table. A format change regenerates the vectors, with the record, segment,
// push, batch and window ones:
//
//	go test -run '^TestEvs.*Vectors$' . -args -update-evs-vectors
//
// which is a format change, and is read as one in review. The Worker has no file system, so they are embedded.

package sidecar

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math"
	mathrand "math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/token_vectors.json
var evsTokenVectorsJson []byte

//go:embed testdata/evs/chain_vectors.json
var evsChainVectorsJson []byte

var updateEvsVectors = flag.Bool("update-evs-vectors", false, "rewrite testdata/evs's vectors")

// Writes a vector file from the host's source tree.
func writeEvsVectors(t *testing.T, path string, vectors any) {
	t.Helper()
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Compares this build's vectors with the stored ones as JSON, or rewrites them under -update-evs-vectors. True when
// the caller should go on to check the stored ones.
func compareEvsVectors(t *testing.T, path string, storedJson []byte, computed any, stored any) bool {
	t.Helper()
	if *updateEvsVectors {
		writeEvsVectors(t, path, computed)
		return false
	}
	if err := json.Unmarshal(storedJson, stored); err != nil {
		t.Fatal(err)
	}
	computedJson, _ := json.Marshal(computed)
	storedJsonAgain, _ := json.Marshal(stored)
	if !bytes.Equal(computedJson, storedJsonAgain) {
		t.Fatalf("this build's vectors differ from %s:\n%s\n%s", path, computedJson, storedJsonAgain)
	}
	return true
}

// Bytes no other vector shares.
func evsTestBytes(label string, length int) []byte {
	digest := sha256.Sum256([]byte("evs vector " + label))
	return bytes.Clone(digest[:length])
}

// An id no other vector shares.
func evsTestId(label string) Id {
	return Id(evsTestBytes(label, 16))
}

// A token no other vector shares.
func evsTestToken(label string) EvsToken {
	return EvsToken(evsTestBytes("token "+label, EvsTokenByteCount))
}

// A repo key of generation with fixed RK_g, holding RK_1 for ref, as a ladder walk leaves it.
func evsTestRepoKey(repoId Id, generation uint64) *EvsRepoKey {
	return &EvsRepoKey{
		repoId:       repoId,
		generation:   generation,
		repoKey:      evsTestBytes("RK "+string(rune('0'+generation)), evsKeyByteCount),
		firstRepoKey: evsTestBytes("RK 1", evsKeyByteCount),
	}
}

func evsTestPathKey(t testing.TB, repoId Id, epoch uint64) *EvsPathKey {
	t.Helper()
	pathKey, err := NewEvsPathKey(evsTestRepoKey(repoId, epoch))
	if err != nil {
		t.Fatal(err)
	}
	return pathKey
}

// What testdata/evs/token_vectors.json holds.
type evsTokenVectors struct {
	RepoId  hexBytes               `json:"repo_id"`
	Epochs  []*evsTokenEpochVector `json:"epochs"`
	Refs    *evsRefVectors         `json:"refs"`
	Digests []*evsDigestVector     `json:"digests"`
}

// One path epoch's key and the token paths it gives.
type evsTokenEpochVector struct {
	Epoch   uint64                `json:"epoch"`
	RepoKey hexBytes              `json:"repo_key"`
	PathKey hexBytes              `json:"path_key"`
	Paths   []*evsTokenPathVector `json:"paths"`
}

// Raw names, their tokens and those tokens' key forms.
type evsTokenPathVector struct {
	Names  []hexBytes `json:"names"`
	Tokens []hexBytes `json:"tokens"`
	Keys   []string   `json:"keys"`
}

// K_ref from RK_1, named refs' ids, and the public ids.
type evsRefVectors struct {
	FirstRepoKey hexBytes                 `json:"first_repo_key"`
	RefKey       hexBytes                 `json:"ref_key"`
	Named        []*evsNamedRefVector     `json:"named"`
	Deposits     []*evsDepositRefVector   `json:"deposits"`
	Erasure      hexBytes                 `json:"erasure_ref_id"`
	GitRefs      []*evsGitRefNameVector   `json:"git_refs"`
	Owned        []*evsOwnedRefNameVector `json:"owned"`
}

type evsNamedRefVector struct {
	Name  hexBytes `json:"name"`
	RefId hexBytes `json:"ref_id"`
}

type evsDepositRefVector struct {
	SidecarId hexBytes `json:"sidecar_id"`
	RefId     hexBytes `json:"ref_id"`
}

type evsGitRefNameVector struct {
	GitRef  string `json:"git_ref"`
	RefName string `json:"ref_name"`
}

type evsOwnedRefNameVector struct {
	SidecarId hexBytes `json:"sidecar_id"`
	Rest      string   `json:"rest"`
	Name      string   `json:"name"`
	// a conflict ref's, when Rest names a ref and TimeMs its time
	TimeMs       int64  `json:"time_ms,omitempty"`
	ConflictName string `json:"conflict_name,omitempty"`
}

// A digest over changed paths and, when not inline, covering prefixes, with what queries of it answer.
type evsDigestVector struct {
	Changed  [][]hexBytes            `json:"changed"`
	Covering [][]hexBytes            `json:"covering,omitempty"`
	Digest   string                  `json:"digest"`
	Queries  []*evsDigestQueryVector `json:"queries"`
}

type evsDigestQueryVector struct {
	TokenPath []hexBytes `json:"token_path"`
	Matches   bool       `json:"matches"`
	MayChange bool       `json:"may_change"`
}

// A token path as hex tokens.
func evsHexTokenPath(tokenPath EvsTokenPath) []hexBytes {
	tokens := make([]hexBytes, len(tokenPath))
	for i, token := range tokenPath {
		tokens[i] = token.Bytes()
	}
	return tokens
}

// Hex tokens as a token path.
func evsTokenPathOfHex(t testing.TB, tokens []hexBytes) EvsTokenPath {
	t.Helper()
	components := make([][]byte, len(tokens))
	for i, token := range tokens {
		components[i] = token
	}
	tokenPath, err := ParseEvsTokenPath(components)
	if err != nil {
		t.Fatal(err)
	}
	return tokenPath
}

// The names the token vectors cover: plain, deep, raw bytes, and é spelled NFC and NFD.
var evsTestPathNames = [][]string{
	{"README.md"},
	{"src", "main.go"},
	{"src", "evs", "token.go"},
	{"caf\u00e9.txt"},
	{"cafe\u0301.txt"},
	{"bin", "\xff\xfe raw"},
}

func computeEvsTokenVectors(t *testing.T) *evsTokenVectors {
	repoId := evsTestId("repo")
	vectors := &evsTokenVectors{RepoId: repoId.Bytes()}
	for _, epoch := range []uint64{1, 2} {
		repoKey := evsTestRepoKey(repoId, epoch)
		pathKey, err := NewEvsPathKey(repoKey)
		if err != nil {
			t.Fatal(err)
		}
		epochVector := &evsTokenEpochVector{Epoch: epoch, RepoKey: repoKey.repoKey, PathKey: pathKey.key}
		for _, names := range evsTestPathNames {
			rawNames := make([][]byte, len(names))
			for i, name := range names {
				rawNames[i] = []byte(name)
			}
			tokenPath, err := EvsPathTokens(pathKey, rawNames)
			if err != nil {
				t.Fatal(err)
			}
			pathVector := &evsTokenPathVector{}
			for i, token := range tokenPath {
				pathVector.Names = append(pathVector.Names, rawNames[i])
				pathVector.Tokens = append(pathVector.Tokens, token.Bytes())
				pathVector.Keys = append(pathVector.Keys, token.String())
			}
			epochVector.Paths = append(epochVector.Paths, pathVector)
		}
		vectors.Epochs = append(vectors.Epochs, epochVector)
	}

	repoKey := evsTestRepoKey(repoId, 2)
	refKey, err := NewEvsRefKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	refs := &evsRefVectors{FirstRepoKey: repoKey.firstRepoKey, RefKey: refKey.key}
	sidecarId := evsTestId("sidecar")
	for _, name := range []string{
		"main", "release", "refs/tags/v1.0", "ur/index", "ur/lfs", "cards",
		string(EvsOwnedRefName(sidecarId, "scratch")),
	} {
		refId, err := EvsRefId(refKey, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		refs.Named = append(refs.Named, &evsNamedRefVector{Name: []byte(name), RefId: refId.Bytes()})
	}
	for _, label := range []string{"depositor a", "depositor b"} {
		depositorId := evsTestId(label)
		refs.Deposits = append(refs.Deposits, &evsDepositRefVector{
			SidecarId: depositorId.Bytes(),
			RefId:     EvsDepositRefId(repoId, depositorId).Bytes(),
		})
	}
	refs.Erasure = EvsErasureRefId(repoId).Bytes()
	for _, gitRef := range []string{"refs/heads/main", "refs/heads/feature/x", "refs/tags/v1.0"} {
		refName, err := EvsGitRefName(gitRef)
		if err != nil {
			t.Fatal(err)
		}
		refs.GitRefs = append(refs.GitRefs, &evsGitRefNameVector{GitRef: gitRef, RefName: string(refName)})
	}
	conflictTime := time.UnixMilli(1767225600000)
	refs.Owned = append(refs.Owned,
		&evsOwnedRefNameVector{SidecarId: sidecarId.Bytes(), Rest: "scratch", Name: string(EvsOwnedRefName(sidecarId, "scratch"))},
		&evsOwnedRefNameVector{
			SidecarId:    sidecarId.Bytes(),
			Rest:         "main",
			Name:         string(EvsOwnedRefName(sidecarId, "main")),
			TimeMs:       conflictTime.UnixMilli(),
			ConflictName: string(EvsConflictRefName(sidecarId, []byte("main"), conflictTime)),
		},
	)
	vectors.Refs = refs

	pathKey := evsTestPathKey(t, repoId, 1)
	tokenPathOf := func(names ...string) EvsTokenPath {
		rawNames := make([][]byte, len(names))
		for i, name := range names {
			rawNames[i] = []byte(name)
		}
		tokenPath, err := EvsPathTokens(pathKey, rawNames)
		if err != nil {
			t.Fatal(err)
		}
		return tokenPath
	}
	queries := []EvsTokenPath{
		tokenPathOf("src", "main.go"),
		tokenPathOf("src"),
		tokenPathOf("src", "evs", "token.go"),
		tokenPathOf("docs", "guide.md"),
		tokenPathOf("README.md"),
	}
	digestCases := []struct {
		changed  []EvsTokenPath
		covering []EvsTokenPath
	}{
		{changed: []EvsTokenPath{tokenPathOf("src", "main.go")}},
		{changed: []EvsTokenPath{tokenPathOf("src", "evs", "token.go"), tokenPathOf("README.md")}},
		{
			changed:  []EvsTokenPath{tokenPathOf("src", "evs", "token.go"), tokenPathOf("src", "evs", "chain.go")},
			covering: []EvsTokenPath{tokenPathOf("src", "evs")},
		},
	}
	for _, digestCase := range digestCases {
		digest := NewEvsPathsDigest(digestCase.changed, digestCase.covering)
		digestVector := &evsDigestVector{Digest: hex.EncodeToString(binary.BigEndian.AppendUint64(nil, uint64(digest)))}
		for _, tokenPath := range digestCase.changed {
			digestVector.Changed = append(digestVector.Changed, evsHexTokenPath(tokenPath))
		}
		for _, tokenPath := range digestCase.covering {
			digestVector.Covering = append(digestVector.Covering, evsHexTokenPath(tokenPath))
		}
		for _, query := range queries {
			digestVector.Queries = append(digestVector.Queries, &evsDigestQueryVector{
				TokenPath: evsHexTokenPath(query),
				Matches:   digest.Matches(query),
				MayChange: digest.MayChange(query),
			})
		}
		vectors.Digests = append(vectors.Digests, digestVector)
	}
	return vectors
}

// The stored tokens equal what this build derives, and what a second derivation written apart from evs_key.go and
// evs_token.go derives: HKDF and HMAC as §11.6 spells them.
func TestEvsTokenVectors(t *testing.T) {
	stored := &evsTokenVectors{}
	if !compareEvsVectors(t, "testdata/evs/token_vectors.json", evsTokenVectorsJson, computeEvsTokenVectors(t), stored) {
		return
	}
	for _, epochVector := range stored.Epochs {
		info := binary.BigEndian.AppendUint64([]byte("UR evs 1.0 path"), epochVector.Epoch)
		pathKey, err := hkdf.Key(sha256.New, epochVector.RepoKey, stored.RepoId, string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pathKey, epochVector.PathKey) {
			t.Errorf("epoch %d: K_path is not HKDF-SHA256(RK_p, salt repo_id, info \"UR evs 1.0 path\" || u64be(p))", epochVector.Epoch)
		}
		for _, pathVector := range epochVector.Paths {
			parent := make([]byte, 16)
			for i, name := range pathVector.Names {
				mac := hmac.New(sha256.New, pathKey)
				mac.Write(parent)
				mac.Write(name)
				token := mac.Sum(nil)[:16]
				if !bytes.Equal(token, pathVector.Tokens[i]) {
					t.Errorf("epoch %d: token %d of %x", epochVector.Epoch, i, pathVector.Names)
				}
				if len(pathVector.Keys[i]) != 26 || strings.ToLower(pathVector.Keys[i]) != pathVector.Keys[i] {
					t.Errorf("key form %q", pathVector.Keys[i])
				}
				parent = token
			}
		}
	}
	refs := stored.Refs
	info := binary.BigEndian.AppendUint64([]byte("UR evs 1.0 ref"), 1)
	refKey, err := hkdf.Key(sha256.New, refs.FirstRepoKey, stored.RepoId, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(refKey, refs.RefKey) {
		t.Error("K_ref is not HKDF-SHA256(RK_1, salt repo_id, info \"UR evs 1.0 ref\" || u64be(1))")
	}
	for _, named := range refs.Named {
		mac := hmac.New(sha256.New, refKey)
		mac.Write([]byte("ref"))
		mac.Write(named.Name)
		if !bytes.Equal(mac.Sum(nil)[:16], named.RefId) {
			t.Errorf("the ref id of %q", named.Name)
		}
	}
	for _, deposit := range refs.Deposits {
		digest := sha256.Sum256(append(bytes.Clone(stored.RepoId), deposit.SidecarId...))
		if !bytes.Equal(digest[:16], deposit.RefId) {
			t.Error("a deposit ref id is not SHA-256(repo_id || sidecar_id)[:16]")
		}
	}
	erasure := sha256.Sum256(append([]byte("UR evs 1.0 erasure"), stored.RepoId...))
	if !bytes.Equal(erasure[:16], refs.Erasure) {
		t.Error("the erasure ref id is not SHA-256(\"UR evs 1.0 erasure\" || repo_id)[:16]")
	}
}

// Each stored digest's bits are the indexes §11.8 and plan-EVS1-format-bytes#7 give, read apart from evs_digest.go.
func TestEvsDigestVectors(t *testing.T) {
	stored := &evsTokenVectors{}
	if err := json.Unmarshal(evsTokenVectorsJson, stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Digests) == 0 {
		t.Fatal("no digest vectors")
	}
	bitsOf := func(tokens []hexBytes) uint64 {
		input := []byte("UR evs digest")
		for _, token := range tokens {
			input = append(input, token...)
		}
		sum := sha256.Sum256(input)
		return uint64(1)<<(binary.BigEndian.Uint32(sum[0:4])%64) | uint64(1)<<(binary.BigEndian.Uint32(sum[4:8])%64)
	}
	for _, vector := range stored.Digests {
		want := uint64(0)
		for _, tokens := range append(slices.Clone(vector.Changed), vector.Covering...) {
			want |= bitsOf(tokens)
		}
		if hex.EncodeToString(binary.BigEndian.AppendUint64(nil, want)) != vector.Digest {
			t.Errorf("digest %s, want %016x", vector.Digest, want)
		}
		for _, query := range vector.Queries {
			queryBits := bitsOf(query.TokenPath)
			if (want&queryBits == queryBits) != query.Matches {
				t.Errorf("a query's match")
			}
		}
	}
}

// What testdata/evs/chain_vectors.json holds.
type evsChainVectors struct {
	RepoId   hexBytes                 `json:"repo_id"`
	RefId    hexBytes                 `json:"ref_id"`
	Start    hexBytes                 `json:"c0"`
	Versions []*evsChainVersionVector `json:"versions"`
}

type evsChainVersionVector struct {
	PushId          hexBytes `json:"push_id"`
	Statement       hexBytes `json:"statement"`
	StatementSha256 hexBytes `json:"statement_sha256"`
	Chain           hexBytes `json:"chain"`
}

func computeEvsChainVectors() *evsChainVectors {
	repoId := evsTestId("repo")
	refId := evsTestId("ref main")
	start := EvsChainStart(repoId, refId)
	vectors := &evsChainVectors{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Start: start[:]}
	chain := start
	for version := range 4 {
		label := string(rune('1' + version))
		pushId := evsTestId("push " + label)
		statement := (&protocol.EvsPush{
			RepoId: repoId.Bytes(), RefId: refId.Bytes(), PushId: pushId.Bytes(), BaseVersion: uint64(version),
			BaseChain: bytes.Clone(chain[:]), TimeMs: 1767225600000 + int64(version),
		})
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(statement)
		// the statement's bytes as received: a Signed body with a placeholder signature, since the chain reads only bytes
		signedBytes := append(bytes.Clone(body), evsTestBytes("signature "+label, 32)...)
		statementSha256 := EvsStatementSha256(signedBytes)
		chain = EvsChainNext(chain, pushId, statementSha256)
		vectors.Versions = append(vectors.Versions, &evsChainVersionVector{
			PushId:          pushId.Bytes(),
			Statement:       signedBytes,
			StatementSha256: statementSha256[:],
			Chain:           bytes.Clone(chain[:]),
		})
	}
	return vectors
}

// C_0 and each C_v equal this build's and §11.8's formulas, computed apart.
func TestEvsChainVectors(t *testing.T) {
	stored := &evsChainVectors{}
	if !compareEvsVectors(t, "testdata/evs/chain_vectors.json", evsChainVectorsJson, computeEvsChainVectors(), stored) {
		return
	}
	start := sha256.Sum256(slices.Concat([]byte("UR evs 1.0 ref"), stored.RepoId, stored.RefId))
	if !bytes.Equal(start[:], stored.Start) {
		t.Error("C_0 is not SHA-256(\"UR evs 1.0 ref\" || repo_id || ref_id)")
	}
	chain := start[:]
	for v, version := range stored.Versions {
		statementSha256 := sha256.Sum256(version.Statement)
		if !bytes.Equal(statementSha256[:], version.StatementSha256) {
			t.Errorf("version %d's statement hash", v+1)
		}
		next := sha256.Sum256(slices.Concat(chain, version.PushId, statementSha256[:]))
		if !bytes.Equal(next[:], version.Chain) {
			t.Errorf("C_%d is not SHA-256(C_%d || push_id || SHA-256(statement))", v+1, v)
		}
		chain = next[:]
	}
}

// §22.5: NFC and NFD spellings of one name are two paths, with two tokens, and nothing is normalized on the way.
func TestEvsNfcAndNfdNamesAreTwoPaths(t *testing.T) {
	pathKey := evsTestPathKey(t, evsTestId("repo"), 1)
	nfc, err := EvsPathToken(pathKey, EvsRootToken, []byte("caf\u00e9"))
	if err != nil {
		t.Fatal(err)
	}
	nfd, err := EvsPathToken(pathKey, EvsRootToken, []byte("cafe\u0301"))
	if err != nil {
		t.Fatal(err)
	}
	if nfc == nfd {
		t.Error("NFC and NFD names share a token")
	}
	again, err := EvsPathToken(pathKey, EvsRootToken, []byte("caf\u00e9"))
	if err != nil || again != nfc {
		t.Error("a name's token is not stable")
	}
}

// One path has one token on every ref of a repo in an epoch (overlays need this), and another in the next epoch or
// another repo.
func TestEvsTokensAreThePathsAloneInAnEpoch(t *testing.T) {
	repoId := evsTestId("repo")
	names := [][]byte{[]byte("src"), []byte("main.go")}
	first, err := EvsPathTokens(evsTestPathKey(t, repoId, 1), names)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EvsPathTokens(evsTestPathKey(t, repoId, 1), names)
	if err != nil || !first.Equal(again) {
		t.Error("one path's token path differs in one epoch")
	}
	nextEpoch, err := EvsPathTokens(evsTestPathKey(t, repoId, 2), names)
	if err != nil || first.Equal(nextEpoch) || first[0] == nextEpoch[0] {
		t.Error("a new path epoch keeps a token")
	}
	otherRepo, err := EvsPathTokens(evsTestPathKey(t, evsTestId("other repo"), 1), names)
	if err != nil || first[0] == otherRepo[0] {
		t.Error("another repo shares a token")
	}
	// a child's token depends on its parent's, so equal names under different directories differ
	underOther, err := EvsPathTokens(evsTestPathKey(t, repoId, 1), [][]byte{[]byte("lib"), []byte("main.go")})
	if err != nil || underOther[1] == first[1] {
		t.Error("a name has one token under two directories")
	}
}

// §22.5: any reader derives main's ref id, at any generation its ladder reached, and one that has not reached RK_1
// refuses rather than derive from another key.
func TestEvsAnyReaderDerivesMainsRefId(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	var mainId Id
	for i, key := range keys {
		refKey, err := NewEvsRefKey(key)
		if err != nil {
			t.Fatalf("generation %d: %v", i+1, err)
		}
		refId, err := EvsRefId(refKey, []byte("main"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			mainId = refId
		} else if refId != mainId {
			t.Errorf("generation %d derives another id for main", i+1)
		}
	}
	// a reader that opened only the newest generation holds no RK_1 until it walks the ladder
	top, err := OpenEvsRepoKey(generations[2], keys[2].repoKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEvsRefKey(top); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a key with no RK_1: %v", err)
	}
	walked, err := OpenGkmLadder(top, generations[:2])
	if err != nil {
		t.Fatal(err)
	}
	refKey, err := NewEvsRefKey(walked[2])
	if err != nil {
		t.Fatal(err)
	}
	if refId, err := EvsRefId(refKey, []byte("main")); err != nil || refId != mainId {
		t.Errorf("a reader after its walk derives %v, %v", refId, err)
	}
}

// Keys that hold nothing refuse every use.
func TestEvsKeysHoldingNothingRefuse(t *testing.T) {
	if _, err := EvsPathToken(nil, EvsRootToken, []byte("a")); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("a nil path key: %v", err)
	}
	if _, err := EvsPathToken(&EvsPathKey{}, EvsRootToken, []byte("a")); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("a declared path key: %v", err)
	}
	if _, err := EvsRefId(&EvsRefKey{}, []byte("main")); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("a declared ref key: %v", err)
	}
	if _, err := NewEvsPathKey(&EvsRepoKey{repoId: evsTestId("repo"), generation: 1}); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a repo key holding no RK_g: %v", err)
	}
}

// A component git cannot hold is refused, and so is a path of no component or more than 32.
func TestEvsPathTokensRefuseWhatNoPathHolds(t *testing.T) {
	pathKey := evsTestPathKey(t, evsTestId("repo"), 1)
	for _, name := range [][]byte{{}, []byte("a/b"), []byte("a\x00b")} {
		if _, err := EvsPathToken(pathKey, EvsRootToken, name); !errors.Is(err, ErrEvsTokenInvalid) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	deep := make([][]byte, EvsTokenPathMaxLength)
	for i := range deep {
		deep[i] = []byte("d")
	}
	tokenPath, err := EvsPathTokens(pathKey, deep)
	if err != nil || len(tokenPath) != EvsTokenPathMaxLength {
		t.Fatalf("32 components: %v", err)
	}
	if _, err := EvsPathTokens(pathKey, append(deep, []byte("d"))); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Errorf("33 components: %v", err)
	}
	// no component is the root, whose token path is empty in every epoch (question evs1-m2-24-root-directory-names)
	if root, err := EvsPathTokens(pathKey, nil); err != nil || len(root) != 0 {
		t.Errorf("no component: %v %v", root, err)
	}
	if _, err := ParseEvsTokenPath(tokenPath.Components()); err != nil {
		t.Errorf("32 components back: %v", err)
	}
	if _, err := ParseEvsTokenPath(append(tokenPath.Components(), tokenPath[0].Bytes())); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Errorf("33 components back: %v", err)
	}
	if _, err := ParseEvsTokenPath([][]byte{make([]byte, 15)}); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Errorf("a short token: %v", err)
	}
	if root, err := ParseEvsChangedTokenPath(nil); err != nil || len(root) != 0 {
		t.Errorf("a change naming the root: %v %v", root, err)
	}
}

// A token's key form is 26 lowercase base32 characters with one spelling per token.
func TestEvsTokenKeyForm(t *testing.T) {
	for _, token := range []EvsToken{{}, evsTestToken("a"), {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		text := token.String()
		if len(text) != 26 || strings.ToLower(text) != text || strings.Contains(text, "=") {
			t.Errorf("key form %q", text)
		}
		parsed, err := ParseEvsToken(text)
		if err != nil || parsed != token {
			t.Errorf("%q back: %v", text, err)
		}
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	text := evsTestToken("a").String()
	// the last character carries 3 bits, so its low 2 are zero, and setting one spells the same bytes again
	last := strings.IndexByte(alphabet, text[25])
	if last < 0 || last&3 != 0 {
		t.Fatalf("last character %q", text[25])
	}
	alternate := text[:25] + string(alphabet[last+1])
	for _, refused := range []string{
		strings.ToUpper(text), text[:25], text + "a", text[:25] + "=", text[:25] + "1", alternate,
	} {
		if _, err := ParseEvsToken(refused); !errors.Is(err, ErrEvsTokenInvalid) {
			t.Errorf("%q: %v", refused, err)
		}
	}
	tokenPath := EvsTokenPath{evsTestToken("a"), evsTestToken("b")}
	if tokenPath.KeyString() != tokenPath[0].String()+"/"+tokenPath[1].String() {
		t.Errorf("key string %q", tokenPath.KeyString())
	}
}

// §11.6's order is the order of the token paths' bytes, a directory before its children.
func TestEvsTokenPathOrderIsItsBytes(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	pool := []EvsToken{evsTestToken("a"), evsTestToken("b"), evsTestToken("c")}
	randomPath := func() EvsTokenPath {
		tokenPath := make(EvsTokenPath, 1+random.IntN(4))
		for i := range tokenPath {
			tokenPath[i] = pool[random.IntN(len(pool))]
		}
		return tokenPath
	}
	for range 2000 {
		a, b := randomPath(), randomPath()
		order := a.Compare(b)
		want := bytes.Compare(a.Bytes(), b.Bytes())
		if (order < 0) != (want < 0) || (order == 0) != (want == 0) {
			t.Fatalf("%x and %x: %d, bytes say %d", a.Bytes(), b.Bytes(), order, want)
		}
		if a.HasPrefix(b) != bytes.HasPrefix(a.Bytes(), b.Bytes()) {
			t.Fatalf("%x holding %x", a.Bytes(), b.Bytes())
		}
	}
	if !(EvsTokenPath{pool[0]}).HasPrefix(nil) {
		t.Error("the empty path holds no path")
	}
}

// plan-EVS1-ref-name-bytes#1: branches take their short names and tags their whole, so a branch named refs/... is
// refused rather than collide with a tag, and nothing but branches and tags maps.
func TestEvsGitRefNames(t *testing.T) {
	for gitRef, want := range map[string]string{
		"refs/heads/main":      "main",
		"refs/heads/feature/x": "feature/x",
		"refs/tags/v1.0":       "refs/tags/v1.0",
	} {
		refName, err := EvsGitRefName(gitRef)
		if err != nil || string(refName) != want {
			t.Errorf("%s: %q, %v", gitRef, refName, err)
		}
		if EvsGitRefOfName(refName) != gitRef {
			t.Errorf("%q back to %s", refName, EvsGitRefOfName(refName))
		}
	}
	for _, gitRef := range []string{
		"refs/heads/", "refs/heads/refs/tags/v1.0", "refs/heads/refs/heads/main", "refs/tags/", "refs/notes/ur",
		"refs/remotes/origin/main", "HEAD", "main",
	} {
		if _, err := EvsGitRefName(gitRef); !errors.Is(err, ErrEvsRefNameInvalid) {
			t.Errorf("%s: %v", gitRef, err)
		}
	}
}

// plan-EVS1-ref-name-bytes#2 and #3: an owned ref's name carries Id.String(), its owner reads back, and a conflict
// ref's time is UTC yyyymmddThhmmssZ.
func TestEvsOwnedRefNames(t *testing.T) {
	sidecarId := evsTestId("sidecar")
	name := EvsOwnedRefName(sidecarId, "scratch")
	if string(name) != "ur/"+sidecarId.String()+"/scratch" {
		t.Errorf("owned name %q", name)
	}
	owner, ok := EvsOwnedRefOwner(name)
	if !ok || owner != sidecarId {
		t.Errorf("owner of %q: %v %v", name, owner, ok)
	}
	at := time.Date(2026, 11, 8, 13, 4, 5, 999, time.FixedZone("x", 3600))
	conflict := EvsConflictRefName(sidecarId, []byte("main"), at)
	if string(conflict) != "ur/"+sidecarId.String()+"/conflicts/main/20261108T120405Z" {
		t.Errorf("conflict name %q", conflict)
	}
	if owner, ok := EvsOwnedRefOwner(conflict); !ok || owner != sidecarId {
		t.Error("a conflict ref's owner")
	}
	hexId := hex.EncodeToString(sidecarId.Bytes())
	for _, notOwned := range []string{
		"main", "ur/index", "ur/lfs", "ur/" + sidecarId.String(), "ur/" + hexId + "/x",
		"ur/" + strings.ToUpper(sidecarId.String()) + "/x", "cards",
	} {
		if _, ok := EvsOwnedRefOwner([]byte(notOwned)); ok {
			t.Errorf("%q read as owned", notOwned)
		}
	}
}

// Certificate Transparency's published trees over its eight test leaves (RFC 6962's test data, which RFC 9162 keeps):
// the root at each size and the paths of the four leaves its suites prove, the empty tree included.
func TestEvsMerkleKnownAnswers(t *testing.T) {
	leaves := [][]byte{}
	for _, leaf := range []string{
		"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f",
	} {
		decoded, _ := hex.DecodeString(leaf)
		leaves = append(leaves, decoded)
	}
	roots := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for size, root := range roots {
		tree := NewEvsMerkleTree(leaves[:size])
		got := tree.Root()
		if hex.EncodeToString(got[:]) != root {
			t.Errorf("size %d: root %x", size, got)
		}
	}
	paths := []struct {
		index int
		size  int
		path  []string
	}{
		{index: 0, size: 1, path: []string{}},
		{index: 0, size: 8, path: []string{
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{index: 5, size: 8, path: []string{
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		}},
		{index: 2, size: 3, path: []string{"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"}},
		{index: 1, size: 5, path: []string{
			"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		}},
	}
	for _, vector := range paths {
		tree := NewEvsMerkleTree(leaves[:vector.size])
		path, err := tree.InclusionPath(vector.index)
		if err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, hash := range path {
			got = append(got, hex.EncodeToString(hash))
		}
		if !slices.Equal(got, vector.path) {
			t.Errorf("leaf %d of %d: path %q", vector.index, vector.size, got)
		}
		root, _ := hex.DecodeString(roots[vector.size])
		if err := EvsVerifyMerkleProof(root, &protocol.EvsMerkleProof{
			Leaf: leaves[vector.index], Index: uint64(vector.index), Size: uint64(vector.size), Path: path,
		}); err != nil {
			t.Errorf("leaf %d of %d does not verify: %v", vector.index, vector.size, err)
		}
	}
}

// Every leaf of every tree up to 70 leaves verifies by §2.1.3.2's walk, and the walk refuses a wrong index, size,
// leaf, or a path one hash long or short.
func TestEvsMerkleEveryLeafVerifies(t *testing.T) {
	leaves := [][]byte{}
	for i := range 70 {
		leaves = append(leaves, []byte{byte(i), byte(i >> 8)})
	}
	for size := 1; size <= len(leaves); size++ {
		tree := NewEvsMerkleTree(leaves[:size])
		root := tree.Root()
		for index := range size {
			path, err := tree.InclusionPath(index)
			if err != nil {
				t.Fatal(err)
			}
			proof := &protocol.EvsMerkleProof{Leaf: leaves[index], Index: uint64(index), Size: uint64(size), Path: path}
			if err := EvsVerifyMerkleProof(root[:], proof); err != nil {
				t.Fatalf("leaf %d of %d: %v", index, size, err)
			}
			for _, wrong := range []*protocol.EvsMerkleProof{
				{Leaf: leaves[index], Index: uint64(index + 1), Size: uint64(size), Path: path},
				{Leaf: []byte("other"), Index: uint64(index), Size: uint64(size), Path: path},
				{Leaf: leaves[index], Index: uint64(index), Size: uint64(size), Path: append(slices.Clone(path), root[:])},
			} {
				if EvsVerifyMerkleProof(root[:], wrong) == nil {
					t.Fatalf("leaf %d of %d: a wrong proof verified", index, size)
				}
			}
			if 0 < len(path) && EvsVerifyMerkleProof(root[:], &protocol.EvsMerkleProof{
				Leaf: leaves[index], Index: uint64(index), Size: uint64(size), Path: path[:len(path)-1],
			}) == nil {
				t.Fatalf("leaf %d of %d: a short path verified", index, size)
			}
		}
		if _, err := tree.InclusionPath(size); err == nil {
			t.Fatal("a leaf past the end has a path")
		}
	}
}

// A change leaf naming tokenPath, encoded as a writer lists it.
func evsTestChangeLeaf(t testing.TB, tokenPath EvsTokenPath, baseEntryVersion uint64) []byte {
	t.Helper()
	leaf, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsChange{
		TokenPath:        tokenPath.Components(),
		BaseEntryVersion: baseEntryVersion,
		EntrySha256:      evsTestBytes("entry", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Sorted, distinct token paths over a small alphabet, so absent paths fall between, before and after them, and
// some are prefixes of others.
func evsTestSortedPaths(random *mathrand.Rand, count int) []EvsTokenPath {
	pool := []EvsToken{evsTestToken("a"), evsTestToken("b"), evsTestToken("c"), evsTestToken("d")}
	seen := map[string]bool{}
	paths := []EvsTokenPath{}
	for len(paths) < count {
		tokenPath := make(EvsTokenPath, 1+random.IntN(3))
		for i := range tokenPath {
			tokenPath[i] = pool[random.IntN(len(pool))]
		}
		if !seen[string(tokenPath.Bytes())] {
			seen[string(tokenPath.Bytes())] = true
			paths = append(paths, tokenPath)
		}
	}
	slices.SortFunc(paths, EvsTokenPath.Compare)
	return paths
}

// Every path a list of up to 80 sorted changes leaves alone has an absence proof that verifies, as one list and in
// 2 to 6 parts; every path it changes has none; and a proof moved to another path, or one with a leaf left out
// between, is refused.
func TestEvsAdjacentLeavesProveAbsence(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(3, 4))
	everyPath := evsTestSortedPaths(random, 84)
	for round := range 60 {
		changeCount := 1 + random.IntN(min(80, len(everyPath)-4))
		chosen := map[int]bool{}
		for len(chosen) < changeCount {
			chosen[random.IntN(len(everyPath))] = true
		}
		changed := []EvsTokenPath{}
		leaves := [][]byte{}
		for i, tokenPath := range everyPath {
			if chosen[i] {
				changed = append(changed, tokenPath)
				leaves = append(leaves, evsTestChangeLeaf(t, tokenPath, uint64(i)))
			}
		}
		trees := []*EvsChangeTree{}
		single, err := NewEvsChangeTree(leaves)
		if err != nil {
			t.Fatal(err)
		}
		trees = append(trees, single)
		if 2 <= len(leaves) {
			partCount := 2 + random.IntN(min(5, len(leaves)-1))
			cuts := []int{0}
			for len(cuts) < partCount {
				cut := 1 + random.IntN(len(leaves)-1)
				if !slices.Contains(cuts, cut) {
					cuts = append(cuts, cut)
				}
			}
			slices.Sort(cuts)
			cuts = append(cuts, len(leaves))
			parts := [][][]byte{}
			for i := range partCount {
				parts = append(parts, leaves[cuts[i]:cuts[i+1]])
			}
			parted, err := NewEvsPartedChangeTree(parts)
			if err != nil {
				t.Fatal(err)
			}
			trees = append(trees, parted)
		}
		for _, tree := range trees {
			root := tree.Root()
			for i, tokenPath := range everyPath {
				absence, err := tree.AbsenceProof(tokenPath)
				if chosen[i] {
					if err == nil {
						t.Fatalf("round %d: a changed path has an absence proof", round)
					}
					continue
				}
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
				if err := EvsVerifyChangeAbsence(root[:], tree.PartCount(), uint64(len(leaves)), tokenPath, absence); err != nil {
					t.Fatalf("round %d, %d parts: %v", round, tree.PartCount(), err)
				}
				// the same proof cannot speak for a changed path
				for j, other := range everyPath {
					if chosen[j] {
						moved := proto.Clone(absence).(*protocol.EvsAbsenceProof)
						moved.TokenPath = other.Components()
						if EvsVerifyChangeAbsence(root[:], tree.PartCount(), uint64(len(leaves)), other, moved) == nil {
							t.Fatalf("round %d: a proof moved to a changed path verified", round)
						}
						break
					}
				}
			}
			// a proof with a changed leaf between its two leaves: leaves two apart
			if 3 <= len(leaves) {
				below, err := tree.InclusionProof(0, 0)
				if err != nil {
					t.Fatal(err)
				}
				abovePart, aboveIndex := 0, 2
				if tree.PartCount() != 0 {
					abovePart, aboveIndex = evsTestPartPosition(tree, 2)
				}
				above, err := tree.InclusionProof(abovePart, aboveIndex)
				if err != nil {
					t.Fatal(err)
				}
				between := changed[1]
				if EvsVerifyChangeAbsence(root[:], tree.PartCount(), uint64(len(leaves)), between,
					&protocol.EvsAbsenceProof{TokenPath: between.Components(), Below: below, Above: above}) == nil {
					t.Fatalf("round %d: leaves two apart proved a change absent", round)
				}
			}
		}
	}
}

// The part and index of the change at a position of a parted tree.
func evsTestPartPosition(tree *EvsChangeTree, position int) (int, int) {
	for part, run := range tree.runs {
		if position < len(run.leaves) {
			return part, position
		}
		position -= len(run.leaves)
	}
	return len(tree.runs), 0
}

// An absence proof's sizes are the ones the statement signs: a one-part list claimed shorter than change_count is
// refused, so a last leaf cannot be claimed early.
func TestEvsAbsenceProofHoldsItsSizesToTheStatement(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(5, 6))
	paths := evsTestSortedPaths(random, 6)
	leaves := [][]byte{}
	for _, tokenPath := range paths[:5] {
		leaves = append(leaves, evsTestChangeLeaf(t, tokenPath, 0))
	}
	tree, err := NewEvsChangeTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root()
	absence, err := tree.AbsenceProof(paths[5])
	if err != nil {
		t.Fatal(err)
	}
	if err := EvsVerifyChangeAbsence(root[:], 0, 5, paths[5], absence); err != nil {
		t.Fatal(err)
	}
	if EvsVerifyChangeAbsence(root[:], 0, 6, paths[5], absence) == nil {
		t.Error("a proof sized for 5 changes verified against 6 signed")
	}
	if EvsVerifyChangeAbsence(root[:], 2, 5, paths[5], absence) == nil {
		t.Error("a one-part proof verified as a push in parts")
	}
	if _, err := NewEvsChangeTree([][]byte{leaves[1], leaves[0]}); !errors.Is(err, ErrEvsMerkleInvalid) {
		t.Errorf("an unsorted list: %v", err)
	}
	if _, err := NewEvsChangeTree([][]byte{leaves[0], leaves[0]}); !errors.Is(err, ErrEvsMerkleInvalid) {
		t.Errorf("a repeated path: %v", err)
	}
	if _, err := NewEvsPartedChangeTree([][][]byte{leaves[2:], leaves[:2]}); !errors.Is(err, ErrEvsMerkleInvalid) {
		t.Errorf("parts out of order: %v", err)
	}
	// one part holding changes beside changeless ones is a tree of one part, two levels deep, so its root is not the
	// one-part push's (DESIGN-DETAILS 8.2.2's parts row)
	onePart, err := NewEvsPartedChangeTree([][][]byte{leaves})
	if err != nil || onePart.PartCount() != 1 || onePart.Root() == root {
		t.Errorf("one part as parts: %v", err)
	}
	// a push in parts with no change is a tree of no part, its root SHA-256 of no bytes, beside which no absence
	// stands (QD-658)
	empty, err := NewEvsPartedChangeTree([][][]byte{})
	if err != nil || empty.Root() != sha256.Sum256(nil) || empty.ChangeCount() != 0 || empty.PartCount() != 0 {
		t.Errorf("no part: %v", err)
	}
	if empty != nil {
		if _, err := empty.AbsenceProof(paths[5]); !errors.Is(err, ErrEvsMerkleInvalid) {
			t.Errorf("an absence in a tree of no change: %v", err)
		}
	}
	if _, err := NewEvsPartedChangeTree([][][]byte{leaves, {}}); !errors.Is(err, ErrEvsMerkleInvalid) {
		t.Errorf("an empty part: %v", err)
	}
}

// Inclusion proofs of every change, as one list and in parts, give back the change and refuse another root.
func TestEvsChangeInclusionProofs(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(7, 8))
	paths := evsTestSortedPaths(random, 9)
	leaves := [][]byte{}
	for _, tokenPath := range paths {
		leaves = append(leaves, evsTestChangeLeaf(t, tokenPath, 0))
	}
	parted, err := NewEvsPartedChangeTree([][][]byte{leaves[:4], leaves[4:5], leaves[5:]})
	if err != nil {
		t.Fatal(err)
	}
	single, err := NewEvsChangeTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, tree := range []*EvsChangeTree{single, parted} {
		root := tree.Root()
		for position, tokenPath := range paths {
			part, index := position, 0
			if tree.PartCount() == 0 {
				part, index = 0, position
			} else {
				part, index = evsTestPartPosition(tree, position)
			}
			proofs, err := tree.InclusionProof(part, index)
			if err != nil {
				t.Fatal(err)
			}
			_, proven, err := EvsVerifyChangeInclusion(root[:], tree.PartCount(), uint64(len(paths)), proofs)
			if err != nil || !proven.Equal(tokenPath) {
				t.Fatalf("%d parts, change %d: %v", tree.PartCount(), position, err)
			}
			if _, _, err := EvsVerifyChangeInclusion(evsTestBytes("another root", 32), tree.PartCount(), uint64(len(paths)), proofs); err == nil {
				t.Fatal("a proof verified to another root")
			}
		}
	}
	partRoot, err := parted.PartRoot(1)
	if err != nil {
		t.Fatal(err)
	}
	wantPartRoot := NewEvsMerkleTree(leaves[4:5]).Root()
	if partRoot != wantPartRoot {
		t.Error("a part's root is not over its own changes")
	}
	partRoots := [][]byte{}
	for part := range 3 {
		root, _ := parted.PartRoot(part)
		partRoots = append(partRoots, root[:])
	}
	if parted.Root() != NewEvsMerkleTree(partRoots).Root() {
		t.Error("a parted push's root is not over its parts' roots")
	}
}

// A reader asks for absence proofs of the path and of each prefix a covering prefix covers, and of nothing a
// covering prefix leaves out.
func TestEvsAbsencePathsFollowTheCoveringPrefixes(t *testing.T) {
	a, b, c := evsTestToken("a"), evsTestToken("b"), evsTestToken("c")
	tokenPath := EvsTokenPath{a, b, c}
	got := EvsAbsencePaths([]EvsTokenPath{{a, b}}, tokenPath)
	if len(got) != 2 || !got[0].Equal(tokenPath) || !got[1].Equal(EvsTokenPath{a, b}) {
		t.Errorf("under a/b: %d paths", len(got))
	}
	if got := EvsAbsencePaths([]EvsTokenPath{{c}}, tokenPath); len(got) != 0 {
		t.Errorf("under c: %d paths", len(got))
	}
	if got := EvsAbsencePaths([]EvsTokenPath{{}}, tokenPath); len(got) != 3 {
		t.Errorf("under the root: %d paths", len(got))
	}
}

// Padmé of lengths worked by hand from the paper's algorithm, every shape of exponent among them, the segment and
// inline bounds included.
func TestEvsPadmeTable(t *testing.T) {
	for length, want := range map[uint64]uint64{
		0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 7: 7, 8: 8, 9: 10, 10: 10, 11: 12, 15: 16, 16: 16, 17: 18, 31: 32,
		32: 32, 33: 36, 37: 40, 63: 64, 64: 64, 65: 72, 127: 128, 129: 144, 255: 256, 257: 272, 1000: 1024,
		1025: 1088, 16 * 1024: 16 * 1024, 16*1024 + 1: 17 * 1024, 1024 * 1024: 1024 * 1024,
		1024*1024 + 1: 1024*1024 + 32*1024, 8*1024*1024 - 1: 8 * 1024 * 1024, 8 * 1024 * 1024: 8 * 1024 * 1024,
		uint64(1) << 63: uint64(1) << 63,
	} {
		if got := EvsPadme(length); got != want {
			t.Errorf("Padmé(%d) = %d, want %d", length, got, want)
		}
	}
	if EvsPadme(uint64(1)<<63+1) != 0 {
		t.Error("a length past 2^63")
	}
}

// Against the paper's algorithm in floating point, for every length to 70,000 and random ones to 2^40: never
// shorter, a fixed point, within 12% past 8 bytes.
func TestEvsPadmeMatchesThePaper(t *testing.T) {
	paper := func(length uint64) uint64 {
		exponent := math.Floor(math.Log2(float64(length)))
		mantissaBits := math.Floor(math.Log2(exponent)) + 1
		mask := uint64(1)<<uint64(exponent-mantissaBits) - 1
		return (length + mask) &^ mask
	}
	random := mathrand.New(mathrand.NewPCG(9, 10))
	lengths := []uint64{}
	for length := uint64(4); length < 70000; length++ {
		lengths = append(lengths, length)
	}
	for range 20000 {
		lengths = append(lengths, 4+random.Uint64N(uint64(1)<<40))
	}
	for _, length := range lengths {
		padded := EvsPadme(length)
		if padded != paper(length) {
			t.Fatalf("Padmé(%d) = %d, the paper's %d", length, padded, paper(length))
		}
		if padded < length || EvsPadme(padded) != padded || !EvsIsPadme(padded) {
			t.Fatalf("Padmé(%d) = %d", length, padded)
		}
		if 8 < length && float64(padded) > float64(length)*1.12 {
			t.Fatalf("Padmé(%d) = %d pads more than 12%%", length, padded)
		}
	}
	if EvsIsPadme(0) || EvsIsPadme(9) {
		t.Error("a length Padmé does not give")
	}
}

// §11.8's digest row: a miss on a path and on every prefix holding it proves no change; a changed path, and every
// path under a changed directory, always match.
func TestEvsDigestMissProvesNoChange(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(11, 12))
	everyPath := evsTestSortedPaths(random, 80)
	for range 300 {
		changed := []EvsTokenPath{}
		for _, tokenPath := range everyPath {
			if random.IntN(20) == 0 {
				changed = append(changed, tokenPath)
			}
		}
		var covering []EvsTokenPath
		if random.IntN(2) == 0 {
			covering = []EvsTokenPath{{everyPath[0][0]}}
		}
		digest := NewEvsPathsDigest(changed, covering)
		for _, tokenPath := range everyPath {
			touched := false
			for _, change := range changed {
				if tokenPath.HasPrefix(change) {
					touched = true
				}
			}
			if touched && !digest.MayChange(tokenPath) {
				t.Fatal("a changed path or one under a changed directory missed the digest")
			}
		}
		for _, change := range changed {
			if !digest.Matches(change) {
				t.Fatal("a changed path does not match")
			}
		}
	}
	if EvsPathsDigest(0).MayChange(EvsTokenPath{evsTestToken("a")}) {
		t.Error("an empty digest matched")
	}
}

// The root's empty token path in the digest and the absence rule (DESIGN-DETAILS 9.2.8): a root delta sets the two
// bits of SHA-256("UR evs digest"), which a query of the root matches and every path's query reads as a prefix's, so
// the empty covering prefix sends evs to the change list for every path; only the empty covering prefix calls for
// the root's absence, and no other path's absences name the root.
func TestEvsDigestAndAbsencesOfTheRoot(t *testing.T) {
	root := EvsTokenPath{}
	file := EvsTokenPath{evsTestToken("a"), evsTestToken("b")}
	if !NewEvsPathsDigest([]EvsTokenPath{root}, nil).MayChange(root) {
		t.Fatal("a root delta does not match the root")
	}
	if !NewEvsPathsDigest([]EvsTokenPath{file}, []EvsTokenPath{root}).MayChange(EvsTokenPath{evsTestToken("elsewhere")}) {
		t.Fatal("the empty covering prefix does not reach every path")
	}
	if EvsPathsDigest(0).MayChange(root) {
		t.Fatal("an empty digest matches the root")
	}
	if got := EvsAbsencePaths([]EvsTokenPath{root}, root); len(got) != 1 || len(got[0]) != 0 {
		t.Fatalf("the root under the empty covering prefix: %v", got)
	}
	if got := EvsAbsencePaths([]EvsTokenPath{file[:1]}, root); len(got) != 0 {
		t.Fatalf("the root under another covering prefix: %v", got)
	}
	for _, absent := range EvsAbsencePaths([]EvsTokenPath{root}, file) {
		if len(absent) == 0 {
			t.Fatal("a path's absences name the root")
		}
	}
}
