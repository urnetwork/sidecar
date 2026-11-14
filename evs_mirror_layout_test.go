// The sealed mirror layout's tests: each family's names as evs's keys give them and nothing else parsing; immutable
// objects kept once, equal bytes again a success and other bytes refused, across a restart; a segment held to its
// hash; slot copies replaced and removed; mirrored refs only moving forward; listings by ref in version order;
// forgetting one repo's mirror alone; and nothing a mirror holds reaching the medium in the clear.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A mirror of repoId on a client over store.
func evsTestMirror(t *testing.T, store SidecarStore, repoId Id) *EvsMirrorStore {
	t.Helper()
	test := newEvsTestClient(t, http.NotFoundHandler(), store)
	mirror, err := test.client.Mirror(repoId)
	if err != nil {
		t.Fatal(err)
	}
	return mirror
}

// What key holds, which must open.
func evsTestMirrorBytes(t *testing.T, mirror *EvsMirrorStore, key EvsMirrorKey) []byte {
	t.Helper()
	reader, err := mirror.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	held, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// n bytes of a pattern.
func evsTestMirrorBody(label string, n int) []byte {
	return bytes.Repeat([]byte(label), n/len(label)+1)[:n]
}

// Each family's name is evs's key for it, ids in lowercase hex and numbers in 20 digits, and parses back to its key;
// a name no key gives is refused.
func TestEvsMirrorNamesFollowEvsKeys(t *testing.T) {
	refId := evsTestId("ref")
	pushId := evsTestId("push")
	segmentId := sha256.Sum256([]byte("a segment"))
	mapSha256 := sha256.Sum256([]byte("a path map"))
	slotId := evsTestId("slot").Bytes()
	refHex := hex.EncodeToString(refId[:])
	for _, c := range []struct {
		key  EvsMirrorKey
		name string
	}{
		{key: EvsMirrorStatementKey(refId, 7), name: "stmt/" + refHex + "/00000000000000000007"},
		{key: EvsMirrorLogPageKey(refId, 0), name: "log/" + refHex + "/00000000000000000000"},
		{key: EvsMirrorRecordKey(pushId, 2), name: "rec/" + hex.EncodeToString(pushId[:]) + "/00000000000000000002"},
		{key: EvsMirrorSegmentKey(segmentId[:]), name: "seg/" + hex.EncodeToString(segmentId[:])},
		{key: EvsMirrorSlotKey(slotId), name: "slot/" + hex.EncodeToString(slotId)},
		{
			key:  EvsMirrorMapPartKey(refId, 3, mapSha256[:], 1),
			name: "pmap/" + refHex + "/00000000000000000003/" + hex.EncodeToString(mapSha256[:]) + "/00000000000000000001",
		},
	} {
		name, err := c.key.Name()
		if err != nil || name != c.name {
			t.Errorf("%s: name %q %v, want %q", c.key.Family, name, err, c.name)
			continue
		}
		parsed, err := ParseEvsMirrorName(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		again, err := parsed.Name()
		if err != nil || again != name || parsed.Family != c.key.Family || parsed.RefId != c.key.RefId ||
			!bytes.Equal(parsed.ObjectId, c.key.ObjectId) || parsed.Number != c.key.Number || parsed.PathEpoch != c.key.PathEpoch {
			t.Errorf("%s parsed as %+v", name, parsed)
		}
	}

	for _, key := range []EvsMirrorKey{
		EvsMirrorStatementKey(refId, 0),
		EvsMirrorSegmentKey(segmentId[:16]),
		EvsMirrorSlotKey(segmentId[:]),
		{Family: EvsMirrorRecords, ObjectId: pushId.Bytes(), Number: 1 << 32},
		{Family: "head", RefId: refId},
	} {
		if _, err := key.Name(); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
			t.Errorf("%+v named: %v", key, err)
		}
	}
	for _, name := range []string{
		"stmt/" + refHex + "/00000000000000000000",
		"stmt/" + strings.ToUpper(refHex) + "/00000000000000000007",
		"stmt/" + refHex + "/0000000000000000007",
		"stmt/" + refHex + "/0000000000000000000x",
		"stmt/" + refHex + "/00000000000000000007/extra",
		"rec/" + hex.EncodeToString(pushId[:]) + "/00000000004294967296",
		"seg/" + hex.EncodeToString(segmentId[:31]),
		"refs/" + refHex,
		"spill/00000000",
		"",
	} {
		if key, err := ParseEvsMirrorName(name); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
			t.Errorf("%q parsed as %+v", name, key)
		}
	}
}

// Every family but slot/ keeps what it first held: equal bytes again change nothing, other bytes are refused, and
// both hold for a mirror reopened on the same store.
func TestEvsMirrorImmutableObjectsKeepWhatTheyHold(t *testing.T) {
	store := newEvsTestStore(t)
	repoId := evsTestId("mirrored repo")
	mirror := evsTestMirror(t, store, repoId)
	refId := evsTestId("ref")
	mapSha256 := sha256.Sum256([]byte("a path map"))
	keys := []EvsMirrorKey{
		EvsMirrorStatementKey(refId, 1),
		EvsMirrorLogPageKey(refId, 0),
		EvsMirrorRecordKey(evsTestId("push"), 0),
		EvsMirrorMapPartKey(refId, 1, mapSha256[:], 0),
	}
	for _, key := range keys {
		first := evsTestMirrorBody("first "+string(key.Family), 300)
		if err := mirror.Put(key, bytes.NewReader(first)); err != nil {
			t.Fatalf("%s: %v", key.Family, err)
		}
		if err := mirror.Put(key, bytes.NewReader(first)); err != nil {
			t.Errorf("%s: equal bytes again: %v", key.Family, err)
		}
		other := evsTestMirrorBody("other "+string(key.Family), 300)
		if err := mirror.Put(key, bytes.NewReader(other)); !errors.Is(err, ErrEvsMirrorConflict) {
			t.Errorf("%s: other bytes: %v", key.Family, err)
		}
		if held := evsTestMirrorBytes(t, mirror, key); !bytes.Equal(held, first) {
			t.Errorf("%s: holds %q", key.Family, held)
		}
	}

	reopened := evsTestMirror(t, store, repoId)
	for _, key := range keys {
		first := evsTestMirrorBody("first "+string(key.Family), 300)
		if held := evsTestMirrorBytes(t, reopened, key); !bytes.Equal(held, first) {
			t.Errorf("%s after a restart: holds %q", key.Family, held)
		}
		if err := reopened.Put(key, bytes.NewReader([]byte("rewritten"))); !errors.Is(err, ErrEvsMirrorConflict) {
			t.Errorf("%s after a restart: other bytes: %v", key.Family, err)
		}
	}
}

// A segment is kept only under its own SHA-256, and no family keeps an empty body or one past its bound; a refused
// put leaves nothing.
func TestEvsMirrorHoldsObjectsToTheirNames(t *testing.T) {
	mirror := evsTestMirror(t, newEvsTestStore(t), evsTestId("mirrored repo"))
	segment := evsTestMirrorBody("segment bytes ", 4096)
	segmentId := sha256.Sum256(segment)
	wrongKey := EvsMirrorSegmentKey(make([]byte, sha256.Size))
	if err := mirror.Put(wrongKey, bytes.NewReader(segment)); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("a segment under another hash: %v", err)
	}
	if held, err := mirror.Has(wrongKey); err != nil || held {
		t.Errorf("a refused segment held: %v %v", held, err)
	}
	key := EvsMirrorSegmentKey(segmentId[:])
	if err := mirror.Put(key, bytes.NewReader(segment)); err != nil {
		t.Fatal(err)
	}
	if held := evsTestMirrorBytes(t, mirror, key); !bytes.Equal(held, segment) {
		t.Errorf("segment holds %d bytes", len(held))
	}
	// held, a wrong body is still no segment of that name
	if err := mirror.Put(key, bytes.NewReader(segment[1:])); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("a held segment's name with other bytes: %v", err)
	}

	statementKey := EvsMirrorStatementKey(evsTestId("ref"), 1)
	if err := mirror.Put(statementKey, bytes.NewReader(nil)); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("an empty statement: %v", err)
	}
	past := evsTestMirrorBody("statement ", DefaultEvsFormatSettings().StatementMaxByteCount+1)
	if err := mirror.Put(statementKey, bytes.NewReader(past)); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("a statement past its bound: %v", err)
	}
	if held, err := mirror.Has(statementKey); err != nil || held {
		t.Errorf("a refused statement held: %v %v", held, err)
	}
	if err := mirror.Put(statementKey, bytes.NewReader(past[:DefaultEvsFormatSettings().StatementMaxByteCount])); err != nil {
		t.Errorf("a statement at its bound: %v", err)
	}
	slotPast := evsTestMirrorBody("slot ", DefaultEvsFormatSettings().SlotMaxByteCount+1)
	if err := mirror.Put(EvsMirrorSlotKey(evsTestId("slot").Bytes()), bytes.NewReader(slotPast)); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("a slot past its bound: %v", err)
	}
}

// A slot copy follows evs's object: a put replaces it, as evs's rewrite dropping an erased key does, and a removal
// takes it, twice harmlessly.
func TestEvsMirrorSlotCopiesFollowEvs(t *testing.T) {
	mirror := evsTestMirror(t, newEvsTestStore(t), evsTestId("mirrored repo"))
	key := EvsMirrorSlotKey(evsTestId("slot").Bytes())
	if err := mirror.Put(key, bytes.NewReader([]byte("two wrapped keys"))); err != nil {
		t.Fatal(err)
	}
	if err := mirror.Put(key, bytes.NewReader([]byte("one wrapped key, one erased"))); err != nil {
		t.Fatal(err)
	}
	if held := evsTestMirrorBytes(t, mirror, key); string(held) != "one wrapped key, one erased" {
		t.Errorf("slot holds %q", held)
	}
	if err := mirror.Remove(key); err != nil {
		t.Fatal(err)
	}
	if held, err := mirror.Has(key); err != nil || held {
		t.Errorf("a removed slot held: %v %v", held, err)
	}
	if err := mirror.Remove(key); err != nil {
		t.Errorf("a second removal: %v", err)
	}
	if _, err := mirror.Open(key); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a removed slot opens: %v", err)
	}
}

// A mirrored ref moves only forward: a lower version and a fork at its version are refused, the same ref again moves
// only its time, and a restart reads it back.
func TestEvsMirrorRefMovesOnlyForward(t *testing.T) {
	store := newEvsTestStore(t)
	repoId := evsTestId("mirrored repo")
	mirror := evsTestMirror(t, store, repoId)
	refId := evsTestId("ref")
	if _, ok, err := mirror.Ref(refId); err != nil || ok {
		t.Fatalf("an empty mirror holds a ref: %v %v", ok, err)
	}
	at := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	chain := sha256.Sum256([]byte("C_5"))
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: refId, Version: 5, Chain: chain, MirroredAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: refId, Version: 4, Chain: chain, MirroredAt: at}); !errors.Is(err, ErrEvsMirrorRefLower) {
		t.Errorf("a lower ref: %v", err)
	}
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: refId, Version: 5, Chain: sha256.Sum256([]byte("forked C_5")), MirroredAt: at}); !errors.Is(err, ErrEvsMirrorRefFork) {
		t.Errorf("a fork: %v", err)
	}
	later := at.Add(time.Hour)
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: refId, Version: 5, Chain: chain, MirroredAt: later}); err != nil {
		t.Errorf("the same ref again: %v", err)
	}
	other := evsTestId("other ref")
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: other, Version: 1, Chain: sha256.Sum256([]byte("C_1")), MirroredAt: at}); err != nil {
		t.Fatal(err)
	}

	reopened := evsTestMirror(t, store, repoId)
	ref, ok, err := reopened.Ref(refId)
	if err != nil || !ok || ref.Version != 5 || ref.Chain != chain || !ref.MirroredAt.Equal(later) {
		t.Errorf("after a restart %+v %v %v", ref, ok, err)
	}
	refs, err := reopened.Refs()
	if err != nil || len(refs) != 2 {
		t.Fatalf("refs %d %v", len(refs), err)
	}
	for _, ref := range refs {
		if ref.RefId != refId && ref.RefId != other {
			t.Errorf("a ref no raise made: %s", ref.RefId)
		}
	}
}

// A family lists in name order, so a ref's statements come by version; a ref narrows only the families kept by ref,
// and a file no key names is not listed.
func TestEvsMirrorListsByRefAndNumber(t *testing.T) {
	store := newEvsTestStore(t)
	repoId := evsTestId("mirrored repo")
	mirror := evsTestMirror(t, store, repoId)
	refA := evsTestId("ref a")
	refB := evsTestId("ref b")
	for _, key := range []EvsMirrorKey{
		EvsMirrorStatementKey(refA, 10),
		EvsMirrorStatementKey(refA, 2),
		EvsMirrorStatementKey(refB, 3),
		EvsMirrorStatementKey(refA, 1),
	} {
		if err := mirror.Put(key, bytes.NewReader([]byte("a statement"))); err != nil {
			t.Fatal(err)
		}
	}
	// a stray file beside the statements, which no key names
	writeStoreFile(t, store, "mirror/"+evsUrlId(repoId)+"/stmt/"+evsUrlId(refA)+"/stray", []byte("not an object"))

	keys, err := mirror.List(EvsMirrorStatements, &refA)
	if err != nil {
		t.Fatal(err)
	}
	versions := []uint64{}
	for _, key := range keys {
		if key.RefId != refA {
			t.Errorf("ref a's listing holds %s", key.RefId)
		}
		versions = append(versions, key.Number)
	}
	if len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 10 {
		t.Errorf("ref a's versions %v", versions)
	}
	every, err := mirror.List(EvsMirrorStatements, nil)
	if err != nil || len(every) != 4 {
		t.Errorf("every statement %d %v", len(every), err)
	}
	if segments, err := mirror.List(EvsMirrorSegments, nil); err != nil || len(segments) != 0 {
		t.Errorf("segments %d %v", len(segments), err)
	}
	if _, err := mirror.List(EvsMirrorSegments, &refA); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("segments by ref: %v", err)
	}
	if _, err := mirror.List("head", nil); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
		t.Errorf("no family: %v", err)
	}
}

// Forgetting a repo's mirror takes every file of it and nothing of another repo's mirror or the client's pins.
func TestEvsMirrorForgetTakesTheRepoAlone(t *testing.T) {
	store := newEvsTestStore(t)
	test := newEvsTestClient(t, http.NotFoundHandler(), store)
	repoA := evsTestId("repo a")
	repoB := evsTestId("repo b")
	mirrorA, err := test.client.Mirror(repoA)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := test.client.Mirror(repoA); err != nil || again != mirrorA {
		t.Errorf("a second mirror of one repo: %v", err)
	}
	mirrorB, err := test.client.Mirror(repoB)
	if err != nil || mirrorB == mirrorA {
		t.Fatalf("repo b's mirror: %v", err)
	}
	refId := evsTestId("ref")
	for _, mirror := range []*EvsMirrorStore{mirrorA, mirrorB} {
		if err := mirror.Put(EvsMirrorStatementKey(refId, 1), bytes.NewReader([]byte("a statement"))); err != nil {
			t.Fatal(err)
		}
		if err := mirror.RaiseRef(&EvsMirrorRef{RefId: refId, Version: 1, MirroredAt: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := test.client.Pins().Raise(&EvsPin{RepoId: repoA, RefId: refId, Version: 1}); err != nil {
		t.Fatal(err)
	}

	if err := mirrorA.Forget(); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List("mirror/" + evsUrlId(repoA) + "/")
	if err != nil || len(entries) != 0 {
		t.Errorf("repo a's mirror keeps %d files %v", len(entries), err)
	}
	if held, err := mirrorB.Has(EvsMirrorStatementKey(refId, 1)); err != nil || !held {
		t.Errorf("repo b's statement gone: %v %v", held, err)
	}
	if _, ok, err := mirrorB.Ref(refId); err != nil || !ok {
		t.Errorf("repo b's ref gone: %v %v", ok, err)
	}
	if _, ok, err := test.client.Pins().Pin(repoA, refId); err != nil || !ok {
		t.Errorf("repo a's pin gone with its mirror: %v %v", ok, err)
	}
}

// What a mirror holds sits in the evs component's directory at the layout's name, sealed: the medium never holds its
// bytes in the clear.
func TestEvsMirrorSealsWhatItHolds(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, evsComponentName)
	repoId := evsTestId("mirrored repo")
	mirror := evsTestMirror(t, store, repoId)
	refId := evsTestId("ref")
	statement := []byte("a recognizable signed statement, as received from evs")
	if err := mirror.Put(EvsMirrorStatementKey(refId, 1), bytes.NewReader(statement)); err != nil {
		t.Fatal(err)
	}
	segment := evsTestMirrorBody("recognizable segment ciphertext ", 70*1024)
	segmentId := sha256.Sum256(segment)
	if err := mirror.Put(EvsMirrorSegmentKey(segmentId[:]), bytes.NewReader(segment)); err != nil {
		t.Fatal(err)
	}
	statementPath := networkFilePath(testNetworkId, "evs/mirror/"+evsUrlId(repoId)+"/stmt/"+evsUrlId(refId)+"/00000000000000000001")
	segmentPath := networkFilePath(testNetworkId, "evs/mirror/"+evsUrlId(repoId)+"/seg/"+hex.EncodeToString(segmentId[:]))
	snapshot := backendSnapshot(t, backend)
	for _, path := range []string{statementPath, segmentPath} {
		if _, ok := snapshot[path]; !ok {
			t.Errorf("nothing at %s", path)
		}
	}
	for path, content := range snapshot {
		if bytes.Contains(content, statement) || bytes.Contains(content, segment[:64]) {
			t.Errorf("%s holds mirrored bytes in the clear", path)
		}
	}
}

// DESIGN-DETAILS 8.2.2's local state names under local/<repo_id>/: each family's name round-trips, and a name no key
// gives is refused.
func TestEvsLocalStateNames(t *testing.T) {
	refId := evsTestId("local ref")
	importId := EvsImportId{1, 2, 3, 4, 5, 6, 7, 8}
	for _, key := range []EvsLocalKey{
		{Family: EvsLocalRefs, RefId: refId}, {Family: EvsLocalHeld, RefId: refId}, {Family: EvsLocalBorn, RefId: refId},
		{Family: EvsLocalJournals, RefId: refId}, {Family: EvsLocalTips, RefId: refId, Page: 7},
		{Family: EvsLocalTipIndex, OidByte: 0xa5}, {Family: EvsLocalImports, ImportId: importId},
	} {
		name, err := key.Name()
		if err != nil {
			t.Fatalf("%s: %v", key.Family, err)
		}
		parsed, err := ParseEvsLocalName(name)
		if err != nil || parsed != key {
			t.Errorf("%s: %q parsed to %+v, %v", key.Family, name, parsed, err)
		}
	}
	if name, _ := (EvsLocalKey{Family: EvsLocalImports, ImportId: importId}).Name(); name != "import/0102030405060708" {
		t.Errorf("an import record's name %q", name)
	}
	if name, _ := (EvsLocalKey{Family: EvsLocalTips, RefId: refId, Page: 7}).Name(); !strings.HasSuffix(name, "/00000000000000000007") {
		t.Errorf("a tips page's name %q", name)
	}
	for _, name := range []string{
		"ref", "ref/" + strings.Repeat("A", 32), "ref/" + strings.Repeat("a", 30), "tips/" + evsUrlId(refId) + "/7",
		"tipindex/a", "tipindex/a5a5", "import/01020304050607", "import/0102030405060708/x", "mirror/x",
	} {
		if _, err := ParseEvsLocalName(name); !errors.Is(err, ErrEvsMirrorObjectInvalid) {
			t.Errorf("%q: %v", name, err)
		}
	}
}

// A helper ref's name (DESIGN-DETAILS 8.2.6): ur/<sidecar_id>/import/<id>/<n>, an owned ref of the importing
// sidecar, parsed back to its sidecar, import and number; any other name, a number with a leading zero or 0 among
// them, is not one.
func TestEvsImportHelperRefNames(t *testing.T) {
	sidecarId := evsTestId("importing sidecar")
	importId := EvsImportId{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3}
	name := EvsImportHelperRefName(sidecarId, importId, 12)
	if string(name) != "ur/"+sidecarId.String()+"/import/deadbeef00010203/12" {
		t.Fatalf("name %q", name)
	}
	if owner, ok := EvsOwnedRefOwner(name); !ok || owner != sidecarId {
		t.Fatalf("a helper ref is an owned ref of its sidecar: %v %v", owner, ok)
	}
	parsedSidecar, parsedImport, n, ok := ParseEvsImportHelperRefName(name)
	if !ok || parsedSidecar != sidecarId || parsedImport != importId || n != 12 {
		t.Fatalf("parsed %v %v %d %v", parsedSidecar, parsedImport, n, ok)
	}
	prefix := "ur/" + sidecarId.String() + "/import/deadbeef00010203/"
	for _, other := range []string{
		prefix + "0", prefix + "012", prefix + "x", prefix, prefix + "1/2", "ur/" + sidecarId.String() + "/import/deadbeef0001020/1",
		"ur/" + sidecarId.String() + "/conflicts/main/20261110T000000Z", "main", "ur/not-a-sidecar/import/deadbeef00010203/1",
		prefix + "4294967296",
	} {
		if _, _, _, ok := ParseEvsImportHelperRefName([]byte(other)); ok {
			t.Errorf("%q parsed as a helper ref", other)
		}
	}
}
