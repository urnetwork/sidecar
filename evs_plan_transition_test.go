//go:build !ios_extension

package sidecar

// EVS2-M10-15's planner rules as pure cases over EvsPlanFormat2Links (§11.7's Versionless rows; FS-64, FS-67, FS-68):
// new, overwrite, staged and chunked versionless versions; one chunk changed citing the other four; off and on over a
// small file and a chunked one (off cites chunks as kind 1 and uploads nothing, on adopts as kind 1, staged turning
// inline); rule (4) re-encrypting every chunk; a 20 MiB file as five 4 MiB kind-5 chunks; a file past 2 GiB refused by
// name; the plan's bytes passing EvsCheckCitation; and EvsPlanRemove listing each versionless file below a removal.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A source of size bytes reporting a size it does not hold, for the cap's check, which reads nothing.
type evsTestSizedSource struct {
	*bytes.Reader
	size int64
}

func (self *evsTestSizedSource) Size() int64 {
	return self.size
}

// A previous version's chain of count locators of kind, staged or not.
func evsTestPreviousChain(label string, count int, kind protocol.EvsLocatorKind, staged bool) []*protocol.EvsLocator {
	chain := []*protocol.EvsLocator{}
	for i := range count {
		id := sha256.Sum256([]byte(fmt.Sprint("previous ", label, " ", i)))
		chain = append(chain, &protocol.EvsLocator{Kind: uint32(kind), Id: id[:], Offset: 120, Length: 4096, Staged: staged})
	}
	return chain
}

// The entry version links render to, written records named by fresh ids: each staged one in staged, each unstaged
// kind-5 one in uploads, as the sender seals and uploads them.
func evsTestRenderLinks(links []*EvsPlannedLink, version uint64, versioning uint32, staged map[[32]byte]bool, uploads map[[32]byte]bool) *protocol.EvsEntryVersion {
	entry := &protocol.EvsEntryVersion{Version: version, PushId: evsTestId("plan push").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Versioning: versioning}
	for i, link := range links {
		if link.Kept != nil {
			locator := &protocol.EvsLocator{Kind: uint32(link.Kind), Id: link.Kept.GetId(), Offset: link.Kept.GetOffset(), Length: link.Kept.GetLength()}
			entry.Chain = append(entry.Chain, locator)
			continue
		}
		id := sha256.Sum256([]byte(fmt.Sprint("written ", version, " ", i)))
		locator := &protocol.EvsLocator{Kind: uint32(link.Kind), Id: id[:], Offset: 120, Length: 4096, Staged: link.Staged}
		switch {
		case link.Staged:
			staged[id] = true
		case link.Kind == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
			uploads[id] = true
		}
		entry.Chain = append(entry.Chain, locator)
	}
	return entry
}

// links rendered and held to the citation rule against base, the path's previous version.
func evsTestRequireCitable(t *testing.T, name string, links []*EvsPlannedLink, versioning uint32, base *protocol.EvsEntryVersion) {
	t.Helper()
	staged, uploads := map[[32]byte]bool{}, map[[32]byte]bool{}
	version := uint64(1)
	if base != nil {
		version = base.GetVersion() + 1
	}
	entry := evsTestRenderLinks(links, version, versioning, staged, uploads)
	path := EvsTokenPath{evsTestToken("plan path")}
	err := EvsCheckCitation([]*EvsCitation{{TokenPath: path, Version: entry, Base: base}}, &EvsCitationSources{
		RefId: evsTestId("plan ref"), Staged: staged, VersionlessUploads: uploads,
	})
	if err != nil {
		t.Errorf("%s: the plan's bytes fail the citation rule: %v", name, err)
	}
}

func evsTestLinkKinds(links []*EvsPlannedLink) (kept int, written int, staged int, kind5 int, kind1 int) {
	for _, link := range links {
		if link.Kept != nil {
			kept += 1
		} else {
			written += 1
		}
		if link.Staged {
			staged += 1
		}
		switch link.Kind {
		case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
			kind5 += 1
		case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
			kind1 += 1
		}
	}
	return
}

func TestEvsPlanVersionlessNewOverwriteStagedAndChunked(t *testing.T) {
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	small := evsTestContent("small versionless", 4000)
	links, reason, err := EvsPlanFormat2Links(&EvsPlanFormat2Args{Versioning: versionless, Size: uint64(len(small)), Content: bytes.NewReader(small)})
	if err != nil || reason != EvsCheckpointNewFile {
		t.Fatalf("a new small file: %v %v", reason, err)
	}
	if kept, written, staged, kind5, _ := evsTestLinkKinds(links); kept != 0 || written != 1 || staged != 1 || kind5 != 1 {
		t.Errorf("a new small file: kept %d written %d staged %d kind5 %d", kept, written, staged, kind5)
	}
	evsTestRequireCitable(t, "a new small file", links, versionless, nil)

	medium := evsTestContent("medium versionless", 64*1024)
	links, _, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{Versioning: versionless, Size: uint64(len(medium)), Content: bytes.NewReader(medium)})
	if _, written, staged, kind5, _ := evsTestLinkKinds(links); err != nil || written != 1 || staged != 0 || kind5 != 1 {
		t.Errorf("a 64 KiB file: written %d staged %d kind5 %d %v", written, staged, kind5, err)
	}

	// FS-64's setup: 20 MiB as five 4 MiB kind-5 chunks, none staged
	big := evsTestContent("big versionless", 20*1024*1024)
	links, reason, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{Versioning: versionless, Size: uint64(len(big)), Content: bytes.NewReader(big)})
	if _, written, staged, kind5, _ := evsTestLinkKinds(links); err != nil || reason != EvsCheckpointChunked || written != 5 || staged != 0 || kind5 != 5 {
		t.Fatalf("20 MiB: %v written %d staged %d kind5 %d %v", reason, written, staged, kind5, err)
	}
	evsTestRequireCitable(t, "20 MiB", links, versionless, nil)

	// one chunk changed: the other four kept as kind 5, the touched one written as kind 5
	previousChain := evsTestPreviousChain("big", 5, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, false)
	edited := bytes.Clone(big)
	edited[9*1024*1024] ^= 1
	previous := &EvsChainState{RecordCount: 5, Chunked: true, Size: uint64(len(big))}
	args := &EvsPlanFormat2Args{
		Versioning: versionless, Size: uint64(len(edited)), Content: bytes.NewReader(edited),
		Previous: previous, PreviousVersioning: versionless, PreviousChain: previousChain, PreviousContent: bytes.NewReader(big),
	}
	links, _, err = EvsPlanFormat2Links(args)
	if kept, written, _, kind5, _ := evsTestLinkKinds(links); err != nil || kept != 4 || written != 1 || kind5 != 5 {
		t.Fatalf("one chunk changed: kept %d written %d kind5 %d %v", kept, written, kind5, err)
	}
	base := &protocol.EvsEntryVersion{Version: 3, Versioning: versionless, Chain: previousChain}
	evsTestRequireCitable(t, "one chunk changed", links, versionless, base)

	// rule (4): every chunk anew
	args.RewriteAll = true
	links, _, err = EvsPlanFormat2Links(args)
	if kept, written, _, _, _ := evsTestLinkKinds(links); err != nil || kept != 0 || written != 5 {
		t.Errorf("rule (4): kept %d written %d %v", kept, written, err)
	}

	// an overwrite of a small staged file: staged again, never citing the staged locator
	stagedChain := evsTestPreviousChain("staged", 1, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, true)
	links, _, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{
		Versioning: versionless, Size: uint64(len(small)), Content: bytes.NewReader(small), Unchanged: true,
		Previous: &EvsChainState{RecordCount: 1, Size: uint64(len(small))}, PreviousVersioning: versionless, PreviousChain: stagedChain,
	})
	if kept, written, staged, _, _ := evsTestLinkKinds(links); err != nil || kept != 0 || written != 1 || staged != 1 {
		t.Errorf("a staged file's setting change: kept %d written %d staged %d %v", kept, written, staged, err)
	}
	evsTestRequireCitable(t, "a staged file's setting change", links, versionless, &protocol.EvsEntryVersion{Version: 3, Versioning: versionless, Chain: stagedChain})

	// past 2 GiB: refused by name, nothing read
	_, _, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{Versioning: versionless, Size: EvsFileMaxByteCount + 1, Content: &evsTestSizedSource{Reader: bytes.NewReader(nil), size: EvsFileMaxByteCount + 1}})
	if !errors.Is(err, ErrEvsFileTooLarge) {
		t.Errorf("past 2 GiB: %v", err)
	}
}

// FS-68's off and on rows over a small file and a chunked one.
func TestEvsPlanTransitionsOffAndOn(t *testing.T) {
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	kept := uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	big := evsTestContent("transition big", 12*1024*1024)
	versionedChunks := evsTestPreviousChain("versioned chunks", 3, protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, false)

	// off, unchanged, no diff or inline: k's records cited as kind 1, nothing written
	off := &EvsPlanFormat2Args{
		Versioning: versionless, Size: uint64(len(big)), Content: bytes.NewReader(big), Unchanged: true,
		Previous: &EvsChainState{RecordCount: 3, Chunked: true, Size: uint64(len(big))}, PreviousVersioning: kept,
		PreviousChain: versionedChunks, PreviousContent: bytes.NewReader(big),
	}
	links, _, err := EvsPlanFormat2Links(off)
	if k, written, _, _, kind1 := evsTestLinkKinds(links); err != nil || k != 3 || written != 0 || kind1 != 3 {
		t.Fatalf("off, unchanged: kept %d written %d kind1 %d %v", k, written, kind1, err)
	}
	evsTestRequireCitable(t, "off, unchanged", links, versionless, &protocol.EvsEntryVersion{Version: 5, Chain: versionedChunks})

	// off over a chain holding a diff: one checkpoint as kind 5
	small := evsTestContent("transition small", 3000)
	diffChain := evsTestPreviousChain("diffed", 2, protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, false)
	links, _, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{
		Versioning: versionless, Size: uint64(len(small)), Content: bytes.NewReader(small), Unchanged: true,
		Previous: &EvsChainState{RecordCount: 2, DiffCount: 1, Size: uint64(len(small))}, PreviousVersioning: kept, PreviousChain: diffChain,
	})
	if k, written, _, kind5, _ := evsTestLinkKinds(links); err != nil || k != 0 || written != 1 || kind5 != 1 {
		t.Errorf("off over a diff: kept %d written %d kind5 %d %v", k, written, kind5, err)
	}

	// off, one chunk changed: k's unchanged kind-1 chunks kept as kind 1, the changed one written as kind 5
	edited := bytes.Clone(big)
	edited[0] ^= 1
	off.Content, off.Unchanged = bytes.NewReader(edited), false
	links, _, err = EvsPlanFormat2Links(off)
	if k, written, _, kind5, kind1 := evsTestLinkKinds(links); err != nil || k != 2 || written != 1 || kind5 != 1 || kind1 != 2 {
		t.Errorf("off, one chunk changed: kept %d written %d kind5 %d kind1 %d %v", k, written, kind5, kind1, err)
	}
	evsTestRequireCitable(t, "off, one chunk changed", links, versionless, &protocol.EvsEntryVersion{Version: 5, Chain: versionedChunks})

	// on, unchanged: k's uploaded kind-5 segments adopted as kind 1, no re-upload
	kind5Chunks := evsTestPreviousChain("versionless chunks", 3, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, false)
	on := &EvsPlanFormat2Args{
		Versioning: kept, Size: uint64(len(big)), Content: bytes.NewReader(big), Unchanged: true,
		Previous: &EvsChainState{RecordCount: 3, Chunked: true, Size: uint64(len(big))}, PreviousVersioning: versionless,
		PreviousChain: kind5Chunks, PreviousContent: bytes.NewReader(big),
	}
	links, _, err = EvsPlanFormat2Links(on)
	if k, written, _, kind5, kind1 := evsTestLinkKinds(links); err != nil || k != 3 || written != 0 || kind5 != 0 || kind1 != 3 {
		t.Fatalf("on, unchanged: kept %d written %d kind5 %d kind1 %d %v", k, written, kind5, kind1, err)
	}
	evsTestRequireCitable(t, "on, unchanged", links, kept, &protocol.EvsEntryVersion{Version: 5, Versioning: versionless, Chain: kind5Chunks})

	// on, a staged small file: written anew, a versioned record, never staged
	stagedChain := evsTestPreviousChain("on staged", 1, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, true)
	links, _, err = EvsPlanFormat2Links(&EvsPlanFormat2Args{
		Versioning: kept, Size: uint64(len(small)), Content: bytes.NewReader(small), Unchanged: true,
		Previous: &EvsChainState{RecordCount: 1, Size: uint64(len(small))}, PreviousVersioning: versionless, PreviousChain: stagedChain,
	})
	if k, written, staged, kind5, kind1 := evsTestLinkKinds(links); err != nil || k != 0 || written != 1 || staged != 0 || kind5 != 0 || kind1 != 1 {
		t.Errorf("on, staged: kept %d written %d staged %d kind5 %d kind1 %d %v", k, written, staged, kind5, kind1, err)
	}
}

// A removal's walk: each versionless file below the removed directory, at any depth, as a file removal; versioned
// files, directories and a path the push writes again left out; a ref's DELETE walks from the root.
type evsTestRemoveTree map[string][]*EvsPlanRemoveChild

func (self evsTestRemoveTree) Children(ctx context.Context, directory string) ([]*EvsPlanRemoveChild, error) {
	return self[directory], nil
}

func TestEvsPlanRemoveListsEachVersionlessFileBelow(t *testing.T) {
	tree := evsTestRemoveTree{
		"":          {{Path: "docs", Directory: true}, {Path: "top.iso", Versioning: 1}},
		"docs":      {{Path: "docs/a.txt"}, {Path: "docs/big.iso", Versioning: 1}, {Path: "docs/deep", Directory: true}, {Path: "docs/again.iso", Versioning: 1}},
		"docs/deep": {{Path: "docs/deep/x.bin", Versioning: 1}, {Path: "docs/deep/index", Versioning: 2}},
	}
	removals, err := EvsPlanRemove(context.Background(), tree, "docs", map[string]bool{"docs/again.iso": true})
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, removal := range removals {
		if !removal.Remove || removal.Content != nil {
			t.Errorf("%s is no removal", removal.Path)
		}
		listed[removal.Path] = true
	}
	if len(listed) != 3 || !listed["docs/big.iso"] || !listed["docs/deep/x.bin"] || !listed["docs/deep/index"] {
		t.Errorf("listed %v", listed)
	}
	all, err := EvsPlanRemove(context.Background(), tree, "", nil)
	if err != nil || len(all) != 5 {
		t.Errorf("a DELETE's walk listed %d: %v", len(all), err)
	}
}
