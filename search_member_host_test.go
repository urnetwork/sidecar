//go:build !ios_extension

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestMemberSearchAttributesDeviceAndTaggedWriterToItsSignedMember(t *testing.T) {
	owner, other := evsTestId("owner"), evsTestId("other")
	device, tagged, separate, unseen := evsTestId("device"), evsTestId("tagged"), evsTestId("separate"), evsTestId("unseen")
	state := &ConfigState{sidecars: map[Id]*bridge.SidecarRow{
		device: {MemberId: owner[:], RevokedAt: 9}, tagged: {Sponsor: owner[:]}, separate: {MemberId: other[:]},
	}}
	for id, want := range map[Id]Id{device: owner, tagged: owner, separate: other, unseen: {}} {
		got, ok := state.searchWriterMember(id)
		if got != want || ok != (want != (Id{})) {
			t.Errorf("writer %v: got %v, %v, want %v", id, got, ok, want)
		}
	}
}

func TestMemberSearchFollowsTheContentRefOfEachSignedRepoClass(t *testing.T) {
	key, err := NewEvsRefKey(evsTestRepoKey(evsTestId("repo"), 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind protocol.RepoKind
		name []byte
	}{
		{kind: protocol.RepoKind_REPO_KIND_DIRECTORY, name: DirectoryCardsRefName()},
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, name: EvsMainRefName},
		{kind: protocol.RepoKind_REPO_KIND_MAILBOX, name: EvsMainRefName},
		{kind: protocol.RepoKind_REPO_KIND_TEAM_RECORD, name: nil},
	} {
		name := memberSearchDefaultFileRef(tc.kind)
		if name != string(tc.name) {
			t.Fatalf("class %v follows %q, expected %q", tc.kind, name, tc.name)
		}
		if name != "" {
			id, err := EvsRefId(key, []byte(name))
			if err != nil || id == (Id{}) {
				t.Fatalf("invalid content ref for class %v: %v", tc.kind, err)
			}
		}
	}
}

func TestMemberSearchConfirmsOnlyTheSignedReposDocumentClass(t *testing.T) {
	id := evsTestId("item")
	mailPath := MailMessagePath(202611, id)
	announcement := string(directoryIndexAnnouncementName(DirectoryAnnouncementKindRepo, Id{}, id))
	cases := []struct {
		kind  protocol.RepoKind
		group bool
		doc   IndexDocKind
		path  string
		allow bool
	}{
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, group: false, doc: IndexDocFile, path: "notes/path", allow: true},
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, group: false, doc: IndexDocFile, path: ".ur-index/file", allow: false},
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, group: false, doc: IndexDocMail, path: mailPath, allow: false},
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, group: true, doc: IndexDocMail, path: mailPath, allow: true},
		{kind: protocol.RepoKind_REPO_KIND_GENERAL, group: true, doc: IndexDocFile, path: mailPath, allow: false},
		{kind: protocol.RepoKind_REPO_KIND_MAILBOX, group: false, doc: IndexDocMail, path: "m/unknown", allow: false},
		{kind: protocol.RepoKind_REPO_KIND_MAILBOX, group: false, doc: IndexDocMail, path: "i/mail", allow: false},
		{kind: protocol.RepoKind_REPO_KIND_MAILBOX, group: false, doc: IndexDocMail, path: mailPath, allow: true},
		{kind: protocol.RepoKind_REPO_KIND_DIRECTORY, group: false, doc: IndexDocDerived, path: announcement, allow: true},
		{kind: protocol.RepoKind_REPO_KIND_DIRECTORY, group: false, doc: IndexDocFile, path: DirectoryCardPath(id), allow: false},
		{kind: protocol.RepoKind_REPO_KIND_DIRECTORY, group: false, doc: IndexDocDerived, path: "a/unknown", allow: false},
		{kind: protocol.RepoKind_REPO_KIND_CONFIG, group: false, doc: IndexDocFile, path: "notes/path", allow: false},
	}
	for _, tc := range cases {
		repo := &SearchScopeRepo{Kind: tc.kind, GroupInbox: tc.group}
		confirmer := &searchConfirmer{query: &SearchQuery{}, acceptRow: func(r *indexRow) bool { return memberSearchIndexRow(repo, r) }}
		m, err := confirmer.confirm(context.Background(), &searchConfirmCandidate{row: &indexRow{docKind: tc.doc, locator: tc.path}})
		if err != nil || (m.state == searchMatchConfirmed) != tc.allow {
			t.Errorf("kind %v group %v doc %d path %q: %+v, %v", tc.kind, tc.group, tc.doc, tc.path, m, err)
		}
	}
}

// A protected member cannot carry a writer's snapshot, a refusal, or a fresh allowance through restart.
func TestMemberSearchReceiptRoundRefusalAndRestart(t *testing.T) {
	world := newTestSyncWorld(t, true)
	state := newSearchStateTestWorld(t)
	world.push(t, evsTestId("writer"), "orchard", 1)
	world.round(t)
	var requests []*RecordReceiptRequest
	refuse := true
	bind := func() {
		world.sync.args.receiptState = state.newState(t)
		scope := &SearchScopeRepo{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_VAULT, Readable: true, ReceiptRequired: true}
		nonWriter, deposit := searchReceiptFollowArgs(scope, func(ctx context.Context, r *RecordReceiptRequest) error {
			if r.RepoId != world.repoId || r.Purpose != RecordReadPurposeSearch || !r.NoSession || len(r.ObjectIds) == 0 {
				t.Fatalf("invalid protected search receipt: %+v", r)
			}
			requests = append(requests, r)
			if refuse {
				return ErrRecordReceiptRefused
			}
			return nil
		})
		if err := world.sync.Follow(&searchSyncRefArgs{repoId: world.repoId, refId: world.refId, repoKind: scope.Kind, source: world.source,
			nonWriter: nonWriter, depositReceipt: deposit, mayErase: func(Id, int64) bool { return true }}); err != nil {
			t.Fatal(err)
		}
	}
	bind()
	if snapshot, err := world.sync.Snapshot(world.repoId, world.refId); snapshot != nil || !errors.Is(err, errSearchSyncReceipt) {
		t.Fatalf("former writer snapshot admitted without a search receipt: %v", err)
	}
	before := len(world.source.fetched())
	if err := world.sync.RunRound(t.Context(), world.repoId, world.refId, false); !errors.Is(err, errSearchSyncReceipt) {
		t.Fatal(err)
	}
	if n := len(world.source.fetched()); n != before || len(requests) != 1 {
		t.Fatalf("protected reads=%d, receipts=%d", n-before, len(requests))
	}
	world.sync.Close()
	world.restart(t)
	bind()
	if snapshot, err := world.sync.Snapshot(world.repoId, world.refId); snapshot != nil || !errors.Is(err, errSearchSyncReceipt) {
		t.Fatalf("restarted snapshot admitted without its receipt: %v", err)
	}
	if err := world.sync.RunRound(t.Context(), world.repoId, world.refId, true); !errors.Is(err, errSearchReceiptInterval) {
		t.Fatal(err)
	}
	if len(requests) != 1 {
		t.Fatalf("restart spent another receipt: %d", len(requests))
	}
	state.clock.advance(state.settings.NonWriterSyncInterval)
	refuse = false
	world.round(t)
	snapshot := world.snapshot(t)
	if !snapshot.manifest.Receipted || len(requests) < 2 {
		t.Fatal("the next budgeted round did not qualify the cached files")
	}
	snapshot.Release()
}

// The signed Git OID and size select a digest for each supported canonical settings encoding before a body read.
func TestMemberSearchReceiptsNameCanonicalSettings(t *testing.T) {
	for _, tc := range []*protocol.IndexSettings{{}, {Off: true}, {WindowDays: 7}, {Off: true, WindowDays: 365}} {
		b, err := indexEncodeSettings(tc)
		if err != nil {
			t.Fatal(err)
		}
		oid := evsGitObjectOid(evsGitBlobKind, b)
		fields := &protocol.EvsSealedFields{GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: uint64(len(b))}
		if got := memberSearchSettingsDigest(fields); got != sha256.Sum256(b) {
			t.Fatal("signed settings receipt identity changed")
		}
		fields.Size++
		if got := memberSearchSettingsDigest(fields); got != ([sha256.Size]byte{}) {
			t.Fatal("accepted mismatched settings size")
		}
	}
}

// Team record cards have the registered run and no private vault fields. Its raw stream entries are never documents.
func TestMemberSearchTeamRecordShowsOnlyRegisteredRunCards(t *testing.T) {
	repo := &SearchScopeRepo{Kind: protocol.RepoKind_REPO_KIND_TEAM_RECORD}
	run := evsTestId("orchard")
	path := string(indexRunCardName(run))
	row := &indexRow{docKind: IndexDocDerived, locator: path}
	row.fields[indexFieldFirstRegistered] = RecordKindRun.String()
	row.fields[indexFieldFirstRegistered+4] = path[len(indexRunCardPrefix):]
	if !memberSearchIndexRow(repo, row) {
		t.Fatal("team run card not searchable")
	}
	row.fields[indexFieldTitle] = "private title"
	if memberSearchIndexRow(repo, row) {
		t.Fatal("a vault title reached a team card")
	}
	row.fields[indexFieldTitle] = ""
	row.fields[indexFieldFirstRegistered+4] = ""
	if memberSearchIndexRow(repo, row) {
		t.Fatal("an unbound card was searchable")
	}
	row.docKind, row.locator = IndexDocRecord, "e/0/0/1"
	row.fields[indexFieldFirstRegistered] = RecordKindContext.String()
	if memberSearchIndexRow(repo, row) {
		t.Fatal("a raw team entry was searchable")
	}
}

// The same stock follow used by the daemon binds the receipt gate to the physical companion only for a non-writer.
func TestMemberSearchFollowsSharedRecordWithBoundReceipts(t *testing.T) {
	world := newTestSyncWorld(t, true)
	member := &memberSearchSource{evs: &EvsClient{}, syncer: world.sync, record: &SidecarRecord{receipts: newRecordReceipts(&recordWriter{})}}
	scope := &SearchScopeRepo{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_VAULT, Readable: true}
	ref := &SearchScopeRef{RefId: evsTestId("content"), indexRef: world.refId, Companion: true, Unbuilt: true}
	for _, protected := range []bool{true, false, true} {
		scope.ReceiptRequired = protected
		if err := member.follow(scope, ref); err != nil {
			t.Fatal(err)
		}
		bound := world.sync.refs[[2]Id{world.repoId, world.refId}]
		if bound == nil || (bound.args.depositReceipt != nil) != protected || bound.args.nonWriter != protected {
			t.Fatalf("physical index has the wrong receipt binding for protected=%v", protected)
		}
		source := bound.args.source.(*memberIndexSource)
		if source.nonWriter != protected || source.store.searchMetadata != protected || !source.store.companion || string(source.store.refName) != string(EvsIndexRefName) ||
			world.sync.refs[[2]Id{world.repoId, ref.RefId}] != nil {
			t.Fatal("a stream was bound to the wrong index or read mode")
		}
	}
	scope.receiptSkipped = true
	_, excluded := searchResolveScope([]*SearchScopeRepo{scope}, &SearchRequest{Repos: []Id{scope.RepoId}})
	if len(excluded) != 1 || excluded[0].Reason != SearchExcludedReceipt {
		t.Fatalf("receipt refusal before stream discovery: %+v", excluded)
	}
}
