//go:build !ios_extension

package sidecar

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

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
		{protocol.RepoKind_REPO_KIND_GENERAL, false, IndexDocFile, "notes/path", true},
		{protocol.RepoKind_REPO_KIND_GENERAL, false, IndexDocFile, ".ur-index/file", false},
		{protocol.RepoKind_REPO_KIND_GENERAL, false, IndexDocMail, mailPath, false},
		{protocol.RepoKind_REPO_KIND_GENERAL, true, IndexDocMail, mailPath, true},
		{protocol.RepoKind_REPO_KIND_GENERAL, true, IndexDocFile, mailPath, false},
		{protocol.RepoKind_REPO_KIND_MAILBOX, false, IndexDocMail, "m/unknown", false},
		{protocol.RepoKind_REPO_KIND_MAILBOX, false, IndexDocMail, "i/mail", false},
		{protocol.RepoKind_REPO_KIND_MAILBOX, false, IndexDocMail, mailPath, true},
		{protocol.RepoKind_REPO_KIND_DIRECTORY, false, IndexDocDerived, announcement, true},
		{protocol.RepoKind_REPO_KIND_DIRECTORY, false, IndexDocFile, DirectoryCardPath(id), false},
		{protocol.RepoKind_REPO_KIND_DIRECTORY, false, IndexDocDerived, "a/unknown", false},
		{protocol.RepoKind_REPO_KIND_CONFIG, false, IndexDocFile, "notes/path", false},
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
