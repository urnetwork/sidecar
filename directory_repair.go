//go:build !ios_extension

// §16.11's repair row for format 2's files (RECORD-M10-02; I-EVS-14, FS-84): evs sees no path, so a breach can still
// replace or remove a card or repo file, and from format 2 the purge deletes the version it replaced a minute later;
// every file under the cards ref is current state its rightful writer reproduces, so a breach denies only until that
// writer's repair and costs no history. Readers show the version they accepted last meanwhile (directory_card.go).
//
//	card       once its path's newest version is another's, a version this copy refused, the sidecar puts its card
//	           again at its next sync: the items it last put, at a seq above, with a fresh at
//	repo file  once its path's newest version is one this copy refused, each device holding D-MCP-35's right on the
//	           repo now puts the repo file again from its folded state: the item that stands, as its own, at that item's
//	           version; racing devices meet at the path's CAS, and the first wins
//	deleted    once a repo is deleted, the signer of its standing file, or a directory admin, removes it
//	notices    the requester's daemon re-creates a pending notice from its request entry (RECORD-M6-18's
//	           repairNotices), and the decider's device rewrites a decided one (RECORD-M6-19's resume); neither is here
//
// A site loss is the card's next renewal's to repair, which RECORD-M10-03's switch writes as a card; the repo files a
// mirror re-seeds come back as they were. Runs after each sync the loop finishes (DirectoryClient.addSyncHook). Safe for
// concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The repair part's name.
const directoryRepairPart = "repair"

// What one repair pass did.
type DirectoryRepairPass struct {
	// This sidecar's card was put again over a version no rule takes.
	Card *DirectoryCardWritten
	// The repos whose file was put again from folded state.
	RepoFiles []Id
	// The repos whose file was removed once the repo was deleted.
	RemovedRepoFiles []Id
}

// Makes the repair run after each sync the loop finishes, once. The hook is added outside the part's making, which
// holds the client's stateLock.
func (self *DirectoryClient) repairs() {
	made := false
	self.part(directoryRepairPart, func() any {
		made = true
		return true
	})
	if !made {
		return
	}
	self.addSyncHook(func(ctx context.Context) {
		if _, err := self.Repair(ctx); err != nil {
			self.log.Infof("[directory]a repair stopped: %s", err)
		}
	})
}

// One repair pass over what this copy last judged: see the file's header. A read_only client, or one with no signer
// bound, repairs nothing.
func (self *DirectoryClient) Repair(ctx context.Context) (*DirectoryRepairPass, error) {
	pass := &DirectoryRepairPass{}
	if self.readOnly || self.sign == nil || self.networkId == (Id{}) {
		return pass, nil
	}
	auth := self.auth()
	if _, ok := auth.Directory(); !ok {
		return pass, nil
	}
	files := self.files()
	var errs []error
	if card, err := self.repairCard(ctx, files); err != nil {
		errs = append(errs, err)
	} else {
		pass.Card = card
	}
	nowMillis := self.clock.Now().UnixMilli()
	items := self.currentFold().View(auth, nowMillis)
	for _, repo := range auth.Repos() {
		path := DirectoryRepoPath(repo.RepoId)
		accepted := files.acceptedAt(path)
		switch {
		case !repo.Live:
			if accepted == nil || accepted.file.Removed || self.cardPathVersion(path) == 0 {
				continue
			}
			if accepted.repo == nil || !self.mayRemoveRepoFile(auth, accepted) {
				continue
			}
			if err := self.removeRepoFile(ctx, repo.RepoId); err != nil && !directoryPathConflict(err) {
				errs = append(errs, err)
				continue
			}
			pass.RemovedRepoFiles = append(pass.RemovedRepoFiles, repo.RepoId)
		case files.breached(path):
			if directoryRepoFileIgnored(repo.Kind) || self.holdsRepoRight(auth, repo.RepoId) != nil {
				continue
			}
			item := directoryStandingRepoItem(items, repo.RepoId)
			if item == nil {
				continue
			}
			rewritten := proto.Clone(item.Announcement).(*protocol.Announcement)
			rewritten.Who = self.repoWho(auth)
			if _, err := self.WriteRepoFile(ctx, rewritten); err != nil && !directoryPathConflict(err) {
				errs = append(errs, err)
				continue
			}
			pass.RepoFiles = append(pass.RepoFiles, repo.RepoId)
		}
	}
	return pass, errors.Join(errs...)
}

// The card this device put last, again at a higher seq, when its path's newest version is one this copy refused;
// nil when nothing needed it.
func (self *DirectoryClient) repairCard(ctx context.Context, files *directoryFiles) (*DirectoryCardWritten, error) {
	path := DirectoryCardPath(self.sidecarId)
	if !files.breached(path) {
		return nil, nil
	}
	writer := self.cardWriter()
	writer.writeLock.Lock()
	defer writer.writeLock.Unlock()
	written, err := self.readCardWritten()
	if err != nil {
		return nil, err
	}
	if written.Content == nil {
		// this device put no card: nothing of its own to reproduce
		return nil, nil
	}
	settings := self.cardSettings()
	stored, err := DirectoryDecodeCard(written.Content, settings)
	if err != nil {
		return nil, fmt.Errorf("%w: the card written", ErrDirectoryStoreCorrupt)
	}
	items, err := self.cardItems(stored.Card.GetItems(), settings, self.clock.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	return self.putCard(ctx, items, settings)
}

// Who a repo file this device writes names: this sidecar, and its member or sponsor.
func (self *DirectoryClient) repoWho(auth DirectoryAuthView) *protocol.AnnounceWho {
	who := &protocol.AnnounceWho{SidecarId: self.sidecarId.Bytes()}
	if memberId, ok := DirectoryWhoMember(auth, self.sidecarId); ok {
		who.MemberId = memberId.Bytes()
	}
	return who
}

// The item that stands for repoId in items, private markers included; nil for none.
func directoryStandingRepoItem(items []*DirectoryItem, repoId Id) *DirectoryItem {
	index := slices.IndexFunc(items, func(item *DirectoryItem) bool {
		return item.Key.Kind == DirectoryAnnouncementKindRepo && recordIdOf(item.Announcement.GetWhere().GetRepoId()) == repoId
	})
	if index < 0 {
		return nil
	}
	return items[index]
}

// Whether this device removes a deleted repo's file: it signed the standing version, or it is a directory admin.
func (self *DirectoryClient) mayRemoveRepoFile(auth DirectoryAuthView, accepted *directoryAcceptedFile) bool {
	if recordIdOf(accepted.repo.Signed.GetSignerId()) == self.sidecarId {
		return true
	}
	admins, err := auth.DirectoryAdmins(auth.Pin())
	return err == nil && slices.Contains(admins, self.sidecarId)
}
