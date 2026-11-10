// What List and Get answer (RECORD-M6-14): the folded current items, filtered locally with no index and no history
// (§16.11's tools row: directory_list(kind, member, repo, active_only, query) and ur directory ls filter the folded
// current state). Nothing of a filter or a query reaches evs (I-19): a view asks the loop for a sync, coalesced over
// ViewCoalesce, and answers from what the copy holds now.
//
//	query      words, each of which must appear, case folded, in some text field of the item: its title or display
//	           name, description, labels, harness, model, project, branch, topics, services' names and descriptions,
//	           claims' text and targets, and its handoff; the names of the fields that matched go in
//	           DirectoryItem.Matches, so a stub names the field a match in prose came from and not its text
//	           (RECORD-M6-22)
//	member     an item whose who, in the reader's state, is that member: its signer's, or a sponsored signer's sponsor
//	repo       a run in that repo, or that repo's own item
//	active     shown active now: no stale, ended or handed-off item
//	private    private markers only when asked: they name no repo, only that one is private and whether it takes
//	           requests by its id
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// No current item has the id.
	ErrDirectoryItemNone = errors.New("directory item not found")
	// More than one writer's run or worker item uses the id (id_reuse): name the writer.
	ErrDirectoryItemAmbiguous = errors.New("directory item id used by more than one writer")
)

// What List keeps of the current items: each set field narrows, and the zero filter keeps every item but private
// markers.
type DirectoryFilter struct {
	// 0 for every kind.
	Kind DirectoryAnnouncementKind
	// The item's member in the reader's state: its signer's, or a sponsored signer's sponsor.
	MemberId *Id
	// A run in this repo, or this repo's own item.
	RepoId *Id
	// Only items shown active now.
	ActiveOnly bool
	// Words each of which must appear in some text field of the item, case folded; empty for none.
	Query string
	// Private markers too.
	IncludePrivate bool
}

// One text field of an item, by the name a stub gives it.
type directoryItemText struct {
	field string
	text  string
}

// The item's text fields, by name, that a query reads.
func directoryItemTexts(item *protocol.Announcement) []directoryItemText {
	who := item.GetWho()
	what := item.GetWhat()
	where := item.GetWhere()
	texts := []directoryItemText{
		{field: "title", text: what.GetTitle()},
		{field: "description", text: what.GetDescription()},
		{field: "member_label", text: who.GetMemberLabel()},
		{field: "agent_label", text: who.GetAgentLabel()},
		{field: "harness", text: who.GetHarness()},
		{field: "model", text: who.GetModel()},
		{field: "project", text: where.GetProject()},
		{field: "branch", text: where.GetBranch()},
		{field: "host_label", text: where.GetHostLabel()},
		{field: "handoff.to_agent_label", text: item.GetHandoff().GetToAgentLabel()},
		{field: "handoff.note", text: item.GetHandoff().GetNote()},
	}
	for _, harness := range what.GetHarnesses() {
		texts = append(texts, directoryItemText{field: "harnesses", text: harness})
	}
	for _, agentLabel := range what.GetAgentLabels() {
		texts = append(texts, directoryItemText{field: "agent_labels", text: agentLabel})
	}
	for _, topic := range what.GetTopics() {
		texts = append(texts, directoryItemText{field: "topics", text: topic})
	}
	for _, service := range what.GetServices() {
		texts = append(texts,
			directoryItemText{field: "services.name", text: service.GetName()},
			directoryItemText{field: "services.description", text: service.GetDescription()},
		)
	}
	for _, claim := range item.GetClaims() {
		texts = append(texts, directoryItemText{field: "claims.text", text: claim.GetText()})
		for _, target := range claim.GetTargets() {
			texts = append(texts, directoryItemText{field: "claims.targets", text: target})
		}
	}
	return texts
}

// The fields of item that query's words appear in, sorted, and whether every word appears in one: case folded, each
// word anywhere in a field's text.
func directoryQueryMatches(item *protocol.Announcement, query string) ([]string, bool) {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return nil, true
	}
	texts := directoryItemTexts(item)
	matches := []string{}
	for _, word := range words {
		found := false
		for _, text := range texts {
			if text.text != "" && strings.Contains(strings.ToLower(text.text), word) {
				found = true
				if !slices.Contains(matches, text.field) {
					matches = append(matches, text.field)
				}
			}
		}
		if !found {
			return nil, false
		}
	}
	slices.Sort(matches)
	return matches, true
}

// The items filter keeps, in their order, each kept one carrying its query's matches.
func directoryFilterItems(items []*DirectoryItem, filter *DirectoryFilter) []*DirectoryItem {
	if filter == nil {
		filter = &DirectoryFilter{}
	}
	kept := []*DirectoryItem{}
	for _, item := range items {
		switch {
		case filter.Kind != 0 && item.Key.Kind != filter.Kind:
			continue
		case item.Display == DirectoryItemPrivate && !filter.IncludePrivate:
			continue
		case filter.ActiveOnly && item.Display != DirectoryItemActive:
			continue
		case filter.MemberId != nil && (item.MemberId == nil || *item.MemberId != *filter.MemberId):
			continue
		case filter.RepoId != nil && recordIdOf(item.Announcement.GetWhere().GetRepoId()) != *filter.RepoId:
			continue
		}
		matches, ok := directoryQueryMatches(item.Announcement, filter.Query)
		if !ok {
			continue
		}
		item.Matches = matches
		kept = append(kept, item)
	}
	return kept
}

// The current items filter keeps, from this copy's fold at the state now, and a sync asked for the view: active first
// within each kind, then the latest renewed. ErrDirectoryNone without a directory.
func (self *DirectoryClient) List(filter *DirectoryFilter) ([]*DirectoryItem, error) {
	auth := self.auth()
	if _, ok := auth.Directory(); !ok {
		return nil, ErrDirectoryNone
	}
	self.ViewSync()
	return directoryFilterItems(self.currentFold().View(auth, self.clock.Now().UnixMilli()), filter), nil
}

// The current item with announcementId, private markers included: a run's or worker's of writerSidecarId when it is
// set, else the one item with the id, ErrDirectoryItemAmbiguous when two writers use it (id_reuse) and
// ErrDirectoryItemNone when none does.
func (self *DirectoryClient) Get(announcementId Id, writerSidecarId *Id) (*DirectoryItem, error) {
	items, err := self.List(&DirectoryFilter{IncludePrivate: true})
	if err != nil {
		return nil, err
	}
	return directoryGetItem(items, announcementId, writerSidecarId)
}

// The item that stands for repoId now, its private marker included; false while none does. What a run's where names
// (RECORD-M6-16): the repo's name and branch only while it holds a live, non-private item, else private.
func (self *DirectoryClient) RepoItem(repoId Id) (*DirectoryItem, bool) {
	item, err := self.Get(DirectoryRepoAnnouncementId(repoId), nil)
	if err != nil {
		return nil, false
	}
	return item, true
}

// Get's choice among items.
func directoryGetItem(items []*DirectoryItem, announcementId Id, writerSidecarId *Id) (*DirectoryItem, error) {
	found := []*DirectoryItem{}
	for _, item := range items {
		if item.Key.AnnouncementId != announcementId {
			continue
		}
		if writerSidecarId != nil && item.Key.Kind != DirectoryAnnouncementKindRepo && item.Key.WriterSidecarId != *writerSidecarId {
			continue
		}
		found = append(found, item)
	}
	switch len(found) {
	case 0:
		return nil, ErrDirectoryItemNone
	case 1:
		return found[0], nil
	}
	return nil, ErrDirectoryItemAmbiguous
}
