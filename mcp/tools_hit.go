//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.10's open row (MCP-M10-02; R-MCP-14, D-MCP-21, D-MCP-25, I-9, FS-80): each search hit names the R tool that
// opens it and that tool's arguments, and a hit argument resolves through the session's own cursors
// (McpSession.ResolveHit), so a hit id opens only in the session whose search gave it, only while the cursor that gave
// it lives, and only as the document it named:
//
//	tools     evs_read(repo, path or hit) opens a file hit; record_query by entry, run or hit opens a record entry's
//	          copy, or a run card's run, in the hit's log; mail_read(id or hit) opens a message hit through
//	          mcpHitOfKind with IndexDocMail once MCP-M7-01 lands the tool; a directory announcement's hit names
//	          directory_list, RECORD-M6-22's, which takes no hit yet
//	stub      a withheld hit carries no path, field or name, only its hit_id, so it opens by that id alone
//	read      opening a hit is a read of what it names: the tool runs its own guard, §8's allow, read receipt and taint
//	          on the repo and path the hit resolves to, exactly as on those arguments named, so a hit never reaches a
//	          repo the tool would refuse by name (D-MCP-21), and untrusted text taints the run before it returns
//	          (D-MCP-16)
//	kind      each tool opens its own kind of document; a hit of another kind is refused, the hit's open naming the
//	          tool that opens it
//	alone     a hit stands for the arguments that name its document: a call naming both is refused
//
// The search a hit resolves through is the search tools' (McpCatalog.Install hands it to the server), so a hit opens
// only where those tools gave it. Errors are constant text, and none names the hit id or what it names.

package mcp

import (
	"errors"
	"strings"

	"github.com/urnetwork/sidecar"
)

// What a network's search opens a hit id by: *sidecar.SearchTools.
type McpSearchHits interface {
	OpenHit(session sidecar.Id, hitId string) (*sidecar.SearchHitRef, error)
}

var _ McpSearchHits = (*sidecar.SearchTools)(nil)

// The hit argument's refusals, each constant.
var (
	errMcpHitUnknown = NewMcpError(McpCodeInvalidArguments, "the hit is none a live search of this session gave: search again", false)
	errMcpHitKind    = NewMcpError(McpCodeInvalidArguments, "the hit names another kind of document: open it with the tool its open names", false)
	errMcpHitAlone   = NewMcpError(McpCodeInvalidArguments, "a hit names what it opens: send it without the arguments it stands for", false)
)

// Sets the search hit arguments resolve through: the installed search tools' (McpCatalog.Install).
func (self *McpServer) setSearchOf(searchOf mcpSearchOfFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searchOf = searchOf
}

// The search hit arguments resolve through, nil while no search tool is installed.
func (self *McpServer) hitSearchOf() mcpSearchOfFunction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.searchOf
}

// What hitId names for this session in call's network (§16.10's open row): the document a search of this session
// gave, while the cursor that gave it lives. errMcpHitUnknown for an id of another session, a forged one, one whose
// cursor ended, an expired or erased one, and for any id where no search runs. A copy.
func (self *McpSession) ResolveHit(call *McpCall, hitId string) (*sidecar.SearchHitRef, error) {
	if call == nil || call.Session != self {
		return nil, errMcpNoCall
	}
	if hitId == "" {
		return nil, errMcpHitUnknown
	}
	searchOf := self.server.hitSearchOf()
	if searchOf == nil {
		return nil, errMcpHitUnknown
	}
	search, err := searchOf(call)
	if err != nil {
		return nil, mcpSearchError(err)
	}
	if search == nil {
		return nil, errMcpHitUnknown
	}
	hits, ok := search.(McpSearchHits)
	if !ok {
		return nil, errMcpHitUnknown
	}
	ref, err := hits.OpenHit(self.SearchSessionId(), hitId)
	if err != nil {
		if errors.Is(err, sidecar.ErrSearchHitUnknown) {
			return nil, errMcpHitUnknown
		}
		return nil, mcpSearchError(err)
	}
	if ref == nil {
		return nil, errMcpHitUnknown
	}
	opened := *ref
	return &opened, nil
}

// The hit hitId names for call's session, refused unless its document is one of kinds: what an opening tool resolves
// its hit argument by. mail_read takes its hit as mcpHitOfKind(call, hit, sidecar.IndexDocMail).
func mcpHitOfKind(call *McpCall, hitId string, kinds ...sidecar.IndexDocKind) (*sidecar.SearchHitRef, error) {
	if call == nil || call.Session == nil {
		return nil, errMcpNoCall
	}
	ref, err := call.Session.ResolveHit(call, hitId)
	if err != nil {
		return nil, err
	}
	for _, kind := range kinds {
		if ref.DocKind == int(kind) {
			return ref, nil
		}
	}
	return nil, errMcpHitKind
}

// evs_read's file: its repo, path and version as named, or as its hit names them, a file's hit standing alone.
func mcpEvsReadOf(call *McpCall, in *mcpEvsReadIn) (sidecar.Id, string, uint64, error) {
	if in.Hit == "" {
		repoId, err := mcpEvsRepoId(in.Repo)
		if err != nil {
			return sidecar.Id{}, "", 0, err
		}
		path, err := mcpEvsPath(in.Path, false)
		if err != nil {
			return sidecar.Id{}, "", 0, err
		}
		return repoId, path, in.Version, nil
	}
	if in.Repo != "" || in.Path != "" || in.Version != 0 {
		return sidecar.Id{}, "", 0, errMcpHitAlone
	}
	ref, err := mcpHitOfKind(call, in.Hit, sidecar.IndexDocFile)
	if err != nil {
		return sidecar.Id{}, "", 0, err
	}
	// a hit's path is a path evs_read takes by name, or it opens nothing
	path, err := mcpEvsPath(ref.Path, false)
	if err != nil {
		return sidecar.Id{}, "", 0, errMcpHitKind
	}
	return ref.RepoId, path, ref.Version, nil
}

// What record_query reads for a hit: the hit's log by its id, and the run of a run card's hit or the copy of an entry's.
type mcpRecordHit struct {
	log   string
	runId *sidecar.Id
	copy  *sidecar.RecordQueryCopy
}

// The prefix of a run card's registered name, run/ || run_id in lowercase hex (§11.14's key row; search_run_card.go).
const mcpRecordRunCardPrefix = "run/"

// record_query's by-hit lookup (§16.10's open row): a record entry's hit reads the entry with that copy in that
// stream, and a run card's the card's run, each in the log the hit is in. A hit stands alone but for untrusted and
// cursor, which page and include what it opens; a directory announcement's hit is directory_list's.
func mcpRecordQueryHit(call *McpCall, in *mcpRecordQueryIn) (*mcpRecordHit, error) {
	if in.Log != "" || in.Run != "" || in.Agent != "" || in.Kind != "" || in.Action != "" || in.Entry != "" || in.Since != "" ||
		in.Until != "" || in.Archived {
		return nil, errMcpHitAlone
	}
	ref, err := mcpHitOfKind(call, in.Hit, sidecar.IndexDocRecord, sidecar.IndexDocDerived)
	if err != nil {
		return nil, err
	}
	hit := &mcpRecordHit{log: mcpRecordHex(ref.RepoId.Bytes())}
	if ref.DocKind == int(sidecar.IndexDocRecord) {
		hit.copy = &sidecar.RecordQueryCopy{RefId: ref.RefId, Path: ref.Path}
		return hit, nil
	}
	name, ok := strings.CutPrefix(ref.Path, mcpRecordRunCardPrefix)
	if !ok {
		// the directory's announcements, a/ || announcement_id, open by directory_list
		return nil, errMcpHitKind
	}
	runId, err := mcpRecordId(name)
	if err != nil || runId == nil {
		return nil, errMcpHitKind
	}
	hit.runId = runId
	return hit, nil
}
