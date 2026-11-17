//go:build !ios_extension

// Run cards (§16.10's run card and group rows; §11.14's version row; RECORD.md 7.3 and 7.4; DESIGN-DETAILS 15.2.8 to
// 15.2.10 and 15.7's note; QD-779, QD-780, QD-783, QD-899; SEARCH-M10-28): the derived document of one run in one
// stream of a vault or a team record, which a rebuild reproduces and an erasure folds again without the erased entry.
//
//	identity  card (R, r): doc kind derived, named run/ || run_id (the id in lowercase hex, as every id in a name is),
//	          chunk 0, under stream R's ref_id; one card a run a stream, so two ingesters' streams holding one run
//	          give two cards, which §16.10's group row joins by field 10 (QD-780)
//	fold      fold(R, r, p, E): the source entries of r that R holds at p, less those erased at E (15.2.2), in the
//	          order (seq in their writer's chain, then entry_id bytes); "first" and "newest" read in it; a fold with no
//	          entry is no document, so a run whose every source entry is erased has no card (QD-783)
//	sources   a vault: context, tool_call, change, transcript, coverage, and claim and handoff; a team record: context,
//	          change, approval, publish, route, reach, coverage (RECORD.md 7.4's sources row as QD-899 amends it). A
//	          vault holds claims and handoffs only in a personal network (RECORD.md 6.3), so folding whatever it holds
//	          of them is "in personal mode" with no input but the stream, as its entry documents read them
//	c         c(R, r, p): the highest entry version among r's source entries R holds at p, erased or not: the stream
//	          version at which the run last changed in R, which a claim, a handoff and the run's coverage move too
//	version   E * 2^b + c, b IndexFormatSettings.CardVersionBitCount (32), E the index_epoch the push names; an epoch
//	          or a c at or past 2^b writes no card (QD-779, QD-783)
//	blocked   a source entry this device cannot open, which an ERASE took while its erasure has no CUT below E: no
//	          card, and the build's pin on R stops below the run's first source entry (15.2.2, 15.2.9)
//	claim     a vault card's fields 13 and 14 (QD-899): the newest claim the fold opens, a claim's id being its opening
//	          entry's entry_id; 13 the expires of its opener's newest claim entry of it, 14 handed_off where a handoff
//	          in the fold names it, else released where a claim entry in the fold releases it, else active. That is the
//	          claim's own state as of the fold, never expired, which a reader computes from 13
//	ended     the row's expires, on a vault's card and a team record's alike: the newest coverage's time while it is
//	          newer than the run's last other entry (RECORD.md 4.3's re-open row), else 0, which §16.10's group row
//	          reads for active
//
// The mapping is RECORD.md 7.4's: a team record's card holds no title, prompt, branch, tool or path, which only the
// vault holds (FS-80), and counts each action kind asked for approval, approval_decision staying outside its sources
// (QD-899). The run's user prompts wait on QD-900's ContextBody prompts (question search-m10-28-transcript-prompts),
// so a vault's card has no prompt text and takes its title from its newest context alone. Card text and titles are
// this device's plaintext and go into no log or error (I-13). Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A stream version or an index epoch at or past 2^CardVersionBitCount: no card is written, and the stream's pin
	// stops below it (15.2.8).
	errIndexCardVersionSpace = errors.New("index card version past its bits")
	// The card's builder cannot open a source entry that an ERASE took while its erasure has no CUT below the push's
	// epoch: no card, and the stream's pin stops below the run (15.2.2's blocked).
	errIndexCardBlocked = errors.New("index card blocked")
)

// A run card's registered name's prefix (§11.14's key row).
const indexRunCardPrefix = "run/"

// run/ || run_id, the id in lowercase hex.
func indexRunCardName(runId Id) []byte {
	return []byte(indexRunCardPrefix + hex.EncodeToString(runId[:]))
}

// Whether a log of logKind holds run cards: a vault and a team record (RECORD.md 7.1's documents row).
func indexRunCardLog(logKind protocol.RepoKind) bool {
	return logKind == protocol.RepoKind_REPO_KIND_VAULT || logKind == protocol.RepoKind_REPO_KIND_TEAM_RECORD
}

// The kinds a card of a log of logKind folds (RECORD.md 7.4's sources row as QD-899 amends it), nil for a log with no
// cards. The build, the backfill, an ERASE's again units and the keys it masks all read them here.
func indexRunCardSources(logKind protocol.RepoKind) []RecordKind {
	switch logKind {
	case protocol.RepoKind_REPO_KIND_VAULT:
		return []RecordKind{
			RecordKindContext, RecordKindToolCall, RecordKindChange, RecordKindTranscript, RecordKindCoverage, RecordKindClaim,
			RecordKindHandoff,
		}
	case protocol.RepoKind_REPO_KIND_TEAM_RECORD:
		return []RecordKind{
			RecordKindContext, RecordKindChange, RecordKindApproval, RecordKindPublish, RecordKindRoute, RecordKindReach,
			RecordKindCoverage,
		}
	}
	return nil
}

// A card's version: epoch * 2^bits + c, errIndexCardVersionSpace where either passes its bits.
func indexRunCardVersion(epoch uint64, c uint64, bits int) (uint64, error) {
	if bits <= 0 || 64 <= bits {
		return 0, errIndexCardVersionSpace
	}
	space := uint64(1) << bits
	if space <= c || uint64(1)<<(64-bits) <= epoch {
		return 0, errIndexCardVersionSpace
	}
	return epoch<<bits | c, nil
}

// The card of runId in stream at refVersion, folded at epoch with erasedAtEpoch the build's erasure test (15.7's
// note's searchRunCard), and c beside it. Nil document, no error, for a run with no source entry or an empty fold;
// errIndexCardBlocked for a blocked card; errIndexCardVersionSpace past the version's bits.
func searchRunCard(ctx context.Context, stream indexRecordStream, runId Id, refVersion uint64, epoch uint64, erasedAtEpoch func(entry *indexRecordEntry) bool, settings *IndexRecordSettings, format *IndexFormatSettings) (*IndexDocument, uint64, error) {
	entries, err := stream.Entries(ctx, refVersion)
	if err != nil {
		return nil, 0, err
	}
	if erasedAtEpoch == nil {
		erasedAtEpoch = func(entry *indexRecordEntry) bool { return false }
	}
	return searchRunCardOf(&indexRunCardArgs{
		logKind: stream.LogKind(), entries: entries, runId: runId, epoch: epoch, erasedAtEpoch: erasedAtEpoch,
		settings: settings, format: format,
	})
}

// What one card is folded from.
type indexRunCardArgs struct {
	logKind protocol.RepoKind
	// Every entry R holds at the pin, any run, any kind.
	entries       []*indexRecordEntry
	runId         Id
	epoch         uint64
	erasedAtEpoch func(entry *indexRecordEntry) bool
	settings      *IndexRecordSettings
	format        *IndexFormatSettings
}

// The card of args.runId among args.entries, and c: see searchRunCard.
func searchRunCardOf(args *indexRunCardArgs) (*IndexDocument, uint64, error) {
	sources := indexRunCardSources(args.logKind)
	if sources == nil {
		return nil, 0, nil
	}
	c := uint64(0)
	folded := []*indexRecordEntry{}
	foldedIds := map[Id]bool{}
	for _, entry := range args.entries {
		runId, ok := entry.runId()
		if !ok || runId != args.runId || !slices.Contains(sources, entry.kind()) {
			continue
		}
		c = max(c, entry.version)
		if args.erasedAtEpoch(entry) || foldedIds[entry.entryId] {
			continue
		}
		foldedIds[entry.entryId] = true
		folded = append(folded, entry)
	}
	if len(folded) == 0 {
		return nil, c, nil
	}
	for _, entry := range folded {
		if entry.keyGone {
			return nil, c, errIndexCardBlocked
		}
	}
	version, err := indexRunCardVersion(args.epoch, c, args.format.CardVersionBitCount)
	if err != nil {
		return nil, c, err
	}
	slices.SortFunc(folded, indexRecordFoldCompare)
	document := indexRunCardMap(args, folded)
	document.Version = version
	if err := indexRecordFieldRegistry().check(document); err != nil {
		return nil, c, err
	}
	return document, c, nil
}

// One folded entry's body, parsed as its kind; nil where it has none or does not parse, the same on every device.
func indexRunCardBody[T proto.Message](entry *indexRecordEntry, body T) (T, bool) {
	var none T
	if entry.body == nil || entry.unreadable || proto.Unmarshal(entry.body, body) != nil {
		return none, false
	}
	return body, true
}

// RECORD.md 7.4's mapping of a fold, in fold order, to the card's row and text.
func indexRunCardMap(args *indexRunCardArgs, folded []*indexRecordEntry) *IndexDocument {
	settings := args.settings
	vault := args.logKind == protocol.RepoKind_REPO_KIND_VAULT
	document := &IndexDocument{Kind: IndexDocDerived, Name: indexRunCardName(args.runId)}
	// the newest context folded gives fields 7-11 and the text's first lines
	var newestContext *indexRecordEntry
	contextBody := &protocol.ContextBody{}
	for _, entry := range folded {
		if entry.kind() == RecordKindContext {
			newestContext = entry
		}
	}
	if newestContext != nil {
		if body, ok := indexRunCardBody(newestContext, &protocol.ContextBody{}); ok {
			contextBody = body
		}
		document.Fields[indexFieldFirstRegistered+1] = []byte(indexRecordHex(newestContext.header.GetWriterSidecarId()))
		document.Fields[indexFieldFirstRegistered+2] = []byte(indexRecordHex(newestContext.header.GetAgentId()))
		document.Fields[indexFieldFirstRegistered+3] = []byte(contextBody.GetAgentLabel())
		document.Fields[indexFieldFirstRegistered+5] = []byte(indexRecordSessionIds(contextBody, settings))
	}
	document.Fields[indexFieldFirstRegistered] = []byte(RecordKindRun.String())
	document.Fields[indexFieldFirstRegistered+4] = []byte(hex.EncodeToString(args.runId[:]))

	toolCounts := map[string]int{}
	commits := []string{}
	paths := map[string]bool{}
	actionCounts := map[string]int{}
	hosts := []string{}
	targets := []string{}
	gaps := []string{}
	appendOnce := func(values []string, value string) []string {
		if value == "" || slices.Contains(values, value) {
			return values
		}
		return append(values, value)
	}
	// a claim:<id hex> target's claim id (RECORD.md 6.4's targets row)
	claimTargetId := func(target string) (Id, bool) {
		form, value := recordTargetForm(target)
		if form != RecordTargetClaim {
			return Id{}, false
		}
		return recordTargetId(value)
	}
	// the fold's claim entries in fold order, each with the claim it opens or names (RECORD.md 7.3's fold): a
	// restatement's claim_id, else a release's one claim: target, else the entry's own entry_id, opening a claim
	type runCardClaimEntry struct {
		entry   *indexRecordEntry
		body    *protocol.CoordinationBody
		claimId Id
		opening bool
	}
	claimEntries := []*runCardClaimEntry{}
	handedOffClaimIds := map[Id]bool{}
	var newestCoverage *indexRecordEntry
	lastEventMillis := int64(0)
	for _, entry := range folded {
		document.Tainted = document.Tainted || entry.header.GetTainted()
		if entry.kind() == RecordKindCoverage {
			newestCoverage = entry
		} else {
			// the run's last event: any folded entry but a coverage one, a claim or handoff after the run's end
			// re-opening it as any later event does
			lastEventMillis = max(lastEventMillis, entry.header.GetTimeMillis())
		}
		switch entry.kind() {
		case RecordKindToolCall:
			if body, ok := indexRunCardBody(entry, &protocol.ToolCallBody{}); ok {
				if body.GetToolName() != "" {
					toolCounts[body.GetToolName()] += 1
				}
				for _, path := range body.GetPaths() {
					if path != "" {
						paths[path] = true
					}
				}
			}
		case RecordKindChange:
			if body, ok := indexRunCardBody(entry, &protocol.ChangeBody{}); ok {
				for _, commit := range body.GetCommits() {
					commits = appendOnce(commits, commit)
				}
				for _, changed := range body.GetPaths() {
					if changed.GetPath() != "" {
						paths[changed.GetPath()] = true
					}
				}
			}
		case RecordKindApproval:
			if body, ok := indexRunCardBody(entry, &protocol.ApprovalRequest{}); ok {
				action := &protocol.CanonicalAction{}
				if proto.Unmarshal(body.GetCanonicalAction(), action) == nil {
					actionCounts[indexRecordActionKind(action.GetKind())] += 1
				}
			}
		case RecordKindPublish:
			if body, ok := indexRunCardBody(entry, &protocol.PublishBody{}); ok && body.GetEvent() == 1 {
				hosts = appendOnce(hosts, body.GetHost())
			}
		case RecordKindRoute:
			if body, ok := indexRunCardBody(entry, &protocol.RouteBody{}); ok && body.GetEvent() == 1 {
				if len(body.GetTargetSidecarId()) != 0 {
					targets = appendOnce(targets, indexRecordHex(body.GetTargetSidecarId())+":"+strconv.FormatUint(uint64(body.GetTargetPort()), 10))
				}
				for _, cidr := range body.GetCidrs() {
					targets = appendOnce(targets, cidr)
				}
			}
		case RecordKindCoverage:
			if body, ok := indexRunCardBody(entry, &protocol.Coverage{}); ok {
				for _, gap := range body.GetGaps() {
					code, _, _ := strings.Cut(gap, ":")
					gaps = appendOnce(gaps, code)
				}
			}
		case RecordKindClaim:
			if body, ok := indexRunCardBody(entry, &protocol.CoordinationBody{}); ok {
				claim := &runCardClaimEntry{entry: entry, body: body, claimId: entry.entryId, opening: true}
				if claimId := body.GetClaimId(); len(claimId) != 0 {
					// a claim_id of another length names no claim; the reader's caps refuse it before here
					claim.claimId, claim.opening = Id{}, false
					if len(claimId) == len(Id{}) {
						claim.claimId = Id(claimId)
					}
				} else {
					for _, target := range body.GetTargets() {
						if claimId, ok := claimTargetId(target); ok {
							claim.claimId, claim.opening = claimId, false
							break
						}
					}
				}
				if claim.claimId != (Id{}) {
					claimEntries = append(claimEntries, claim)
				}
			}
		case RecordKindHandoff:
			if body, ok := indexRunCardBody(entry, &protocol.CoordinationBody{}); ok {
				for _, target := range body.GetTargets() {
					if claimId, ok := claimTargetId(target); ok {
						handedOffClaimIds[claimId] = true
					}
				}
			}
		}
	}
	document.StartedSeconds = uint64(max(folded[0].header.GetTimeMillis(), 0) / 1000)
	if newestCoverage != nil && lastEventMillis < newestCoverage.header.GetTimeMillis() {
		// ended: the newest coverage is newer than the run's last other entry (RECORD.md 4.3's re-open row), a vault's
		// card and a team record's alike (QD-899)
		document.ExpiresSeconds = uint64(newestCoverage.header.GetTimeMillis() / 1000)
	}
	// fields 13 and 14, the newest claim the fold opens (QD-899); a team record holds no claim among its sources
	var newestClaim *runCardClaimEntry
	for _, claim := range claimEntries {
		if claim.opening {
			newestClaim = claim
		}
	}
	if vault && newestClaim != nil {
		opener := newestClaim.entry.header.GetWriterSidecarId()
		expiresMillis, released := int64(0), false
		for _, claim := range claimEntries {
			if claim.claimId != newestClaim.claimId {
				continue
			}
			if bytes.Equal(claim.entry.header.GetWriterSidecarId(), opener) {
				// the opener's newest entry of the claim, by seq, gives its expires
				expiresMillis = claim.body.GetExpiresMillis()
			}
			// a release from any writer, never undone
			released = released || claim.body.GetClaimState() == recordClaimStateReleased
		}
		state := indexRecordClaimStates[recordClaimStateActive]
		switch {
		case handedOffClaimIds[newestClaim.claimId]:
			state = searchStateHandedOff
		case released:
			state = indexRecordClaimStates[recordClaimStateReleased]
		}
		if expiresMillis != 0 {
			document.Fields[indexFieldFirstRegistered+7] = []byte(indexRecordTime(expiresMillis))
		}
		document.Fields[indexFieldFirstRegistered+8] = []byte(state)
	}

	lines := []string{indexRecordPair(contextBody.GetHarness(), contextBody.GetHarnessVersion()), contextBody.GetModel()}
	if vault {
		document.Fields[indexFieldTitle] = []byte(indexCutUtf8(indexRowText(contextBody.GetTitle()), settings.TitleByteCount))
		tools := indexRunCardCounts(toolCounts)
		document.Fields[indexFieldFirstRegistered+6] = []byte(strings.Join(tools[:min(len(tools), settings.CardToolCount)], " "))
		lines = append(lines, indexRecordPair(contextBody.GetProject(), contextBody.GetBranch()))
		lines = append(lines, tools...)
		lines = append(lines, commits...)
		touched := make([]string, 0, len(paths))
		for path := range paths {
			touched = append(touched, path)
		}
		slices.SortFunc(touched, func(a string, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
		lines = append(lines, touched[:min(len(touched), settings.CardPathCount)]...)
	} else {
		lines = append(lines, contextBody.GetProject())
		lines = append(lines, commits...)
		// each action kind asked for approval: the approval requests, whatever was decided (QD-899)
		lines = append(lines, indexRunCardCounts(actionCounts)...)
		lines = append(lines, hosts...)
		lines = append(lines, targets...)
		lines = append(lines, gaps...)
	}
	text := indexCutUtf8(indexRowText(indexRecordLines(lines...)), settings.CardTextByteCount)
	document.Fields[indexFieldBody] = []byte(text)
	document.ByteCount = uint64(len(text))
	return document
}

// name:count for each name, by count, the most first, then by name.
func indexRunCardCounts(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a string, b string) int {
		if counts[a] != counts[b] {
			return counts[b] - counts[a]
		}
		return strings.Compare(a, b)
	})
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, name+":"+strconv.Itoa(counts[name]))
	}
	return values
}
