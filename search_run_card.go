//go:build !ios_extension

// Run cards (§16.10's run card and group rows; §11.14's version row; RECORD.md 7.4; DESIGN-DETAILS 15.2.8 to 15.2.10
// and 15.7's note; QD-779, QD-780, QD-783; SEARCH-M10-28): the derived document of one run in one stream of a vault or
// a team record, which a rebuild reproduces and an erasure folds again without the erased entry.
//
//	identity  card (R, r): doc kind derived, named run/ || run_id (the id in lowercase hex, as every id in a name is),
//	          chunk 0, under stream R's ref_id; one card a run a stream, so two ingesters' streams holding one run
//	          give two cards, which §16.10's group row joins by field 10 (QD-780)
//	fold      fold(R, r, p, E): the source entries of r that R holds at p, less those erased at E (15.2.2), in the
//	          order (seq in their writer's chain, then entry_id bytes); "first" and "newest" read in it; a fold with no
//	          entry is no document, so a run whose every source entry is erased has no card (QD-783)
//	sources   a vault: context, tool_call, change, transcript; a team record: context, change, approval, publish,
//	          route, reach, coverage (RECORD.md 7.4's sources row)
//	c         c(R, r, p): the highest entry version among r's source entries R holds at p, erased or not: the stream
//	          version at which the run last changed in R
//	version   E * 2^b + c, b IndexFormatSettings.CardVersionBitCount (32), E the index_epoch the push names; an epoch
//	          or a c at or past 2^b writes no card (QD-779, QD-783)
//	blocked   a source entry this device cannot open, which an ERASE took while its erasure has no CUT below E: no
//	          card, and the build's pin on R stops below the run's first source entry (15.2.2, 15.2.9)
//
// The mapping is RECORD.md 7.4's: a team record's card holds no title, prompt, branch, tool or path, which only the
// vault holds (FS-80). Two of the vault's rows read kinds that are not its sources, the newest claim's fields 13 and 14
// and the newest coverage's time as the row's expires, which no fold of the sources can give, so a vault's card leaves
// them empty until question search-m10-28-vault-card-sources is answered; and the run's user prompts, which only the
// harness's transcript lines hold in a harness's own format, wait on question search-m10-28-transcript-prompts, so a
// vault's card has no prompt text and takes its title from its newest context alone. Card text and titles are this
// device's plaintext and go into no log or error (I-13). Package-level functions are safe for concurrent use.

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

// The kinds a card of a log of logKind folds (RECORD.md 7.4's sources row), nil for a log with no cards.
func indexRunCardSources(logKind protocol.RepoKind) []RecordKind {
	switch logKind {
	case protocol.RepoKind_REPO_KIND_VAULT:
		return []RecordKind{RecordKindContext, RecordKindToolCall, RecordKindChange, RecordKindTranscript}
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
	var newestCoverage *indexRecordEntry
	lastEventMillis := int64(0)
	for _, entry := range folded {
		document.Tainted = document.Tainted || entry.header.GetTainted()
		if entry.kind() == RecordKindCoverage {
			newestCoverage = entry
		} else {
			lastEventMillis = max(lastEventMillis, entry.header.GetTimeMillis())
		}
		switch entry.kind() {
		case RecordKindToolCall:
			if body, ok := indexRunCardBody(entry, &protocol.ToolCallBody{}); ok {
				if body.GetToolName() != "" {
					toolCounts[body.GetToolName()] += 1
				}
				for _, path := range body.GetPaths() {
					paths[path] = path != ""
				}
			}
		case RecordKindChange:
			if body, ok := indexRunCardBody(entry, &protocol.ChangeBody{}); ok {
				for _, commit := range body.GetCommits() {
					commits = appendOnce(commits, commit)
				}
				for _, changed := range body.GetPaths() {
					paths[changed.GetPath()] = changed.GetPath() != ""
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
		}
	}
	document.StartedSeconds = uint64(max(folded[0].header.GetTimeMillis(), 0) / 1000)
	if !vault && newestCoverage != nil && lastEventMillis < newestCoverage.header.GetTimeMillis() {
		// ended: the newest coverage is newer than the run's last event (RECORD.md 4.3's re-open row)
		document.ExpiresSeconds = uint64(newestCoverage.header.GetTimeMillis() / 1000)
	}

	lines := []string{indexRecordPair(contextBody.GetHarness(), contextBody.GetHarnessVersion()), contextBody.GetModel()}
	if vault {
		document.Fields[indexFieldTitle] = []byte(indexCutUtf8(indexRowText(contextBody.GetTitle()), settings.TitleByteCount))
		tools := indexRunCardCounts(toolCounts)
		document.Fields[indexFieldFirstRegistered+6] = []byte(strings.Join(tools[:min(len(tools), settings.CardToolCount)], " "))
		lines = append(lines, indexRecordPair(contextBody.GetProject(), contextBody.GetBranch()))
		lines = append(lines, tools...)
		lines = append(lines, commits...)
		touched := []string{}
		for path, kept := range paths {
			if kept {
				touched = append(touched, path)
			}
		}
		slices.SortFunc(touched, func(a string, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
		lines = append(lines, touched[:min(len(touched), settings.CardPathCount)]...)
	} else {
		lines = append(lines, contextBody.GetProject())
		lines = append(lines, commits...)
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
