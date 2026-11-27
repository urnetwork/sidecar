//go:build !ios_extension && !sidecar_http

// `ur harness export` (DESIGN-COMPUTE §24.6, §24.9; CTXH-M11-05, D-CTXH-11): a run as Pi's v3 session JSONL, every node
// and part, which Pi and PiG open. It counts as `ur record export --run <id> --bodies` in format 5, pi, so RECORD.md
// section 9's rows bind it:
//
//	confirm   a person's command confirmed on /dev/tty or in an app's UI, before anything is read; the caller taints
//	          the runs of a harness among its ancestors first (Sidecar.TaintAncestorRuns)
//	record    the disclosure entry, act export, format pi, naming the run and its kinds 54 and 55 with bodies, filed and
//	          landed before the first line is returned; a receipt-only reader's read receipts instead
//	file      the session header (version 3, the run's id as the session's, its first node's time, and the run it
//	          continues as parentSession), then each node of the run this device holds, in its writer's order, as its
//	          Pi entry: its parts put back from its blobs, a part not held as its marker (§24.10's after row), a
//	          same_as node as the item it names. A node whose body this device does not hold (erased, withheld,
//	          dropped) is left out and counted
//	pii       every email address and phone number in the lines is hashed under record.redact.pii
//	          (session_export_pii.go), where the vault keeps them as written (Q-CTXH-15)
//
// The run's bodies are fetched only now, as it is exported (SessionReader.Open), each held to its header's commitment.
// The lines are a copy beyond recall: a later erasure does not reach them.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"
)

// An export of a run in the pi format (the file header).
func init() {
	recordExportPi = sessionExportPi
}

// What `ur harness export` asks.
type SessionPiExportArgs struct {
	RunId Id
	// The person confirmed the command on /dev/tty or in an app's UI.
	Confirmed bool
	// The network's capture redactor, whose record.redact.pii the lines are hashed under; nil hashes under a key of the
	// export's own.
	Redactor *Redactor
}

// A run exported, its record landed.
type SessionPiExported struct {
	// The session header, then one line a node, none ending in a newline.
	Lines [][]byte
	// The nodes written, and those left out, their bodies not held here.
	NodeCount   int
	UnheldCount int
	// Parts written as their markers, not held here.
	PrunedPartCount int
	// The addresses and numbers hashed.
	PiiCount int
	// The record is read receipts alone: this device files no disclosure entry in the vault.
	ReceiptsOnly bool
}

// Exports runs as Pi sessions.
type SessionPiExport struct {
	record *SidecarRecord
}

// The record's Pi exporter.
func (self *SidecarRecord) SessionPiExport() *SessionPiExport {
	return &SessionPiExport{record: self}
}

// RecordExport's pi format: args' run, in its author's vault, as this exporter writes it.
func sessionExportPi(ctx context.Context, export *RecordExport, args *RecordExportArgs) (*RecordExported, error) {
	vaultId, err := export.record.SessionReader().VaultId()
	if err != nil {
		return nil, err
	}
	if args.LogId != vaultId {
		return nil, fmt.Errorf("%w: a pi export is of a run in its author's vault", ErrRecordExportArgs)
	}
	exported, err := export.record.SessionPiExport().Export(ctx, &SessionPiExportArgs{RunId: *args.RunId, Confirmed: args.Confirmed, Redactor: args.Redactor})
	if err != nil {
		return nil, err
	}
	return &RecordExported{Lines: exported.Lines, ReceiptsOnly: exported.ReceiptsOnly}, nil
}

// Exports args' run: see the file header. Nothing is read before the confirmation is checked, and no line is returned
// before the export's record lands.
func (self *SessionPiExport) Export(ctx context.Context, args *SessionPiExportArgs) (*SessionPiExported, error) {
	if args == nil || args.RunId == (Id{}) {
		return nil, fmt.Errorf("%w: no run", ErrRecordExportArgs)
	}
	if !args.Confirmed {
		return nil, ErrRecordExportUnconfirmed
	}
	redactor := args.Redactor
	if redactor == nil {
		var err error
		if redactor, err = (&RecordExportArgs{}).piiRedactor(); err != nil {
			return nil, err
		}
	}
	reader := self.record.SessionReader()
	vaultId, err := reader.VaultId()
	if err != nil {
		return nil, err
	}
	view, err := reader.Open(ctx, vaultId, args.RunId)
	if err != nil {
		return nil, err
	}
	runId := args.RunId
	recordArgs := &RecordExportArgs{
		LogId: vaultId, RunId: &runId, Kinds: []RecordKind{RecordKindSessionEntry, RecordKindSessionBlob}, Bodies: true,
		Format: RecordExportFormatPi, Confirmed: true,
	}
	taken := []*RecordReadEntry{}
	for _, entry := range self.record.reader.Entries(vaultId) {
		if recordArgs.takes(entry) {
			taken = append(taken, entry)
		}
	}
	// the export's record lands before any line exists
	receiptsOnly, err := self.record.export.recordExport(ctx, recordArgs, taken)
	if err != nil {
		return nil, err
	}
	exported := &SessionPiExported{ReceiptsOnly: receiptsOnly}
	nodes := slices.Clone(view.Nodes)
	slices.SortStableFunc(nodes, func(a *SessionReadNode, b *SessionReadNode) int {
		switch {
		case a.WriterSidecarId != b.WriterSidecarId:
			return a.WriterSidecarId.Cmp(b.WriterSidecarId)
		case a.Seq < b.Seq:
			return -1
		case b.Seq < a.Seq:
			return 1
		}
		return 0
	})
	lines := [][]byte{}
	var firstMillis int64
	parentSession := ""
	for _, node := range nodes {
		if node.Body == nil || node.Invalid != nil {
			exported.UnheldCount += 1
			continue
		}
		itemNode, ok := view.itemOf(node)
		if !ok {
			exported.UnheldCount += 1
			continue
		}
		partBytes := map[string][]byte{}
		for _, part := range itemNode.Body.GetParts() {
			if held, ok := itemNode.PartBytes[part.GetPointer()]; ok {
				partBytes[part.GetPointer()] = held
				continue
			}
			partBytes[part.GetPointer()] = []byte(SessionPartMarker(part))
			if !part.GetOmitted() {
				exported.PrunedPartCount += 1
			}
		}
		item, err := SessionItemRestore(itemNode.Body.GetItem(), itemNode.Body.GetParts(), partBytes)
		if err != nil {
			return nil, err
		}
		hashed, count, err := SessionHashPiiJson(redactor, item)
		if err != nil {
			return nil, err
		}
		exported.PiiCount += count
		lines = append(lines, bytes.TrimSpace(hashed))
		exported.NodeCount += 1
		if firstMillis == 0 || node.TimeMillis < firstMillis {
			firstMillis = node.TimeMillis
		}
		if parentRunId := node.Body.GetParentRunId(); len(parentRunId) == len(Id{}) && parentSession == "" {
			parentSession = recordIdOf(parentRunId).String()
		}
	}
	header, err := NewHarnessPiSessionHeader(args.RunId.String(), time.UnixMilli(firstMillis), "", parentSession).Json()
	if err != nil {
		return nil, err
	}
	exported.Lines = append([][]byte{header}, lines...)
	return exported, nil
}
