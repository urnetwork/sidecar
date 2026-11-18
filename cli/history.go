// ur history (§11.7's cli rows; R-EVS-26, D-MCP-32, I-13, FS-89; EVS2-M10-23): a path's history dropped, a repo's drops
// listed and a drop cancelled, through the daemon's evs client over the control path, which no MCP tool reaches (§16.6's
// refused list):
//
//	ur history drop <repo_id>:<path>... [--ref=<ref>] [--follow] [--recursive] [--now] [--dry-run] [--confirm=<path>]
//	                [--detach | --resume=<preview_id>] [--json]
//	ur history drops <repo_id> [--ref=<ref>] [--json]
//	ur history cancel <repo_id> <drop_id> [--ref=<ref>]
//
//	drop     files the mandatory dry run (EvsRepo.DropHistoryPreview), stops on a list mismatch, prints what frees and
//	         what stays, then asks on the controlling terminal for the typed path, and the word now with --now, and
//	         drops through a Confirm method (D-CORE-13), so only a control session a person answered for signs.
//	         --dry-run prints the dry run and stops; --detach files the dry run and prints its id; --resume reads a
//	         dry run filed before, walking the lineages again and filing nothing, across a daemon restart; --confirm
//	         answers the typed path for scripted use on a real terminal's behalf, where §5.8 allows a control session,
//	         and never answers the word now; --json prints the daemon's answer as JSON, which holds no key
//	drops    each drop's id, state, window's end and the paths this device can name that its lineages cover
//	cancel   a pending drop's cancel, any repo admin's, refused within 60 s of its window's end
//
// Paths are the person's own and go only between ur and its daemon on this device (I-13). The daemon method of the drop
// and of the cancel is a Confirm method, so an agent's session, which is never control, cannot call it.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur history calls.
const (
	urMethodHistoryPreview = "history.preview"
	urMethodHistoryDrop    = "history.drop"
	urMethodHistoryDrops   = "history.drops"
	urMethodHistoryCancel  = "history.cancel"
)

func init() {
	registerUrCommand(&urCommand{
		name: "history",
		usage: strings.Join([]string{
			"  ur history drop <repo_path>... [--ref=<ref>] [--follow] [--recursive] [--now] [--dry-run] [--confirm=<path>] [--detach | --resume=<preview_id>] [--json]",
			"  ur history drops <repo_id> [--ref=<ref>] [--json]",
			"  ur history cancel <repo_id> <drop_id> [--ref=<ref>]",
		}, "\n"),
		summary: "drop a path's history, keeping its head: a repo admin's act, previewed and confirmed on the terminal; list a repo's drops; cancel a pending one",
		run:     runUrHistory,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urHistoryMethods)
}

// What history.preview asks: a repo, its ref, the paths, and the dry run's options.
type urHistoryPreviewParams struct {
	RepoId    string   `json:"repo_id"`
	Ref       string   `json:"ref,omitempty"`
	Paths     []string `json:"paths"`
	Follow    bool     `json:"follow,omitempty"`
	Recursive bool     `json:"recursive,omitempty"`
	Detach    bool     `json:"detach,omitempty"`
	// the dry runs to resume, each batch's preview id in hex
	Resume []string `json:"resume,omitempty"`
}

// history.preview's answer: the dry run's ids and figures, and the lines ur prints of it.
type urHistoryPreviewReply struct {
	PreviewIds   []string `json:"preview_ids"`
	ConfirmText  string   `json:"confirm_text"`
	VersionCount uint64   `json:"version_count"`
	FreedBytes   uint64   `json:"freed_bytes"`
	SharedBytes  uint64   `json:"shared_bytes"`
	InlineBytes  uint64   `json:"inline_bytes"`
	PackedBytes  uint64   `json:"packed_bytes"`
	YoungBytes   uint64   `json:"young_bytes"`
	Lines        []string `json:"lines"`
}

// What history.drop asks: the dry run by its first id, the typed path, and now with its word.
type urHistoryDropParams struct {
	RepoId      string `json:"repo_id"`
	PreviewId   string `json:"preview_id"`
	ConfirmPath string `json:"confirm_path"`
	Now         bool   `json:"now,omitempty"`
	ConfirmNow  string `json:"confirm_now,omitempty"`
}

// What history.drops and history.cancel ask.
type urHistoryDropsParams struct {
	RepoId string `json:"repo_id"`
	Ref    string `json:"ref,omitempty"`
	DropId string `json:"drop_id,omitempty"`
}

// A drop's or a cancel's answer: lines, and for --json the drops as listed.
type urHistoryReply struct {
	Lines []string         `json:"lines"`
	Drops []*urHistoryDrop `json:"drops,omitempty"`
}

// One drop as ur history drops lists it: ids, its state, its window's end and the paths this device names.
type urHistoryDrop struct {
	DropId      string   `json:"drop_id"`
	RefId       string   `json:"ref_id"`
	Version     uint64   `json:"version"`
	State       string   `json:"state"`
	NotBeforeMs int64    `json:"not_before_ms"`
	FreedBytes  uint64   `json:"freed_bytes"`
	Paths       []string `json:"paths,omitempty"`
}

// The lines of a dry run: what it lists, what frees and what stays.
func urHistoryPreviewLines(preview *sidecar.EvsDropPreview) []string {
	lines := []string{}
	for _, lineage := range preview.Lineages {
		boundary := "its head stays"
		if lineage.DropPath.GetBoundary() == sidecar.EvsDropBoundaryRemoved {
			boundary = "removed; its removal stays"
		}
		lines = append(lines, fmt.Sprintf("%s: %d older version(s) dropped, %s", lineage.Path, lineage.DropPath.GetCount(), boundary))
	}
	lines = append(lines,
		fmt.Sprintf("frees %d bytes; %d bytes stay shared with versions that are kept, %d bytes inline until a compaction",
			preview.FreedBytes, preview.SharedBytes, preview.InlineBytes),
		fmt.Sprintf("%d bytes packed and %d bytes too young to delete yet; every statement and hash stays", preview.PackedBytes, preview.YoungBytes))
	if 1 < len(preview.Batches) {
		lines = append(lines, fmt.Sprintf("in %d DROP pushes, one command", len(preview.Batches)))
	}
	return lines
}

// The lines of a committed drop: each DROP push's id, ref version and window's end.
func urHistoryDropLines(result *sidecar.EvsDropHistoryResult) []string {
	lines := []string{}
	for _, pushed := range result.Pushes {
		lines = append(lines, fmt.Sprintf("drop %s at ref version %d, pending until %s; ur history cancel cancels it until a minute before",
			hex.EncodeToString(pushed.DropId.Bytes()), pushed.Version, pushed.NotBefore.UTC().Format("2006-01-02 15:04:05Z")))
		if !pushed.IndexRewritten {
			lines = append(lines, "  the search index's rewrite of its versions is left to the backfill")
		}
	}
	return lines
}

// The drops as ur history drops lists them, and their lines.
func urHistoryDropsOf(drops []*sidecar.EvsDrop) ([]*urHistoryDrop, []string) {
	listed := []*urHistoryDrop{}
	lines := []string{}
	for _, drop := range drops {
		status := drop.Status
		state, ok := sidecar.SidecarDropStateOf(status.GetState())
		if !ok {
			state = "unknown"
		}
		listed = append(listed, &urHistoryDrop{
			DropId: hex.EncodeToString(status.GetDropId()), RefId: hex.EncodeToString(status.GetRefId()), Version: status.GetVersion(),
			State: string(state), NotBeforeMs: status.GetNotBeforeMs(), FreedBytes: status.GetFreedBytes(), Paths: drop.Paths,
		})
		line := fmt.Sprintf("drop %s at ref version %d: %s", hex.EncodeToString(status.GetDropId()), status.GetVersion(), state)
		if state == sidecar.SidecarDropPending {
			line += ", until " + time.UnixMilli(status.GetNotBeforeMs()).UTC().Format("2006-01-02 15:04:05Z")
		}
		lines = append(lines, line)
		for _, path := range drop.Paths {
			lines = append(lines, "  "+path)
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "no drops")
	}
	return listed, lines
}

// The methods over target, when it hosts a Sidecar.
func urHistoryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	repoOf := func(repoId string) (*sidecar.EvsRepo, error) {
		_, repo, _, err := urEvsRepoOf(evs, &urEvsRepoParams{RepoId: repoId})
		return repo, err
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodHistoryPreview,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urHistoryPreviewParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				repo, err := repoOf(params.RepoId)
				if err != nil {
					return nil, err
				}
				args := &sidecar.EvsDropPreviewArgs{
					RefName: urEvsRefName(params.Ref), Paths: params.Paths, Follow: params.Follow, Recursive: params.Recursive,
					Detach: params.Detach,
				}
				for _, previewId := range params.Resume {
					previewBytes, err := hex.DecodeString(previewId)
					if err != nil || len(previewBytes) != 16 {
						return nil, fmt.Errorf("%q is no preview id", previewId)
					}
					args.ResumePreviewIds = append(args.ResumePreviewIds, previewBytes)
				}
				preview, err := repo.DropHistoryPreview(ctx, args)
				if err != nil {
					return nil, err
				}
				reply := &urHistoryPreviewReply{
					ConfirmText: sidecar.EvsDropConfirmText(preview), VersionCount: preview.VersionCount, FreedBytes: preview.FreedBytes,
					SharedBytes: preview.SharedBytes, InlineBytes: preview.InlineBytes, PackedBytes: preview.PackedBytes,
					YoungBytes: preview.YoungBytes, Lines: urHistoryPreviewLines(preview),
				}
				for _, batch := range preview.Batches {
					reply.PreviewIds = append(reply.PreviewIds, hex.EncodeToString(batch.PreviewId))
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodHistoryDrop,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urHistoryDropParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				repo, err := repoOf(params.RepoId)
				if err != nil {
					return nil, err
				}
				previewId, err := hex.DecodeString(params.PreviewId)
				if err != nil {
					return nil, fmt.Errorf("%q is no preview id", params.PreviewId)
				}
				result, err := repo.DropHistory(ctx, &sidecar.EvsDropHistoryArgs{
					PreviewId: previewId, ConfirmPath: params.ConfirmPath, Now: params.Now, ConfirmNow: params.ConfirmNow,
				})
				if err != nil {
					return nil, err
				}
				return &urHistoryReply{Lines: urHistoryDropLines(result)}, nil
			},
		},
		{
			Name: urMethodHistoryDrops,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urHistoryDropsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				repo, err := repoOf(params.RepoId)
				if err != nil {
					return nil, err
				}
				known, err := repo.KnownPaths(ctx, urEvsRefName(params.Ref))
				if err != nil {
					return nil, err
				}
				drops, err := repo.Drops(ctx, &sidecar.EvsDropsArgs{RefName: urEvsRefName(params.Ref), KnownPaths: known})
				if err != nil {
					return nil, err
				}
				listed, lines := urHistoryDropsOf(drops)
				return &urHistoryReply{Lines: lines, Drops: listed}, nil
			},
		},
		{
			Name:    urMethodHistoryCancel,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urHistoryDropsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				repo, err := repoOf(params.RepoId)
				if err != nil {
					return nil, err
				}
				dropBytes, err := hex.DecodeString(params.DropId)
				dropId, idErr := sidecar.IdFromBytes(dropBytes)
				if err != nil || idErr != nil {
					return nil, fmt.Errorf("%q is no drop id", params.DropId)
				}
				cancelled, err := repo.CancelDrop(ctx, &sidecar.EvsCancelDropArgs{RefName: urEvsRefName(params.Ref), DropId: dropId})
				if err != nil {
					return nil, err
				}
				return &urHistoryReply{Lines: []string{fmt.Sprintf("drop %s at ref version %d cancelled at ref version %d",
					params.DropId, cancelled.DropVersion, cancelled.Version)}}, nil
			},
		},
	}
}

// A repo_id:path argument split, refused when it names no repo.
func urHistoryRepoPath(argument string) (string, string, error) {
	repoId, path, found := strings.Cut(argument, ":")
	if !found || path == "" {
		return "", "", fmt.Errorf("%q is no <repo_id>:<path>", argument)
	}
	if _, err := sidecar.EvsGitRepoOf("id:" + repoId); err != nil {
		return "", "", fmt.Errorf("%q is no repo id", repoId)
	}
	return repoId, path, nil
}

// An option's one value, whether docopt gives it as a string or a list.
func urHistoryOption(options docopt.Opts, name string) string {
	switch value := options[name].(type) {
	case string:
		return value
	case []string:
		if 0 < len(value) {
			return value[0]
		}
	}
	return ""
}

// Runs the part of ur history its first word names.
func runUrHistory(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "drop"):
		return runUrHistoryDrop(ctx, cli, options)
	case urOptionBool(options, "drops"):
		reply := &urHistoryReply{}
		params := &urHistoryDropsParams{RepoId: urOptionString(options, "<repo_id>"), Ref: urHistoryOption(options, "--ref")}
		if err := cli.callDaemon(ctx, urMethodHistoryDrops, params, false, reply); err != nil {
			return err
		}
		return urHistoryPrint(cli, options, reply.Lines, reply.Drops)
	case urOptionBool(options, "cancel"):
		params := &urHistoryDropsParams{
			RepoId: urOptionString(options, "<repo_id>"), Ref: urHistoryOption(options, "--ref"), DropId: urOptionString(options, "<drop_id>"),
		}
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("cancel drop %s?", params.DropId))
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("nothing was cancelled")
		}
		reply := &urHistoryReply{}
		if err := cli.callDaemon(ctx, urMethodHistoryCancel, params, true, reply); err != nil {
			return err
		}
		return urHistoryPrint(cli, options, reply.Lines, nil)
	}
	return errors.New("ur history takes drop, drops or cancel")
}

// Prints lines, or with --json the value.
func urHistoryPrint(cli *urCli, options docopt.Opts, lines []string, value any) error {
	if urOptionBool(options, "--json") && value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		cli.printf("%s\n", encoded)
		return nil
	}
	for _, line := range lines {
		cli.printf("%s\n", line)
	}
	return nil
}

// ur history drop: see the file header.
func runUrHistoryDrop(ctx context.Context, cli *urCli, options docopt.Opts) error {
	arguments, _ := options["<repo_path>"].([]string)
	params := &urHistoryPreviewParams{
		Ref: urHistoryOption(options, "--ref"), Follow: urOptionBool(options, "--follow"), Recursive: urOptionBool(options, "--recursive"),
		Detach: urOptionBool(options, "--detach"),
	}
	for _, argument := range arguments {
		repoId, path, err := urHistoryRepoPath(argument)
		if err != nil {
			return err
		}
		if params.RepoId != "" && params.RepoId != repoId {
			return errors.New("ur history drop drops paths of one repo at a time")
		}
		params.RepoId = repoId
		params.Paths = append(params.Paths, path)
	}
	if len(params.Paths) == 0 {
		return errors.New("ur history drop takes at least one <repo_id>:<path>")
	}
	if resume := urHistoryOption(options, "--resume"); resume != "" {
		params.Resume = strings.Split(resume, ",")
	}
	preview := &urHistoryPreviewReply{}
	if err := cli.callDaemon(ctx, urMethodHistoryPreview, params, false, preview); err != nil {
		return err
	}
	if params.Detach {
		cli.printf("dry run filed: ur history drop %s --resume %s\n", strings.Join(arguments, " "), strings.Join(preview.PreviewIds, ","))
		return nil
	}
	if urOptionBool(options, "--dry-run") {
		return urHistoryPrint(cli, options, preview.Lines, preview)
	}
	for _, line := range preview.Lines {
		cli.printf("%s\n", line)
	}
	drop := &urHistoryDropParams{RepoId: params.RepoId, PreviewId: preview.PreviewIds[0], Now: urOptionBool(options, "--now")}
	drop.ConfirmPath = urHistoryOption(options, "--confirm")
	if drop.ConfirmPath == "" {
		typed, err := readLineOnTty(cli, fmt.Sprintf("type %s to drop its history: ", preview.ConfirmText))
		if err != nil {
			return err
		}
		drop.ConfirmPath = typed
	}
	if drop.Now {
		typed, err := readLineOnTty(cli, "type now to drop it with no week's window: ")
		if err != nil {
			return err
		}
		drop.ConfirmNow = typed
	}
	reply := &urHistoryReply{}
	if err := cli.callDaemon(ctx, urMethodHistoryDrop, drop, true, reply); err != nil {
		return err
	}
	return urHistoryPrint(cli, options, reply.Lines, reply)
}

// One line typed on the terminal, prompt first: what a drop's confirmation reads. Never stdin.
func readLineOnTty(cli *urCli, prompt string) (string, error) {
	tty, err := cli.openTty()
	if err != nil {
		return "", fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	answer, err := tty.readLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(answer), nil
}
