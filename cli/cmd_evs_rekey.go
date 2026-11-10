// ur evs rekey (§10.16, R-KEYS-3, owner decision 64; KEYS-M2-26): rewrites a repo's files under its current key
// generation, so none still opens with a key an older generation held. A removed reader keeps what it could already
// read; this ends its reach into files nobody has written since.
//
//	ur evs rekey <repo_id> [--ref=<ref>]... [<path>...]   start the job, or resume the repo's unfinished one
//	ur evs rekey <repo_id> --status                       where the repo's job stands
//
// The job runs in the daemon (sidecar.GkmRekey), in pushes of at most 1,024 entry writes and at most 50 files a
// second, and keeps its place after each push that commits, so the command returns at once and a daemon restarted
// midway goes on from the last committed push when the command is run again. --ref names a ref by its name (main when
// none is given) and each path a file or a directory with everything below it.
//
// It covers the refs and paths named and says so, never the whole repo: evs cannot list a repo's refs or a ref's top
// level yet (questions evs1-m2-01-ref-creation-fields and evs1-m2-24-root-directory-names), so with no path and no
// unfinished job the daemon refuses rather than report a repo rekeyed that it could not walk. A git-mode ref, written
// only through the local tier, and another sidecar's owned ref are skipped and named.
//
// A rekey writes ordinary pushes as this device, a writer's act, so it takes no confirmation on the terminal. Paths
// and ref names are the person's own and go only between ur and its daemon on this device.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur evs rekey calls.
const (
	urMethodEvsRekeyStart  = "evs.rekey.start"
	urMethodEvsRekeyStatus = "evs.rekey.status"
)

// A hosted Sidecar's rekey jobs, which the daemon's composition assigns once it builds an evs client for each
// network and a sidecar.GkmRekey on it. No host does yet (CORE's), so it is nil and ur evs rekey refuses, saying so.
var urDaemonRekey func(running *sidecar.Sidecar) (*sidecar.GkmRekey, error)

// What ur evs rekey answers while the daemon builds no evs client.
var errUrNoRekey = errors.New("this daemon builds no evs client for its network yet, so it has no rekey job to run")

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsRekeyMethods)
}

// What the rekey methods act on: a target hosting a Sidecar with an evs client.
type urEvsRekeyTarget interface {
	// Starts request's job, or resumes the repo's unfinished one, and answers where it starts from.
	startRekey(request *sidecar.GkmRekeyRequest) (*sidecar.GkmRekeyProgress, error)
	// The repo's job, false when it has none.
	rekeyProgress(repoId sidecar.Id) (*sidecar.GkmRekeyProgress, bool, error)
}

// The only hosted network's rekey jobs.
func (self *urDaemonNetwork) rekey() (*sidecar.GkmRekey, error) {
	if urDaemonRekey == nil {
		return nil, errUrNoRekey
	}
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return urDaemonRekey(running)
}

func (self *urDaemonNetwork) startRekey(request *sidecar.GkmRekeyRequest) (*sidecar.GkmRekeyProgress, error) {
	rekey, err := self.rekey()
	if err != nil {
		return nil, err
	}
	return rekey.Start(request)
}

func (self *urDaemonNetwork) rekeyProgress(repoId sidecar.Id) (*sidecar.GkmRekeyProgress, bool, error) {
	rekey, err := self.rekey()
	if err != nil {
		return nil, false, err
	}
	return rekey.Progress(repoId)
}

// evs.rekey.start's and evs.rekey.status's params. Refs are ref names as text.
type urEvsRekeyParams struct {
	RepoId sidecar.Id `json:"repo_id"`
	Refs   []string   `json:"refs,omitempty"`
	Paths  []string   `json:"paths,omitempty"`
}

// A ref a job skipped.
type urEvsRekeySkipped struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

// A job as the methods answer it: its scope, counts and positions, never a key.
type urEvsRekeyReply struct {
	// False for a status of a repo with no job.
	Known      bool                 `json:"known"`
	State      string               `json:"state,omitempty"`
	Generation uint64               `json:"generation,omitempty"`
	Refs       []string             `json:"refs,omitempty"`
	Paths      []string             `json:"paths,omitempty"`
	Rewritten  uint64               `json:"rewritten"`
	Current    uint64               `json:"current"`
	Absent     uint64               `json:"absent"`
	Pushes     uint64               `json:"pushes"`
	Skipped    []*urEvsRekeySkipped `json:"skipped,omitempty"`
	StopReason string               `json:"stop_reason,omitempty"`
}

// The reply of a job's progress.
func urEvsRekeyReplyOf(progress *sidecar.GkmRekeyProgress) *urEvsRekeyReply {
	reply := &urEvsRekeyReply{
		Known: true, State: string(progress.State), Generation: progress.Generation, Paths: progress.Paths,
		Rewritten: progress.RewrittenCount, Current: progress.CurrentCount, Absent: progress.AbsentCount, Pushes: progress.PushCount,
		StopReason: progress.StopReason,
	}
	for _, refName := range progress.RefNames {
		reply.Refs = append(reply.Refs, string(refName))
	}
	for _, skipped := range progress.SkippedRefs {
		reply.Skipped = append(reply.Skipped, &urEvsRekeySkipped{Ref: string(skipped.RefName), Reason: skipped.Reason})
	}
	return reply
}

// The rekey methods over target, when it hosts a Sidecar.
func urEvsRekeyMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	rekey, ok := target.(urEvsRekeyTarget)
	if !ok {
		return nil
	}
	decode := func(call *sidecar.DaemonCall) (*urEvsRekeyParams, error) {
		params := &urEvsRekeyParams{}
		if err := decodeUrParams(call, params); err != nil || params.RepoId == (sidecar.Id{}) {
			return nil, errors.New("a rekey takes a repo id")
		}
		return params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodEvsRekeyStart,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call)
				if err != nil {
					return nil, err
				}
				request := &sidecar.GkmRekeyRequest{RepoId: params.RepoId, Paths: params.Paths}
				for _, ref := range params.Refs {
					if ref == "" {
						return nil, errors.New("a ref's name is not empty")
					}
					request.RefNames = append(request.RefNames, []byte(ref))
				}
				progress, err := rekey.startRekey(request)
				if err != nil {
					return nil, err
				}
				return urEvsRekeyReplyOf(progress), nil
			},
		},
		{
			Name: urMethodEvsRekeyStatus,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := decode(call)
				if err != nil {
					return nil, err
				}
				progress, known, err := rekey.rekeyProgress(params.RepoId)
				if err != nil {
					return nil, err
				}
				if !known {
					return &urEvsRekeyReply{}, nil
				}
				return urEvsRekeyReplyOf(progress), nil
			},
		},
	}
}

// ur evs rekey: starts or resumes the repo's job, or shows where it stands.
func runUrEvsRekey(ctx context.Context, cli *urCli, options docopt.Opts) error {
	repoIdText, _ := options.String("<repo_id>")
	repoId, err := sidecar.ParseId(repoIdText)
	if err != nil {
		return fmt.Errorf("%q is no repo id", repoIdText)
	}
	reply := &urEvsRekeyReply{}
	if urOptionBool(options, "--status") {
		if err := cli.callDaemon(ctx, urMethodEvsRekeyStatus, &urEvsRekeyParams{RepoId: repoId}, false, reply); err != nil {
			return err
		}
		if !reply.Known {
			cli.printf("repo %s: no rekey job\n", repoId)
			return nil
		}
		printUrEvsRekey(cli, repoId, reply)
		return nil
	}
	params := &urEvsRekeyParams{RepoId: repoId}
	if refs, ok := options["--ref"].([]string); ok {
		params.Refs = refs
	}
	if paths, ok := options["<path>"].([]string); ok {
		params.Paths = paths
	}
	if err := cli.callDaemon(ctx, urMethodEvsRekeyStart, params, false, reply); err != nil {
		return err
	}
	printUrEvsRekey(cli, repoId, reply)
	cli.printf("  the job runs in the daemon: ur evs rekey %s --status shows where it stands\n", repoId)
	return nil
}

// Prints a job: its state, its scope and its counts.
func printUrEvsRekey(cli *urCli, repoId sidecar.Id, reply *urEvsRekeyReply) {
	cli.printf("repo %s: rekey to generation %d, %s\n", repoId, reply.Generation, reply.State)
	paths := "each ref from its top level"
	if 0 < len(reply.Paths) {
		paths = "paths " + strings.Join(reply.Paths, ", ")
	}
	cli.printf("  scope: refs %s; %s\n", strings.Join(reply.Refs, ", "), paths)
	cli.printf("  %d file(s) rewritten in %d push(es), %d already of the generation, %d gone before they were read\n",
		reply.Rewritten, reply.Pushes, reply.Current, reply.Absent)
	for _, skipped := range reply.Skipped {
		why := skipped.Reason
		switch skipped.Reason {
		case "git_mode":
			why = "a git-mode ref, written only through the local tier"
		case "not_owner":
			why = "a ref only its owner writes"
		}
		cli.printf("  skipped ref %s: %s\n", skipped.Ref, why)
	}
	switch reply.State {
	case string(sidecar.GkmRekeyStateStopped):
		if reply.StopReason != "" {
			cli.printf("  stopped: %s\n", reply.StopReason)
		}
		cli.printf("  run ur evs rekey %s again to go on from the last push that committed\n", repoId)
	case string(sidecar.GkmRekeyStateDone):
		cli.printf("  files outside this scope, and on a skipped ref, keep the keys they had\n")
	}
}
