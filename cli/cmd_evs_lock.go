// ur evs lock and ur evs unlock (ACL-M10-01; §8.8's RepoVersioning, §11.7, §11.13; owner decisions 160, 183): a repo
// admin's lock on a repo's versioning, filed as RepoVersioning{lock} through this device's act once the person confirms
// on /dev/tty, never through MCP. While it stands, format-2 writers write no versionless version and evs refuses drops,
// never their cancels; a drop still pending when its job would start is voided (§11.13). The design names no command,
// so these are this task's; the drops pending when a lock is filed, which §11.7's drop table lists, are offered for
// cancelling once this device reads that table (EVS2's drop listing), and until then the command says the lock voids
// them at their start.
//
//	ur evs lock <repo_id>
//	ur evs unlock <repo_id>

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur evs lock and unlock call.
const urMethodEvsLock = "evs.lock"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsLockMethods)
}

// What the lock method acts on.
type urEvsLockTarget interface {
	fileRepoLock(ctx context.Context, repoId sidecar.Id, lock bool) error
}

// A confirmed control call.
func (self *urDaemonNetwork) fileRepoLock(ctx context.Context, repoId sidecar.Id, lock bool) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.FileRepoLock(ctx, repoId, lock, sidecar.SidecarActConfirmed)
}

type urEvsLockParams struct {
	RepoId string `json:"repo_id"`
	Lock   bool   `json:"lock"`
}

// The lock method over target, when it hosts a Sidecar: a Confirm one, so nothing but a confirmed control call files.
func urEvsLockMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	locks, ok := target.(urEvsLockTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name:    urMethodEvsLock,
		Confirm: true,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urEvsLockParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			repoId, err := sidecar.ParseId(params.RepoId)
			if err != nil {
				return nil, errors.New("no repo id")
			}
			return nil, locks.fileRepoLock(ctx, repoId, params.Lock)
		},
	}}
}

// ur evs lock or unlock: the repo, a yes on the terminal, then the filing.
func runUrEvsLock(ctx context.Context, cli *urCli, options docopt.Opts, lock bool) error {
	repoId, err := sidecar.ParseId(urOptionString(options, "<repo_id>"))
	if err != nil {
		return fmt.Errorf("not a repo id: %w", err)
	}
	question := fmt.Sprintf("unlock versioning on %s, so its writers may write versionless versions and drops go through again?", repoId)
	if lock {
		cli.printf("a drop of %s still pending when its job would start is voided by the lock (§11.13); a cancel is never refused\n", repoId)
		question = fmt.Sprintf("lock versioning on %s: no versionless version and no drop while it stands?", repoId)
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodEvsLock, &urEvsLockParams{RepoId: repoId.String(), Lock: lock}, true, nil); err != nil {
		return err
	}
	if lock {
		cli.printf("%s is locked\n", repoId)
	} else {
		cli.printf("%s is unlocked\n", repoId)
	}
	return nil
}
