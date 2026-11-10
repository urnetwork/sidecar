// ur login --recover (§5.6's genesis row, §7.9's Recovery, plan-CORE-cli-ui-missing #5, CORE-M2-06): a member's new
// device holding only the member's recovery code. When the daemon holds no client yet, ur logs in as ur login does, so
// the device holds an unadmitted client of the member; then it reads the 12 words from /dev/tty alone, with echo off
// as the pass is read, never argv, the environment or stdin, and hands them to the daemon's recovery.recover, a
// Confirm method, which derives the code's keys, uses them and erases them (Sidecar.RecoverWithCode). It prints where
// the recovery stands: filed and waiting on an admin's cosign or on the recovery window, admitted and waiting on the
// config group's key, recovered, or stopped at a failed anchor. A recovery that waits is run again once its admission
// lands, with the code typed again, since no device keeps it. Once recovered, ur offers ur keychain recovery-rotate on
// the terminal: the code was typed into this device.
//
// The words cross the control socket once, as the pass does, and the daemon's reply holds no secret (the reply walk).

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur login --recover calls.
const urMethodRecoveryRecover = "recovery.recover"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urLoginRecoverMethods)
}

// What recovery.recover acts on: a daemon target that runs a Sidecar.
type urLoginRecoverTarget interface {
	recoverWithCode(ctx context.Context, words []byte) (*sidecar.SidecarRecovery, error)
}

// A confirmed control call, the person having typed the code on /dev/tty: the only hosted network's Sidecar recovers.
// The words become a code here and nowhere else in the daemon; a Go string cannot be zeroed, so their parse's copy
// stays until collected.
func (self *urDaemonNetwork) recoverWithCode(ctx context.Context, words []byte) (*sidecar.SidecarRecovery, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	code, err := sidecar.ParseRecoveryCode(string(words))
	if err != nil {
		return nil, err
	}
	return running.RecoverWithCode(ctx, code, sidecar.SidecarActConfirmed)
}

// recovery.recover's params: the words as typed, which a request may carry once and a reply never.
type urRecoverParams struct {
	Words []byte `json:"words"`
}

// One repo of the recovery's pass, as the reply lists it.
type urRecoverRepo struct {
	RepoId     sidecar.Id `json:"repo_id"`
	Generation uint64     `json:"generation,omitempty"`
	Leaf       bool       `json:"leaf,omitempty"`
	SelfJoined bool       `json:"self_joined,omitempty"`
	Waiting    string     `json:"waiting,omitempty"`
}

// recovery.recover's reply: ids, positions and times, never a secret.
type urRecoverReply struct {
	Phase            string           `json:"phase"`
	MemberId         sidecar.Id       `json:"member_id"`
	StatementId      []byte           `json:"statement_id,omitempty"`
	Proposal         bool             `json:"proposal,omitempty"`
	Restored         bool             `json:"restored,omitempty"`
	Position         uint64           `json:"position,omitempty"`
	ActivatesAfterMs int64            `json:"activates_after_ms,omitempty"`
	Waiting          string           `json:"waiting,omitempty"`
	Repos            []*urRecoverRepo `json:"repos,omitempty"`
	OfferRotate      bool             `json:"offer_rotate,omitempty"`
	// Why the call stopped short, where it did: an anchor or a pass that could not run, or the failed anchor.
	Error string `json:"error,omitempty"`
}

// A recovery's reply from what the Sidecar answered.
func newUrRecoverReply(recovery *sidecar.SidecarRecovery) *urRecoverReply {
	reply := &urRecoverReply{
		Phase:       string(recovery.Phase),
		MemberId:    recovery.MemberId,
		StatementId: recovery.StatementId,
		Proposal:    recovery.Proposal,
		Restored:    recovery.Restored,
		Waiting:     recovery.Waiting,
		OfferRotate: recovery.OfferRotate,
	}
	if recovery.Entry != nil {
		reply.Position = recovery.Entry.GetVersion()
	}
	if !recovery.ActivatesAfter.IsZero() {
		reply.ActivatesAfterMs = recovery.ActivatesAfter.UnixMilli()
	}
	for _, repo := range recovery.Repos {
		replyRepo := &urRecoverRepo{RepoId: repo.RepoId, Generation: repo.Generation, Leaf: repo.Leaf, SelfJoined: repo.SelfJoined}
		if repo.Waiting != nil {
			replyRepo.Waiting = repo.Waiting.Error()
		}
		reply.Repos = append(reply.Repos, replyRepo)
	}
	return reply
}

// The recovery method over target, when it runs a Sidecar.
func urLoginRecoverMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	recovering, ok := target.(urLoginRecoverTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodRecoveryRecover,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecoverParams{}
				if err := decodeUrParams(call, params); err != nil || len(params.Words) == 0 {
					return nil, errors.New("a recovery takes the code's 12 words")
				}
				defer clear(params.Words)
				recovery, err := recovering.recoverWithCode(ctx, params.Words)
				if recovery == nil {
					return nil, err
				}
				reply := newUrRecoverReply(recovery)
				if err != nil {
					reply.Error = err.Error()
				}
				return reply, nil
			},
		},
	}
}

// The 12 words from the terminal, echo off, never stdin. The caller zeroes them.
func readRecoveryCodeFromTty(cli *urCli) ([]byte, error) {
	tty, err := cli.openTty()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprint(tty, "recovery code (12 words): ")
	words, err := tty.readSecretLine()
	fmt.Fprint(tty, "\n")
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, errors.New("no recovery code was typed")
	}
	return words, nil
}

// Logs in first where the daemon holds no client, reads the code from the terminal, recovers, and offers a new code
// once recovered.
func runUrLoginRecover(ctx context.Context, cli *urCli, options docopt.Opts) error {
	status := &urStatusReply{}
	if err := cli.callDaemon(ctx, urMethodStatus, &urStatusParams{}, false, status); err != nil {
		return err
	}
	if status.State == "" || status.State == string(sidecar.SidecarStateUnenrolled) {
		// the device holds an unadmitted client of the member first (§7.9's before row)
		if cli.login == nil {
			return errors.New("ur login --recover needs ur-cli to log in, which is not built yet: enroll with ur connect --token, then run ur login --recover")
		}
		authKey, drop, err := cli.login(ctx, cli, "")
		// the OAuth token goes before anything else runs: only the single-use key outlives it
		if drop != nil {
			drop()
		}
		if err != nil {
			return err
		}
		if err := enrollThroughDaemon(ctx, cli, &urEnrollParams{AuthKey: authKey}); err != nil {
			return err
		}
	}

	words, err := readRecoveryCodeFromTty(cli)
	if err != nil {
		return err
	}
	reply := &urRecoverReply{}
	err = cli.callDaemon(ctx, urMethodRecoveryRecover, &urRecoverParams{Words: words}, true, reply)
	clear(words)
	if err != nil {
		return err
	}

	switch sidecar.SidecarRecoveryPhase(reply.Phase) {
	case sidecar.SidecarRecoveryPending:
		switch {
		case 0 < reply.ActivatesAfterMs:
			cli.printf("recovery filed as proposal %x: %s; it can activate from %s\n", reply.StatementId, reply.Waiting,
				time.UnixMilli(reply.ActivatesAfterMs).UTC().Format(time.RFC3339))
		case reply.Proposal:
			cli.printf("recovery filed as proposal %x: %s\n", reply.StatementId, reply.Waiting)
		default:
			cli.printf("recovery filed: %s\n", reply.Waiting)
		}
		cli.printf("once the admission lands, run ur login --recover again and type the code: no device keeps it\n")
	case sidecar.SidecarRecoveryAdmitted:
		if reply.Error != "" {
			cli.printf("admitted; the recovery check could not run: %s\n", reply.Error)
		} else {
			cli.printf("%s; run ur login --recover again once it arrives\n", reply.Waiting)
		}
	case sidecar.SidecarRecoveryStopped:
		return fmt.Errorf("recovery stopped: this network's config does not chain to the genesis your code signed, so this device does nothing more there: %s", reply.Error)
	case sidecar.SidecarRecoveryAnchored:
		cli.printf("recovered: this device is admitted and anchored to the network your code was bound in\n")
		for _, repo := range reply.Repos {
			if repo.Waiting != "" {
				cli.printf("  repo %s waits: %s\n", repo.RepoId, repo.Waiting)
			}
		}
		if reply.Error != "" {
			cli.printf("the recovery's pass stopped short and runs again with ur login --recover: %s\n", reply.Error)
		}
	default:
		return fmt.Errorf("the daemon answered a recovery phase %q", reply.Phase)
	}

	if !reply.OfferRotate {
		return nil
	}
	confirmed, err := confirmOnTty(cli, "this code was typed into this device: set a new recovery code now?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("run ur keychain recovery-rotate to replace the code\n")
		return nil
	}
	return runUrKeychainRecoveryRotate(ctx, cli, options)
}
