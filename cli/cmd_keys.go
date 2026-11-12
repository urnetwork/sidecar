// ur keys (§10.5, §16.16): the command word several areas build. This file registers it and its rotate part
// (KEYS-M2-26); §16's tracks add add-presence, add-ssh, ls and rm as their own cmd_keys_<part>.go, each with its usage
// line and its case here: add-presence, ls and rm are cmd_keys_presence.go's (MCP-M3-09); add-ssh waits on SSHSIGs,
// which the owner dropped from every milestone until a customer asks (plan-MCP-risk-classifier#1).
//
//	ur keys rotate <repo_id>    a new key generation for the repo now (§10.5's Rotate, cause request)
//	ur keys add-presence        a presence key on this host's authenticator (cmd_keys_presence.go)
//	ur keys rm <key_id>         one of the member's keys revoked
//	ur keys ls                  the member's live presence keys
//
// rotate asks the daemon's key client for GkmClient.RotateRepo and nothing else: the client claims the generation
// with cause request, or with cause remove when a key holder left or lapsed since the generation before and none
// covers it yet, which is the rotation the next write would have made anyway (DESIGN-DETAILS 6.2.5). The command
// never chooses a cause. It prints the generation and its cause, never a key. A rotation is a writer's ordinary act,
// as the one every 30 days is, so it takes no confirmation on the terminal; a device that may not rotate is refused
// by the client. Files keep the keys they were written under until their next write after a remove generation, or
// until `ur evs rekey`.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur keys rotate calls.
const urMethodKeysRotate = "keys.rotate"

// A hosted Sidecar's key client, which the daemon's composition assigns once it builds one for each network. No host
// does yet (the client's wiring into NewSidecar is CORE's), so it is nil and ur keys rotate refuses, saying so.
var urDaemonGkmClient func(running *sidecar.Sidecar) (sidecar.GkmClient, error)

// What ur keys rotate answers while the daemon builds no key client.
var errUrNoGkmClient = errors.New("this daemon builds no key client for its network yet, so it cannot rotate a repo's keys")

func init() {
	registerUrCommand(&urCommand{
		name: "keys",
		usage: strings.Join([]string{
			"  ur keys rotate <repo_id>",
			"  ur keys add-presence",
			"  ur keys rm <key_id>",
			"  ur keys ls",
		}, "\n"),
		summary: "keys: rotate a repo's generation, or add, remove and list presence keys",
		run:     runUrKeys,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urKeysMethods)
}

// Runs the part of ur keys its first word names.
func runUrKeys(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "rotate"):
		return runUrKeysRotate(ctx, cli, options)
	case urOptionBool(options, "add-presence"):
		return runUrKeysAddPresence(ctx, cli)
	case urOptionBool(options, "rm"):
		return runUrKeysRemove(ctx, cli, options)
	case urOptionBool(options, "ls"):
		return runUrKeysList(ctx, cli)
	}
	return errors.New("ur keys takes rotate, add-presence, rm or ls")
}

// What the keys methods act on: a target hosting a Sidecar with a key client.
type urKeysTarget interface {
	// A new generation of the repo now, and the cause it was claimed with.
	rotateRepo(ctx context.Context, repoId sidecar.Id) (generation uint64, cause sidecar.GkmCause, err error)
}

func (self *urDaemonNetwork) rotateRepo(ctx context.Context, repoId sidecar.Id) (uint64, sidecar.GkmCause, error) {
	if urDaemonGkmClient == nil {
		return 0, 0, errUrNoGkmClient
	}
	running, err := self.onlySidecar()
	if err != nil {
		return 0, 0, err
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		return 0, 0, err
	}
	return urRotateRepo(ctx, gkm, repoId)
}

// `ur keys rotate` on a key client: RotateRepo alone, whose cause is the client's to set.
func urRotateRepo(ctx context.Context, gkm sidecar.GkmClient, repoId sidecar.Id) (uint64, sidecar.GkmCause, error) {
	key, err := gkm.RotateRepo(ctx, repoId)
	if err != nil {
		return 0, 0, err
	}
	return key.Generation(), key.Cause(), nil
}

// keys.rotate's params.
type urKeysRotateParams struct {
	RepoId sidecar.Id `json:"repo_id"`
}

// keys.rotate's reply: a position and a cause, never a key.
type urKeysRotateReply struct {
	Generation uint64 `json:"generation"`
	Cause      string `json:"cause"`
}

// A cause as ur prints it.
func urGkmCauseName(cause sidecar.GkmCause) string {
	switch cause {
	case sidecar.GkmCauseRemove:
		return "remove"
	case sidecar.GkmCauseRequest:
		return "request"
	case sidecar.GkmCauseSchedule:
		return "schedule"
	}
	return fmt.Sprintf("cause %d", cause)
}

// The keys methods over target, when it hosts a Sidecar.
func urKeysMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	keys, ok := target.(urKeysTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodKeysRotate,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urKeysRotateParams{}
				if err := decodeUrParams(call, params); err != nil || params.RepoId == (sidecar.Id{}) {
					return nil, errors.New("a rotation takes a repo id")
				}
				generation, cause, err := keys.rotateRepo(ctx, params.RepoId)
				if err != nil {
					return nil, err
				}
				return &urKeysRotateReply{Generation: generation, Cause: urGkmCauseName(cause)}, nil
			},
		},
	}
}

// ur keys rotate: asks for the rotation and prints the generation it claimed.
func runUrKeysRotate(ctx context.Context, cli *urCli, options docopt.Opts) error {
	repoIdText, _ := options.String("<repo_id>")
	repoId, err := sidecar.ParseId(repoIdText)
	if err != nil {
		return fmt.Errorf("%q is no repo id", repoIdText)
	}
	reply := &urKeysRotateReply{}
	if err := cli.callDaemon(ctx, urMethodKeysRotate, &urKeysRotateParams{RepoId: repoId}, false, reply); err != nil {
		return err
	}
	cli.printf("repo %s: generation %d, cause %s\n", repoId, reply.Generation, reply.Cause)
	if reply.Cause == urGkmCauseName(sidecar.GkmCauseRemove) {
		cli.printf("a key holder left or lapsed since the generation before, so each file is rewritten under this one at its next write, or by ur evs rekey\n")
	}
	return nil
}
