// ur directory's person acts, ur's half (§16.11's signing row, §5.8, D-CORE-13, D-CORE-18; CORE-M6-02): the daemon's
// directory methods registered over the daemon's networks (sidecar.DaemonDirectoryMethods), and the two helpers
// RECORD-M6-23's ur directory commands send their acts through.
//
//	confirmed  announce, revoke, approve, deny and erase ask the person on /dev/tty, never stdin, and send the Confirm
//	           method only on a yes, with ur_confirmed; no terminal, or a no, sends nothing
//	claims     ur directory runs sends directory.claims; a value wider than the project's present one comes back
//	           needs_confirmation, and only after a yes on /dev/tty does ur send directory.claims.confirm
//
// The daemon checks again whatever ur sends, so a same-uid process that forges ur_confirmed reaches no more than
// owner decision 47 discloses.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDirectoryMethods)
}

// The directory's methods over the daemon target's networks, when it hosts them. RECORD-M6-19 and RECORD-M6-20 set
// their acts' backends here as each lands; until then those methods refuse, signing nothing.
func urDirectoryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.daemon == nil {
		return nil
	}
	return sidecar.DaemonDirectoryMethods(network.daemon, urDirectoryBackends())
}

// The acts' backends this ur has: the Sidecar's own list, taint and announcement, and none yet of the rest.
func urDirectoryBackends() *sidecar.DaemonDirectoryBackends {
	return &sidecar.DaemonDirectoryBackends{}
}

// A person act refused for want of the person's yes: nothing was sent.
var errUrDirectoryNotConfirmed = errors.New("not confirmed: nothing was signed")

// Sends a directory person act, method, once the person answers yes to question on /dev/tty: its reply decoded into
// reply. No terminal, or any answer but yes, sends nothing.
func urDirectoryConfirmedCall(ctx context.Context, cli *urCli, method string, params any, question string, reply any) error {
	yes, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !yes {
		return errUrDirectoryNotConfirmed
	}
	return cli.callDaemon(ctx, method, params, true, reply)
}

// ur directory runs's choice of value for the caller's project in network: at once when it is no wider than the
// project's present value, else only after the person's yes on /dev/tty. Answers the value a new session starts under.
func urDirectoryChooseClaims(ctx context.Context, cli *urCli, network string, value string) (*sidecar.DaemonDirectoryClaimsReply, error) {
	params := &sidecar.DaemonDirectoryClaimsParams{Network: network, Claims: value}
	reply := &sidecar.DaemonDirectoryClaimsReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDirectoryClaims, params, false, reply); err != nil {
		return nil, err
	}
	if !reply.NeedsConfirmation {
		return reply, nil
	}
	question := fmt.Sprintf("Announce this project's runs in the team directory under %s, wider than its %s now?", value, reply.Claims)
	confirmed := &sidecar.DaemonDirectoryClaimsReply{}
	if err := urDirectoryConfirmedCall(ctx, cli, sidecar.DaemonMethodDirectoryClaimsConfirm, params, question, confirmed); err != nil {
		return nil, err
	}
	return confirmed, nil
}
