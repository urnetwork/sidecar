// ur keychain recovery-rotate [--compromise] (§5.9's Recovery code, D-CORE-10, D-CORE-13, CORE-M2-05): draws a new
// recovery code for this device's member, has the daemon sign its RecoveryBind or RecoveryRebind once the person
// confirms on /dev/tty, and shows the code's 12 words on the terminal, once. ur draws the code and derives its keys
// itself: the daemon is asked for what the genesis_sig signs (keychain.recovery_anchor) and handed only the two
// public keys and that signature (keychain.recovery_bind, a Confirm method), so no word, code or private key
// crosses the control socket, reaches the daemon, stdout or a file. The words are written to the terminal only after
// the daemon signed the binding, since a code whose binding was refused binds nothing.
//
// Afterwards the old code admits nothing and gets no new wrap, and opens only what was wrapped to it before, which
// the command says with §5.9's backup rule. With --compromise the rebind's reason makes each repo's next rotation a
// remove rotation with a path epoch (§10.8), and the command lists the member's devices to review, this one, the
// rebind's signer, last (g0-recheck-2-compromise-rebind-backups #1): each is revoked with ur devices revoke
// --compromise, which is CORE-M3-04's.

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur keychain recovery-rotate calls.
const (
	urMethodKeychainRecoveryAnchor = "keychain.recovery_anchor"
	urMethodKeychainRecoveryBind   = "keychain.recovery_bind"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urKeychainRecoveryMethods)
}

// What the recovery methods act on: a daemon target that runs a Sidecar.
type urKeychainRecoveryTarget interface {
	recoveryAnchor() (sidecar.Id, []byte, error)
	bindRecovery(ctx context.Context, binding *sidecar.RecoveryBinding, compromise bool) (*sidecar.RecoveryRotation, error)
}

func (self *urDaemonNetwork) recoveryAnchor() (sidecar.Id, []byte, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return sidecar.Id{}, nil, err
	}
	return running.RecoveryAnchor()
}

// A confirmed control call, the person having answered on /dev/tty. The daemon's presence prompt is §16's, so a
// binding the log covers is refused until it lands, never signed without the check.
func (self *urDaemonNetwork) bindRecovery(ctx context.Context, binding *sidecar.RecoveryBinding, compromise bool) (*sidecar.RecoveryRotation, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	rotation, err := running.BindRecovery(ctx, binding, compromise, sidecar.SidecarActConfirmed, nil)
	if errors.Is(err, sidecar.ErrSidecarActPending) {
		// signed and kept: its post goes again, and the reply says so
		return rotation, nil
	}
	return rotation, err
}

// keychain.recovery_anchor's reply: public values.
type urRecoveryAnchorReply struct {
	NetworkId     sidecar.Id `json:"network_id"`
	GenesisSha256 []byte     `json:"genesis_sha256"`
}

// keychain.recovery_bind's params: a binding's public half.
type urRecoveryBindParams struct {
	Ed25519PublicKey []byte `json:"ed25519_public_key"`
	XwingPublicKey   []byte `json:"xwing_public_key"`
	GenesisSig       []byte `json:"genesis_sig"`
	Compromise       bool   `json:"compromise,omitempty"`
}

// One of the member's devices, as keychain.recovery_bind's reply lists them.
type urRecoveryDevice struct {
	SidecarId sidecar.Id `json:"sidecar_id"`
	This      bool       `json:"this,omitempty"`
	State     string     `json:"state"`
}

// keychain.recovery_bind's reply: ids and positions, never a secret.
type urRecoveryBindReply struct {
	KeySha256         []byte              `json:"key_sha256"`
	PreviousKeySha256 []byte              `json:"previous_key_sha256,omitempty"`
	Position          uint64              `json:"position,omitempty"`
	ProposalId        []byte              `json:"proposal_id,omitempty"`
	Pending           bool                `json:"pending,omitempty"`
	Devices           []*urRecoveryDevice `json:"devices,omitempty"`
}

// The recovery methods over target, when it runs a Sidecar.
func urKeychainRecoveryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	recovery, ok := target.(urKeychainRecoveryTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodKeychainRecoveryAnchor,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				networkId, genesisSha256, err := recovery.recoveryAnchor()
				if err != nil {
					return nil, err
				}
				return &urRecoveryAnchorReply{NetworkId: networkId, GenesisSha256: genesisSha256}, nil
			},
		},
		{
			Name:    urMethodKeychainRecoveryBind,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRecoveryBindParams{}
				if err := decodeUrParams(call, params); err != nil || len(params.Ed25519PublicKey) == 0 {
					return nil, errors.New("a recovery binding takes its two public keys and its genesis signature")
				}
				rotation, err := recovery.bindRecovery(ctx, &sidecar.RecoveryBinding{
					Ed25519PublicKey: params.Ed25519PublicKey,
					XwingPublicKey:   params.XwingPublicKey,
					GenesisSig:       params.GenesisSig,
				}, params.Compromise)
				if err != nil {
					return nil, err
				}
				reply := &urRecoveryBindReply{
					KeySha256:         rotation.KeySha256,
					PreviousKeySha256: rotation.PreviousKeySha256,
					ProposalId:        rotation.ProposalId,
					Pending:           rotation.Pending,
				}
				if rotation.Entry != nil {
					reply.Position = rotation.Entry.GetVersion()
				}
				for _, device := range rotation.Devices {
					reply.Devices = append(reply.Devices, &urRecoveryDevice{SidecarId: device.SidecarId, This: device.This, State: device.State})
				}
				return reply, nil
			},
		},
	}
}

// Draws the code, has the daemon sign its binding on a yes, and shows the words on the terminal.
func runUrKeychainRecoveryRotate(ctx context.Context, cli *urCli, options docopt.Opts) error {
	compromise, _ := options.Bool("--compromise")
	anchor := &urRecoveryAnchorReply{}
	if err := cli.callDaemon(ctx, urMethodKeychainRecoveryAnchor, nil, false, anchor); err != nil {
		return err
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "This replaces your recovery code for this network. The old code will admit no new device and open nothing new.\n%s\n", sidecar.RecoveryBackupRule)
	if compromise {
		fmt.Fprintf(tty, "As a compromise rotation, every repo you read re-keys at its next rotation, and you should then revoke each device the old code's holder may have reached.\n")
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "rotate the recovery code?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}

	code, err := sidecar.NewRecoveryCode(rand.Reader)
	if err != nil {
		return err
	}
	words, err := code.Words()
	if err != nil {
		code.Erase()
		return err
	}
	keys, err := code.Keys()
	if err != nil {
		return err
	}
	genesisSig, err := keys.SignGenesis(anchor.NetworkId, anchor.GenesisSha256)
	params := &urRecoveryBindParams{
		Ed25519PublicKey: keys.Ed25519PublicKey(),
		XwingPublicKey:   keys.XwingPublicKey(),
		GenesisSig:       genesisSig,
		Compromise:       compromise,
	}
	keys.Erase()
	if err != nil {
		return err
	}
	reply := &urRecoveryBindReply{}
	if err := cli.callDaemon(ctx, urMethodKeychainRecoveryBind, params, true, reply); err != nil {
		// nothing was signed: the code binds nothing and is not shown
		return err
	}

	tty, err = cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Your new recovery code, shown this once. Write it down and keep it apart from this device:\n\n")
	for row := 0; row < len(words); row += 4 {
		fmt.Fprintf(tty, "  %s\n", strings.Join(words[row:min(row+4, len(words))], " "))
	}
	fmt.Fprintf(tty, "\n")
	switch {
	case len(reply.ProposalId) != 0:
		fmt.Fprintf(tty, "The binding waits for another admin's cosign: ur approve %x on their device. Keep the old code until it completes.\n", reply.ProposalId)
	case reply.Pending:
		fmt.Fprintf(tty, "The binding is signed and its post is still going. Keep the old code until ur status shows it landed.\n")
	default:
		fmt.Fprintf(tty, "The binding landed at position %d.\n", reply.Position)
	}
	if compromise {
		fmt.Fprintf(tty, "Review each device of yours and revoke any the old code's holder may have reached, this device last, from a replacement:\n")
		for _, device := range reply.Devices {
			if !device.This {
				fmt.Fprintf(tty, "  ur devices revoke %s --compromise    (%s)\n", device.SidecarId, device.State)
			}
		}
	}
	cli.printf("recovery code rotated\n")
	return nil
}
