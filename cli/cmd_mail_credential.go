// ur mail credential (§15.10, §15.16, D-MAIL-11, I-7, I-17, owner decision 47; MAIL-M8-07): makes the network's local
// mail credential, the secret IMAP's LOGIN takes and submission's AUTH with it (MAIL-M9-01), and opens the daemon's
// IMAP listener.
//
//	ur mail credential [--network=<net>]
//
// ur draws the secret in its own process (sidecar.NewMailLocalCredentialSecret) and sends the daemon only its
// verifier, through mail.credential, a Confirm method, so neither an MCP nor a hook session can set one. Once the
// daemon has kept the verifier, ur writes the secret to the terminal, once, with the user name and IMAP's addresses,
// and never to stdout, a file or a log, so an agent driving ur reads none of it (I-7), and nothing can show it again:
// a person who lost it makes another. A credential made before stops opening anything at once, so ur asks on
// /dev/tty first, and with no terminal it makes nothing.
//
// The daemon serves IMAP once a network has mail on and a credential made: at its start, after an unlock, and after
// this command, binding every interface unless --listen narrows it, TLS off loopback (Daemon.MailImap). The design
// names this command's flags nowhere: --network is ur mail's, as cli/UI.md records (plan-CORE-cli-ui-missing).

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urnetwork/sidecar"
)

// The control method ur mail credential calls.
const urMethodMailCredential = "mail.credential"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urMailCredentialMethods)
}

// What mail.credential acts on: a target that keeps each hosted network's local credential and runs the daemon's
// IMAP.
type urMailCredentialTarget interface {
	// The local credential of network, a hosted one by name, or, empty, §5.8's pick; refused while its mail is off.
	mailCredential(network string) (*sidecar.MailLocalCredential, error)
	// Opens the daemon's IMAP listener once a network serves IMAP, answering its status.
	startMailImap() (*sidecar.DaemonLocalListenerStatus, error)
}

// mail.credential's params: the verifier alone, never the secret.
type urMailCredentialParams struct {
	Network  string `json:"network,omitempty"`
	Verifier []byte `json:"verifier"`
}

// mail.credential's reply: the user name and where IMAP listens, never a secret.
type urMailCredentialReply struct {
	User string `json:"user"`
	// host:port of each address IMAP binds, and whether a LAN host can reach it.
	ImapAddresses  []string `json:"imap_addresses,omitempty"`
	ImapLanExposed bool     `json:"imap_lan_exposed,omitempty"`
	// Why IMAP does not listen, empty when it does.
	ImapProblem string `json:"imap_problem,omitempty"`
}

// The hosted network's local credential, while its mail is on.
func (self *urDaemonNetwork) mailCredential(network string) (*sidecar.MailLocalCredential, error) {
	if self.daemon == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	networkId, err := self.daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, network)
	if err != nil {
		return nil, err
	}
	running, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	client, err := running.Mail()
	if err != nil {
		return nil, err
	}
	if !client.Enabled() {
		return nil, errors.New("mail is off for the network: run ur mail enable first")
	}
	return client.LocalCredential()
}

// The daemon's IMAP, opened once a network serves it.
func (self *urDaemonNetwork) startMailImap() (*sidecar.DaemonLocalListenerStatus, error) {
	if self.daemon == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	return self.daemon.MailImap().Start()
}

// Opens IMAP where a hosted network already serves it, as the daemon starts or unlocks; with none it stays closed.
func (self *urDaemonNetwork) startMailImapIfServing() {
	if self.daemon == nil {
		return
	}
	if _, err := self.startMailImap(); err != nil && !errors.Is(err, sidecar.ErrMailImapNoAccount) {
		fmt.Fprintf(os.Stderr, "ur: IMAP did not start: %v\n", err)
	}
}

// mail.credential over target, when it keeps credentials; IMAP opens here for a network that already serves it.
func urMailCredentialMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if network, ok := target.(*urDaemonNetwork); ok {
		network.startMailImapIfServing()
	}
	credentials, ok := target.(urMailCredentialTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodMailCredential,
			// a credential opens the member's mail, so only a person's ur makes one (D-CORE-13)
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urMailCredentialParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				credential, err := credentials.mailCredential(params.Network)
				if err != nil {
					return nil, err
				}
				if err := credential.Install(params.Verifier); err != nil {
					return nil, err
				}
				reply := &urMailCredentialReply{User: sidecar.MailLocalCredentialUser}
				status, err := credentials.startMailImap()
				if err != nil {
					reply.ImapProblem = err.Error()
					return reply, nil
				}
				reply.ImapAddresses, reply.ImapLanExposed = status.Addresses, status.LanExposed
				return reply, nil
			},
		},
	}
}

// Draws the credential, has the daemon keep its verifier on a yes, and shows the secret on the terminal alone.
func runUrMailCredential(ctx context.Context, cli *urCli, network string) error {
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "This makes the network's mail credential for IMAP and submission, shown once on this terminal. A mail client using one made before stops working.\n")
	tty.Close()
	confirmed, err := confirmOnTty(cli, "make a new mail credential?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	secret, err := sidecar.NewMailLocalCredentialSecret(nil)
	if err != nil {
		return err
	}
	reply := &urMailCredentialReply{}
	if err := cli.callDaemon(ctx, urMethodMailCredential, &urMailCredentialParams{Network: network, Verifier: secret.Verifier}, true, reply); err != nil {
		// nothing was kept: the secret opens nothing and is not shown
		return err
	}
	tty, err = cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Your mail credential, shown this once. Give it to your mail client; ur cannot show it again:\n\n")
	fmt.Fprintf(tty, "  user      %s\n", reply.User)
	fmt.Fprintf(tty, "  password  %s\n", secret.Text)
	for _, address := range reply.ImapAddresses {
		fmt.Fprintf(tty, "  imap      %s, plaintext on loopback and TLS elsewhere\n", address)
	}
	fmt.Fprintf(tty, "\n")
	cli.printf("mail credential made; one made before no longer works\n")
	switch {
	case reply.ImapProblem != "":
		cli.printf("IMAP does not listen: %s\n", reply.ImapProblem)
	case reply.ImapLanExposed:
		cli.printf("IMAP listens on every interface, TLS off loopback; --listen narrows it\n")
	}
	return nil
}
