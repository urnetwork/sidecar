//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// git's ssh front (§11.11's Binding; I-17, X19; owner decisions 84, 130): git-upload-pack and git-receive-pack behind
// x/crypto/ssh, on the listener DaemonLocalListen binds for git's ssh, which carries its own encryption everywhere.
//
//	host key  one ed25519 key per network, made at the first front's start and kept sealed in the evs component's
//	          store (ssh/host_key), whose public line `ur mount` prints for the client's known_hosts
//	who       public keys only: no password, no keyboard-interactive; an authorized key maps to the sidecar or an
//	          isolated agent (§5.5), through the host's lookup (§7.9's KeyRegister once it serves ssh keys); no lookup
//	          refuses every key
//	what      one session channel, one exec of `git-upload-pack '<repo>'` or `git-receive-pack '<repo>'`, the repo
//	          /<repo_id hex>.git or <repo_id hex>.git, run on the mount's bare repository with the channel as its stdio,
//	          receive-pack behind the mount's hooks with a receive session; its exit status sent back
//
// Nothing else is served: no shell, no pty, no forwarding, no subsystem, and no environment a client sends.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Where the network's ssh host key rests in the evs component's sealed store.
const evsGitSshHostKeyName = "ssh/host_key"

// The network's ssh host key: read from the sealed store, or made and kept there at first use.
func (self *EvsMounts) SshHostKey() (ssh.Signer, error) {
	store := self.client.args.Store
	reader, err := store.Open(evsGitSshHostKeyName)
	if err == nil {
		seed, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%w: the ssh host key", ErrSidecarStoreFailed)
		}
		testHookSecret("evs_git_ssh_host_key", seed)
		return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	}
	if !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(seed)
	testHookSecret("evs_git_ssh_host_key", seed)
	writer, err := store.Create(evsGitSshHostKeyName)
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	if _, err := writer.Write(seed); err != nil {
		return nil, err
	}
	if err := writer.Commit(); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}

// The host key's known_hosts line, its type and base64: what `ur mount` prints.
func EvsGitSshHostKeyLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// What the ssh front serves on.
type EvsGitSshFrontArgs struct {
	Mounts   *EvsMounts
	Listener net.Listener
	HostKey  ssh.Signer
	// The caller an authorized key is: the agent's label, empty for the sidecar itself, and false for a key no one
	// registered. Nil refuses every key.
	AuthorizedKey func(key ssh.PublicKey) (string, bool)
}

// git's ssh front.
type EvsGitSshFront struct {
	args   *EvsGitSshFrontArgs
	config *ssh.ServerConfig

	stateLock sync.Mutex
	closed    bool
	conns     map[net.Conn]bool
}

// The front over args; Serve runs it.
func NewEvsGitSshFront(args *EvsGitSshFrontArgs) (*EvsGitSshFront, error) {
	if args == nil || args.Mounts == nil || args.Listener == nil || args.HostKey == nil {
		return nil, fmt.Errorf("%w: git's ssh front needs its mounts, a listener and a host key", errInvalidSettings)
	}
	self := &EvsGitSshFront{args: args, conns: map[net.Conn]bool{}}
	self.config = &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if args.AuthorizedKey == nil {
				return nil, errors.New("no key is authorized")
			}
			agent, ok := args.AuthorizedKey(key)
			if !ok {
				return nil, errors.New("an unknown key")
			}
			return &ssh.Permissions{Extensions: map[string]string{"ur-agent": agent}}, nil
		},
	}
	self.config.AddHostKey(args.HostKey)
	return self, nil
}

// Accepts connections until the listener closes.
func (self *EvsGitSshFront) Serve(ctx context.Context) error {
	for {
		conn, err := self.args.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !self.track(conn) {
			conn.Close()
			return nil
		}
		go func() {
			defer self.untrack(conn)
			self.serveConn(ctx, conn)
		}()
	}
}

// Ends every connection and the listener.
func (self *EvsGitSshFront) Close() error {
	self.stateLock.Lock()
	self.closed = true
	conns := self.conns
	self.conns = map[net.Conn]bool{}
	self.stateLock.Unlock()
	for conn := range conns {
		conn.Close()
	}
	return self.args.Listener.Close()
}

// Keeps conn for Close, false once closed.
func (self *EvsGitSshFront) track(conn net.Conn) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.conns[conn] = true
	return true
}

// Forgets and closes conn.
func (self *EvsGitSshFront) untrack(conn net.Conn) {
	self.stateLock.Lock()
	delete(self.conns, conn)
	self.stateLock.Unlock()
	conn.Close()
}

// One connection: its handshake, then each session channel; every other channel type is refused.
func (self *EvsGitSshFront) serveConn(ctx context.Context, conn net.Conn) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, self.config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	agent := serverConn.Permissions.Extensions["ur-agent"]
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only git's session")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go self.serveSession(ctx, channel, channelRequests, agent)
	}
}

// The exit-status request's payload.
type evsSshExitStatus struct {
	Status uint32
}

// One session: its one exec of git-upload-pack or git-receive-pack; anything else refused.
func (self *EvsGitSshFront) serveSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, agent string) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			// no shell, pty, environment or subsystem
			request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			request.Reply(false, nil)
			return
		}
		service, mount, ok := self.commandOf(payload.Command)
		if !ok {
			request.Reply(false, nil)
			fmt.Fprintln(channel.Stderr(), "ur: only git-upload-pack and git-receive-pack of a mounted repo")
			channel.SendRequest("exit-status", false, ssh.Marshal(&evsSshExitStatus{Status: 1}))
			return
		}
		request.Reply(true, nil)
		code := self.runService(ctx, channel, service, mount, agent)
		channel.SendRequest("exit-status", false, ssh.Marshal(&evsSshExitStatus{Status: uint32(code)}))
		return
	}
}

// The service and the mount an exec's command names: `git-upload-pack '<repo>'` or `git-receive-pack '<repo>'`, the
// repo /<repo_id hex>.git or <repo_id hex>.git, quoted or not.
func (self *EvsGitSshFront) commandOf(command string) (string, *EvsLocalRepo, bool) {
	service, rest, found := strings.Cut(strings.TrimSpace(command), " ")
	if !found || (service != daemonGitUploadPack && service != daemonGitReceivePack) {
		return "", nil, false
	}
	path := strings.Trim(strings.TrimSpace(rest), "'\"")
	path = strings.TrimPrefix(path, "/")
	idText, found := strings.CutSuffix(path, evsLocalBareRepoExtension)
	if !found {
		return "", nil, false
	}
	decoded, err := hex.DecodeString(idText)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != idText {
		return "", nil, false
	}
	mount, ok := self.args.Mounts.Get(Id(decoded))
	return service, mount, ok
}

// Runs service on the mount's bare repository with channel as its stdio, a receive-pack behind a receive session,
// answering its exit code.
func (self *EvsGitSshFront) runService(ctx context.Context, channel ssh.Channel, service string, mount *EvsLocalRepo, agent string) int {
	git := mount.git
	verb := strings.TrimPrefix(service, "git-")
	env := []string{}
	if service == daemonGitReceivePack {
		session, closeSession := self.args.Mounts.OpenReceiveSession(mount, agent)
		defer closeSession()
		env = append(env, self.args.Mounts.ReceiveEnvironment(session)...)
	}
	return evsRunGitService(ctx, git, verb, mount.BareDir, env, channel, channel, channel.Stderr())
}

// Runs git <verb> <dir> with in, out and errOut as its stdio and env added to the clean environment, answering its
// exit code. Its stdin is copied by a goroutine that the process's exit ends, so a client that keeps its side open
// never holds the service past its end.
func evsRunGitService(ctx context.Context, git *EvsGitRunner, verb string, dir string, env []string, in io.Reader, out io.Writer, errOut io.Writer) int {
	command := exec.CommandContext(ctx, git.Path(), verb, dir)
	command.Env = git.Environment(env...)
	command.Dir = git.home
	command.Stdout = out
	command.Stderr = errOut
	stdin, err := command.StdinPipe()
	if err != nil {
		return 1
	}
	if err := command.Start(); err != nil {
		return 1
	}
	go func() {
		io.Copy(stdin, in)
		stdin.Close()
	}()
	if err := command.Wait(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		return 1
	}
	return 0
}
