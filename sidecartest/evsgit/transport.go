//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// git's transports in the git world besides its local one (§4.10, §11.11's Binding and helper rows; I-17, X19; FS-73,
// §22.9's git-lfs row, EVS2-M10-29): a device serves its mounts to stock git over plain http on loopback and over ssh,
// as ur daemon's listeners do, each started at its first use and served until the test ends, and to git-remote-ur
// through its daemon's git mode, so a clause pushes and fetches through the same receive path, hooks and tip check over
// each transport a daemon serves. A clone over http authenticates as the mount, with the Basic header
// git-credential-ur gives git; one over ssh with a key the front maps to the sidecar, the host key pinned; one of a
// ur:// remote runs the world's git-remote-ur (WorldSettings.RemoteHelperCommand), which git finds first on the
// device's PATH, as ur's install puts it beside ur.
//
//	ur        a test binary that builds a world names a test of its own in WorldSettings.RemoteHelperCommand which
//	          calls RemoteHelper: the root's helper protocol (sidecar.EvsGitRemoteHelper) dialing the daemon whose
//	          socket RemoteSocketVariable names in git mode, as ur does as git-remote-ur (cli/git_remote_ur.go, a
//	          package this one cannot import); the daemon hands the session to the device's client's git service
//	          (EvsClient.ServeGit). The daemon hosts no Sidecar, so <net> is not resolved among hosted networks, which
//	          NewDaemonGitMode does and daemon_git_test.go holds; and the clone's git-lfs agent is configured as
//	          CloneOver configures every clone's, not from GIT_DIR during the fetch, which is cli's own step

package evsgit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
)

// The transports a clone takes besides git's local one.
const (
	TransportHttp = "http"
	TransportSsh  = "ssh"
	TransportUr   = "ur"
)

// The environment variable naming the daemon socket git-remote-ur dials.
const RemoteSocketVariable = "UR_TEST_EVS_GIT_REMOTE_SOCKET"

// The <net> a world's ur:// remotes name, which its daemons do not resolve (see the file header).
const remoteNetworkLabel = "world.test"

// A remote of the device's repo over transport: its url and the config a clone of it keeps.
type deviceRemote struct {
	url    string
	config [][]string
}

// The device's remote over transport, its front started at the first ask; nil and why when this host cannot serve it.
func (self *Device) remote(transport string) (*deviceRemote, string) {
	t := self.world.t
	t.Helper()
	self.remotesLock.Lock()
	defer self.remotesLock.Unlock()
	if remote, ok := self.remotes[transport]; ok {
		return remote, ""
	}
	var remote *deviceRemote
	switch transport {
	case TransportHttp:
		remote = self.serveHttp()
	case TransportSsh:
		sshPath, err := exec.LookPath("ssh")
		if err != nil {
			return nil, "no ssh client on this host"
		}
		remote = self.serveSsh(sshPath)
	case TransportUr:
		remote = self.serveUr()
	default:
		t.Fatalf("no transport %q", transport)
	}
	if self.remotes == nil {
		self.remotes = map[string]*deviceRemote{}
	}
	self.remotes[transport] = remote
	return remote, ""
}

// git's http front on loopback, as DaemonLocalListen binds it for git's http, its caller the mount's Basic credential.
func (self *Device) serveHttp() *deviceRemote {
	t := self.world.t
	t.Helper()
	listener, err := sidecar.DaemonLocalListen(&sidecar.DaemonLocalListenArgs{Service: sidecar.DaemonLocalGitHttp, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	front, err := sidecar.NewEvsGitHttpFront(&sidecar.EvsGitHttpFrontArgs{Mounts: self.Mounts, Listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- front.Serve(listener) }()
	t.Cleanup(func() {
		front.Close()
		<-served
	})
	password := self.Mount.HttpPassword()
	if password == "" {
		t.Fatal("a mount with no http secret serves nothing over http")
	}
	header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(sidecar.EvsGitHttpUser+":"+password))
	return &deviceRemote{
		url:    "http://127.0.0.1:" + strconv.Itoa(listener.Port()) + "/" + filepath.Base(self.Mount.BareDir),
		config: [][]string{{"http.extraHeader", header}},
	}
}

// git's ssh front on loopback, a key of the device's own mapped to the sidecar, and the ssh command at sshPath that
// pins its host key.
func (self *Device) serveSsh(sshPath string) *deviceRemote {
	t := self.world.t
	t.Helper()
	hostKey, err := self.Mounts.SshHostKey()
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(self.directory, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	authorized, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front, err := sidecar.NewEvsGitSshFront(&sidecar.EvsGitSshFrontArgs{
		Mounts: self.Mounts, Listener: listener, HostKey: hostKey,
		AuthorizedKey: func(key ssh.PublicKey) (string, bool) {
			return "", bytes.Equal(key.Marshal(), authorized.Marshal())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- front.Serve(context.Background()) }()
	t.Cleanup(func() {
		front.Close()
		<-served
	})
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	knownHosts := filepath.Join(self.directory, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("[127.0.0.1]:"+port+" "+sidecar.EvsGitSshHostKeyLine(hostKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf("%s -F /dev/null -i %s -o IdentitiesOnly=yes -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -o BatchMode=yes", sshPath, keyPath, knownHosts)
	return &deviceRemote{
		url:    "ssh://ur@127.0.0.1:" + port + "/" + filepath.Base(self.Mount.BareDir),
		config: [][]string{{"core.sshCommand", command}},
	}
}

// The repo's ur:// remote, ur://<net>/id:<repo_id>, which the world's git-remote-ur on the device's PATH serves through
// its daemon's git mode.
func (self *Device) serveUr() *deviceRemote {
	t := self.world.t
	t.Helper()
	if len(self.world.settings.RemoteHelperCommand) == 0 {
		t.Fatal("a world with no git-remote-ur helper serves no ur:// remote")
	}
	return &deviceRemote{url: "ur://" + remoteNetworkLabel + "/id:" + self.world.repoId.String()}
}

// git-remote-ur on the device's PATH: a script that execs the world's helper command with git's <remote> and <url>.
// Called while the device is made, in a world with a helper command.
func (self *Device) installRemoteHelper() {
	t := self.world.t
	t.Helper()
	if err := os.MkdirAll(self.urBin(), 0o700); err != nil {
		t.Fatal(err)
	}
	quoted := []string{}
	for _, arg := range self.world.settings.RemoteHelperCommand {
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", `'\''`)+"'")
	}
	script := "#!/bin/sh\nexec " + strings.Join(quoted, " ") + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(self.urBin(), "git-remote-ur"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// Where the device keeps the git-remote-ur its git finds first.
func (self *Device) urBin() string {
	return filepath.Join(self.directory, "ur-bin")
}

// The environment a device's git runs with in a world with git-remote-ur: the socket its helper dials. Empty without.
func (self *Device) remoteEnvironment() []string {
	if len(self.world.settings.RemoteHelperCommand) == 0 {
		return nil
	}
	return []string{RemoteSocketVariable + "=" + self.socket}
}

// A clone of the device's repo over transport, as Clone makes one over git's local transport: its committer this
// device's client, git-lfs's agent configured before the checkout, and the remote's config kept for later fetches and
// pushes. Empty and why when this host cannot serve transport.
func (self *Device) CloneOver(transport string) (string, string) {
	t := self.world.t
	t.Helper()
	remote, skip := self.remote(transport)
	if remote == nil {
		return "", skip
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "clone")
	cloneArgs := []string{}
	for _, setting := range remote.config {
		cloneArgs = append(cloneArgs, "-c", setting[0]+"="+setting[1])
	}
	cloneArgs = append(cloneArgs, "clone", "-q", "--no-checkout", remote.url, dir)
	if out, ok := self.GitIn(parent, nil, cloneArgs...); !ok {
		t.Fatalf("a clone over %s: %s", transport, out)
	}
	for _, setting := range append([][]string{
		{"user.name", self.Label}, {"user.email", self.Email()}, {"committer.name", self.Label}, {"committer.email", self.Email()},
	}, remote.config...) {
		self.MustGit(dir, "config", setting[0], setting[1])
	}
	if self.world.settings.Lfs != nil {
		self.configureLfs(dir)
	}
	if _, born := self.GitIn(dir, nil, "rev-parse", "--verify", "-q", "HEAD"); born {
		self.MustGit(dir, "checkout", "-q")
	}
	return dir, ""
}

// The test a WorldSettings.RemoteHelperCommand names: git-remote-ur <remote> <url> for one git, speaking the helper's
// protocol to the daemon whose socket RemoteSocketVariable names, in git mode, then exiting with the protocol's code.
// It returns at once when the variable is unset, so the test passes as itself.
func RemoteHelper() {
	socket := os.Getenv(RemoteSocketVariable)
	if socket == "" {
		return
	}
	code := sidecar.EvsGitRemoteHelper(context.Background(), &sidecar.EvsGitRemoteHelperArgs{
		Url: os.Args[len(os.Args)-1],
		Dial: func(ctx context.Context, repo string, service string) (io.ReadWriteCloser, error) {
			client, err := sidecar.DialDaemon(ctx, socket, &sidecar.DaemonHello{Mode: sidecar.DaemonModeGit, Version: daemonVersion, Repo: repo, Service: service})
			if err != nil {
				return nil, err
			}
			return &daemonStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	os.Exit(code)
}
