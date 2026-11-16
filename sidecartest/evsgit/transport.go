//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// git's http and ssh fronts in the git world (§11.11's Binding; I-17, X19; FS-73, EVS2-M10-29): a device serves its
// mounts to stock git over plain http on loopback and over ssh, as ur daemon's listeners do, each started at its first
// use and served until the test ends, so a clause pushes and fetches through the same receive path, hooks and tip check
// over each of git's transports a daemon serves. A clone over http authenticates as the mount, with the Basic header
// git-credential-ur gives git; one over ssh with a key the front maps to the sidecar, the host key pinned.

package evsgit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
)

// The transports a clone takes besides git's local one.
const (
	TransportHttp = "http"
	TransportSsh  = "ssh"
)

// A remote of the device's repo over transport: its url and the config a clone of it keeps.
type deviceRemote struct {
	url    string
	config [][]string
}

// The device's remote over transport, its front started at the first ask.
func (self *Device) remote(transport string) *deviceRemote {
	t := self.world.t
	t.Helper()
	self.remotesLock.Lock()
	defer self.remotesLock.Unlock()
	if remote, ok := self.remotes[transport]; ok {
		return remote
	}
	var remote *deviceRemote
	switch transport {
	case TransportHttp:
		remote = self.serveHttp()
	case TransportSsh:
		remote = self.serveSsh()
	default:
		t.Fatalf("no transport %q", transport)
	}
	if self.remotes == nil {
		self.remotes = map[string]*deviceRemote{}
	}
	self.remotes[transport] = remote
	return remote
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

// git's ssh front on loopback, a key of the device's own mapped to the sidecar, and the ssh command that pins its host
// key.
func (self *Device) serveSsh() *deviceRemote {
	t := self.world.t
	t.Helper()
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh client on this host")
	}
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

// A clone of the device's repo over transport, as Clone makes one over git's local transport: its committer this
// device's client, git-lfs's agent configured before the checkout, and the remote's config kept for later fetches and
// pushes.
func (self *Device) CloneOver(transport string) string {
	t := self.world.t
	t.Helper()
	remote := self.remote(transport)
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
	return dir
}
