//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// EVS1-M2-37's tests (§22.5's §5 row): stock git clones and pushes over plain http on loopback, https on a
// self-signed certificate, and ssh; every caller authenticates, a wrong Host is refused, an unknown ssh key is
// refused, and an http listener asked to bind off loopback with no certificate is refused at its setup.

package sidecar

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Runs git with args and env added to a clean one, answering its output and whether it succeeded.
func evsTestGitWith(t *testing.T, env []string, args ...string) (string, bool) {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	command := exec.Command(gitPath, args...)
	command.Env = append([]string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")}, env...)
	out, err := command.CombinedOutput()
	return string(out), err == nil
}

// The http front over listener, served until the test ends.
func evsTestHttpFront(t *testing.T, receiver *evsTestReceiver, listener net.Listener) {
	t.Helper()
	front, err := NewEvsGitHttpFront(&EvsGitHttpFrontArgs{Mounts: receiver.mounts, Listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- front.Serve(listener) }()
	t.Cleanup(func() {
		front.Close()
		<-served
	})
}

// The Basic header git sends for the mount, which the credential helper gives git in production.
func evsTestBasicHeader(receiver *evsTestReceiver) string {
	return "http.extraHeader=Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(EvsGitHttpUser+":"+receiver.mount.HttpPassword()))
}

// Plain http on loopback: a clone, a commit and a push through the hooks, evs taking it.
func TestEvsLocalHttpCloneAndPushOnLoopback(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalGitHttp, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	evsTestHttpFront(t, receiver, listener)
	url := "http://127.0.0.1:" + strconv.Itoa(listener.Port()) + "/" + evsUrlId(receiver.mount.RepoId) + ".git"
	dir := filepath.Join(t.TempDir(), "clone")
	if out, ok := evsTestGitWith(t, nil, "-c", evsTestBasicHeader(receiver), "clone", "-q", url, dir); !ok {
		t.Fatalf("the clone: %s", out)
	}
	for _, setting := range [][]string{{"user.name", "agent one"}, {"user.email", publisher.email}, {"http.extraHeader", strings.TrimPrefix(evsTestBasicHeader(receiver), "http.extraHeader=")}} {
		evsTestGit(t, dir, "config", setting[0], setting[1])
	}
	c1 := receiver.commit(dir, map[string]string{"a.txt": "over http\n"})
	if out, ok := evsTestGitWith(t, nil, "-C", dir, "push", "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
	if version := receiver.headVersion("main"); version != 1 {
		t.Fatalf("evs's head %d", version)
	}
}

// Every caller authenticates, loopback included; a wrong Host is refused before authentication; a repo no mount
// serves answers nothing.
func TestEvsLocalHttpRefusals(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalGitHttp, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	evsTestHttpFront(t, receiver, listener)
	base := "http://127.0.0.1:" + strconv.Itoa(listener.Port())
	path := "/" + evsUrlId(receiver.mount.RepoId) + ".git/info/refs?service=git-upload-pack"
	get := func(host string, user string, password string, path string) int {
		request, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			request.Host = host
		}
		if user != "" {
			request.SetBasicAuth(user, password)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	password := receiver.mount.HttpPassword()
	cases := []struct {
		name     string
		host     string
		user     string
		password string
		path     string
		want     int
	}{
		{name: "no credential", want: http.StatusUnauthorized, path: path},
		{name: "a wrong password", user: EvsGitHttpUser, password: strings.Repeat("0", len(password)), want: http.StatusUnauthorized, path: path},
		{name: "a wrong user", user: "root", password: password, want: http.StatusUnauthorized, path: path},
		{name: "a wrong Host", host: "attacker.example", user: EvsGitHttpUser, password: password, want: http.StatusMisdirectedRequest, path: path},
		{name: "a repo no mount serves", user: EvsGitHttpUser, password: password, want: http.StatusUnauthorized, path: "/" + evsUrlId(evsTestId("other repo")) + ".git/info/refs"},
		{name: "the mount's credential", user: EvsGitHttpUser, password: password, want: http.StatusOK, path: path},
	}
	for _, c := range cases {
		if got := get(c.host, c.user, c.password, c.path); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// https on a self-signed certificate, which the client pins as its CA: a clone and a push.
func TestEvsLocalHttpsOnASelfSignedCertificate(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	config, fingerprint, der, err := EvsGitSelfSignedTls([]string{"127.0.0.1"}, publisher.writer.test.clock.Now())
	if err != nil || len(fingerprint) != 64 {
		t.Fatalf("the certificate %q %v", fingerprint, err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(inner, config)
	evsTestHttpFront(t, receiver, listener)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	url := "https://127.0.0.1:" + strconv.Itoa(inner.Addr().(*net.TCPAddr).Port) + "/" + evsUrlId(receiver.mount.RepoId) + ".git"
	dir := filepath.Join(t.TempDir(), "clone")
	if out, ok := evsTestGitWith(t, nil, "-c", "http.sslCAInfo="+caPath, "-c", evsTestBasicHeader(receiver), "clone", "-q", url, dir); !ok {
		t.Fatalf("the clone: %s", out)
	}
	for _, setting := range [][]string{{"user.name", "agent one"}, {"user.email", publisher.email}, {"http.sslCAInfo", caPath},
		{"http.extraHeader", strings.TrimPrefix(evsTestBasicHeader(receiver), "http.extraHeader=")}} {
		evsTestGit(t, dir, "config", setting[0], setting[1])
	}
	c1 := receiver.commit(dir, map[string]string{"a.txt": "over https\n"})
	if out, ok := evsTestGitWith(t, nil, "-C", dir, "push", "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
}

// An http listener asked to bind off loopback with no certificate is refused before it binds anything: no plaintext
// setup reaches past this host.
func TestEvsLocalHttpOffLoopbackWithoutTlsRefused(t *testing.T) {
	if _, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalGitHttp, Listen: []string{"192.0.2.1"}}); !errors.Is(err, ErrDaemonLocalPlaintext) {
		t.Fatalf("an off-loopback plaintext listener: %v", err)
	}
}

// A client's ssh key, its private half in OpenSSH form at a 0600 file.
func evsTestSshKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return path, sshPublic
}

// The ssh front over a loopback listener, the authorized key mapped to the sidecar, served until the test ends, and
// the GIT_SSH_COMMAND a client of keyPath uses, pinning the host key.
func evsTestSshFront(t *testing.T, receiver *evsTestReceiver, authorized ssh.PublicKey, keyPath string) (string, string) {
	t.Helper()
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh client")
	}
	hostKey, err := receiver.mounts.SshHostKey()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front, err := NewEvsGitSshFront(&EvsGitSshFrontArgs{
		Mounts: receiver.mounts, Listener: listener, HostKey: hostKey,
		AuthorizedKey: func(key ssh.PublicKey) (string, bool) {
			return "", string(key.Marshal()) == string(authorized.Marshal())
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
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("[127.0.0.1]:"+port+" "+EvsGitSshHostKeyLine(hostKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := sshPath + " -F /dev/null -i " + keyPath + " -o IdentitiesOnly=yes -o UserKnownHostsFile=" + knownHosts +
		" -o StrictHostKeyChecking=yes -o BatchMode=yes"
	url := "ssh://ur@127.0.0.1:" + port + "/" + evsUrlId(receiver.mount.RepoId) + ".git"
	return command, url
}

// ssh with an authorized key: a clone and a push through the hooks; an unknown key is refused.
func TestEvsLocalSshCloneAndPush(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	keyPath, public := evsTestSshKey(t)
	command, url := evsTestSshFront(t, receiver, public, keyPath)
	dir := filepath.Join(t.TempDir(), "clone")
	env := []string{"GIT_SSH_COMMAND=" + command}
	if out, ok := evsTestGitWith(t, env, "clone", "-q", url, dir); !ok {
		t.Fatalf("the clone: %s", out)
	}
	evsTestGit(t, dir, "config", "user.name", "agent one")
	evsTestGit(t, dir, "config", "user.email", publisher.email)
	c1 := receiver.commit(dir, map[string]string{"a.txt": "over ssh\n"})
	if out, ok := evsTestGitWith(t, env, "-C", dir, "push", "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
	strangerPath, _ := evsTestSshKey(t)
	stranger := strings.Replace(command, "-i "+keyPath, "-i "+strangerPath, 1)
	if out, ok := evsTestGitWith(t, []string{"GIT_SSH_COMMAND=" + stranger}, "clone", "-q", url, filepath.Join(t.TempDir(), "stranger")); ok {
		t.Fatalf("an unknown key cloned: %s", out)
	}
}
