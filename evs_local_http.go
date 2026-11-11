//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// git's http front (§11.11's Binding; I-17, X19; owner decisions 84, 130; plan-EVS1-git-http-credential): `git
// http-backend` behind the daemon's authenticating HTTP front, on the listener DaemonLocalListen binds for git's http.
//
//	where     plain http answers only on 127.0.0.1 and ::1; beyond loopback the listener is a TLS server on the device's
//	          §13 certificate, else a self-signed one whose fingerprint `ur mount` prints (EvsGitSelfSignedTls); a
//	          listener asked to bind off loopback with no certificate is refused at its setup, whatever --listen says
//	who       every caller authenticates, loopback included: Basic with the user ur and the mount's own secret, 32
//	          random bytes drawn at the first ur mount add and kept sealed in the evs component's store, its hex
//	          compared in constant time; git-credential-ur hands git that secret over the daemon's peer-checked socket
//	          (ur mount's), so it never enters a remote url, an environment variable or a log
//	Host      a request reaches git only with a Host the listener answers to (DaemonLocalListener.HttpHandler), which
//	          stops a DNS-rebinding page
//	CGI       the environment is built here, never inherited from the daemon: the git runner's clean variables, CGI's
//	          own, GIT_PROJECT_ROOT at the network's git tree, and for a receive-pack a receive session's UR_GIT_SESSION
//	          so the mount's hooks reach the daemon
//
// A repo is /<repo_id hex>.git, the bare repository's own name under the network's git tree; any other path is 404.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The user Basic names on every mount (plan-EVS1-git-http-credential).
const EvsGitHttpUser = "ur"

// The mount's Basic password: its secret's hex, empty for a mount with none, which serves nothing over http.
func (self *EvsLocalRepo) HttpPassword() string {
	if len(self.httpSecret) == 0 {
		return ""
	}
	return hex.EncodeToString(self.httpSecret)
}

// What the http front serves on.
type EvsGitHttpFrontArgs struct {
	Mounts *EvsMounts
	// The listener of DaemonLocalGitHttp, which decides plaintext or TLS per connection; any net.Listener a test
	// gives, which the front serves as it comes.
	Listener net.Listener
	// The names beyond localhost and the bound addresses the front answers to: the device's §13 names.
	Hosts []string
}

// git's http front.
type EvsGitHttpFront struct {
	mounts *EvsMounts
	server *http.Server
	// the listener, when it is the daemon's
	local *DaemonLocalListener
}

// The front over args.Listener; Serve runs it.
func NewEvsGitHttpFront(args *EvsGitHttpFrontArgs) (*EvsGitHttpFront, error) {
	if args == nil || args.Mounts == nil || args.Listener == nil {
		return nil, fmt.Errorf("%w: git's http front needs its mounts and a listener", errInvalidSettings)
	}
	self := &EvsGitHttpFront{mounts: args.Mounts}
	var handler http.Handler = http.HandlerFunc(self.serveGit)
	local, isLocal := args.Listener.(*DaemonLocalListener)
	if isLocal {
		self.local = local
		handler = local.HttpHandler(handler, args.Hosts, self.authenticate)
	} else {
		handler = evsGitHostChecked(handler, args.Listener, args.Hosts, self.authenticate)
	}
	self.server = &http.Server{Handler: handler, ReadHeaderTimeout: args.Mounts.client.settings.RequestTimeout}
	return self, nil
}

// Serves until Close; a closed listener ends it with nil.
func (self *EvsGitHttpFront) Serve(listener net.Listener) error {
	err := self.server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Stops serving.
func (self *EvsGitHttpFront) Close() error {
	return self.server.Close()
}

// The Host and authentication checks DaemonLocalListener.HttpHandler makes, over a listener that is not the daemon's:
// localhost, the loopback addresses and the bound one, and hosts, with or without the port.
func evsGitHostChecked(handler http.Handler, listener net.Listener, hosts []string, authenticate func(request *http.Request) bool) http.Handler {
	port := ""
	allowed := map[string]bool{}
	if tcpAddress, ok := listener.Addr().(*net.TCPAddr); ok {
		port = strconv.Itoa(tcpAddress.Port)
		hosts = append(hosts, tcpAddress.IP.String())
	}
	for _, host := range append([]string{"localhost", "127.0.0.1", "::1"}, hosts...) {
		allowed[strings.ToLower(host)] = true
		allowed[strings.ToLower(net.JoinHostPort(host, port))] = true
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.ToLower(request.Host)
		if unbracketed, ok := strings.CutSuffix(strings.TrimPrefix(host, "["), "]"); ok && strings.HasPrefix(host, "[") {
			host = unbracketed
		}
		if !allowed[host] {
			http.Error(writer, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		if !authenticate(request) {
			writer.Header().Set("WWW-Authenticate", `Basic realm="ur"`)
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(writer, request)
	})
}

// The mount a request's path names, /<repo_id hex>.git/..., and the path's rest: false for any other.
func (self *EvsGitHttpFront) mountOf(path string) (*EvsLocalRepo, bool) {
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	idText, found := strings.CutSuffix(first, evsLocalBareRepoExtension)
	if !found {
		return nil, false
	}
	decoded, err := hex.DecodeString(idText)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != idText {
		return nil, false
	}
	return self.mounts.Get(Id(decoded))
}

// Basic with the user ur and the mount's own secret, compared in constant time (I-17: loopback included).
func (self *EvsGitHttpFront) authenticate(request *http.Request) bool {
	mount, ok := self.mountOf(request.URL.Path)
	if !ok {
		return false
	}
	user, password, ok := request.BasicAuth()
	want := mount.HttpPassword()
	if !ok || want == "" {
		return false
	}
	userOk := subtle.ConstantTimeCompare([]byte(user), []byte(EvsGitHttpUser)) == 1
	passwordOk := subtle.ConstantTimeCompare([]byte(password), []byte(want)) == 1
	return userOk && passwordOk
}

// One request through git http-backend as CGI, its environment built here (see the file header).
func (self *EvsGitHttpFront) serveGit(writer http.ResponseWriter, request *http.Request) {
	mount, ok := self.mountOf(request.URL.Path)
	if !ok || strings.Contains(request.URL.Path, "..") {
		http.NotFound(writer, request)
		return
	}
	git := mount.git
	env := git.Environment(
		"GATEWAY_INTERFACE=CGI/1.1",
		"SERVER_PROTOCOL="+request.Proto,
		"REQUEST_METHOD="+request.Method,
		"PATH_INFO="+request.URL.Path,
		"QUERY_STRING="+request.URL.RawQuery,
		"GIT_PROJECT_ROOT="+self.mounts.gitTree,
		"GIT_HTTP_EXPORT_ALL=1",
		"REMOTE_USER="+EvsGitHttpUser,
		"REMOTE_ADDR=127.0.0.1",
	)
	if contentType := request.Header.Get("Content-Type"); contentType != "" {
		env = append(env, "CONTENT_TYPE="+contentType)
	}
	if 0 <= request.ContentLength {
		env = append(env, "CONTENT_LENGTH="+strconv.FormatInt(request.ContentLength, 10))
	}
	if encoding := request.Header.Get("Content-Encoding"); encoding != "" {
		env = append(env, "HTTP_CONTENT_ENCODING="+encoding)
	}
	if protocol := request.Header.Get("Git-Protocol"); protocol != "" {
		env = append(env, "HTTP_GIT_PROTOCOL="+protocol)
	}
	if strings.HasSuffix(request.URL.Path, "/git-receive-pack") || request.URL.Query().Get("service") == daemonGitReceivePack {
		session, closeSession := self.mounts.OpenReceiveSession(mount, "")
		defer closeSession()
		env = append(env, self.mounts.ReceiveEnvironment(session)...)
	}
	if err := evsServeCgi(request.Context(), writer, request.Body, git.Path(), []string{"http-backend"}, env, git.home); err != nil {
		if self.mounts.client.log.V(1).Enabled() {
			self.mounts.client.log.Infof("[evs]git http-backend: %v", err)
		}
	}
}

// Runs program as a CGI script with env, input as its body, and writes its answer: the status and headers it prints
// before the blank line, then the rest as the body.
func evsServeCgi(ctx context.Context, writer http.ResponseWriter, input io.Reader, program string, args []string, env []string, dir string) error {
	command := exec.CommandContext(ctx, program, args...)
	command.Env = env
	command.Dir = dir
	command.Stdin = input
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		http.Error(writer, "the git backend did not start", http.StatusInternalServerError)
		return err
	}
	if err := command.Start(); err != nil {
		http.Error(writer, "the git backend did not start", http.StatusInternalServerError)
		return err
	}
	reader := bufio.NewReaderSize(stdout, 64*1024)
	header, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		command.Process.Kill()
		command.Wait()
		http.Error(writer, "the git backend answered no headers", http.StatusBadGateway)
		return err
	}
	status := http.StatusOK
	if text := header.Get("Status"); text != "" {
		code, _, _ := strings.Cut(text, " ")
		if parsed, err := strconv.Atoi(code); err == nil {
			status = parsed
		}
		header.Del("Status")
	}
	for name, values := range header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(status)
	if _, err := io.Copy(writer, reader); err != nil {
		command.Process.Kill()
	}
	return command.Wait()
}

// A self-signed TLS server certificate for hosts, ECDSA P-256 and valid a year, and its SHA-256 fingerprint in hex:
// what an off-loopback listener serves when the device holds no §13 certificate, `ur mount` printing the fingerprint so
// a client pins it.
func EvsGitSelfSignedTls(hosts []string, now time.Time) (*tls.Config, string, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, "", nil, err
	}
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, "", nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ur mount"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", nil, err
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", nil, err
	}
	testHookSecret("evs_git_tls_key", keyDer)
	fingerprint := sha256.Sum256(der)
	config := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	return config, hex.EncodeToString(fingerprint[:]), der, nil
}
