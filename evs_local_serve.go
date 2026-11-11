//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// git-remote-ur and the daemon's git service (§11.11's helper and names rows, §4.10; EVS1-M2-38): git runs
// `git-remote-ur <remote> ur://<net>/<repo>`, which answers capabilities with connect (gitremote-helpers(7)) and, for
// `connect <service>`, dials the daemon's git mode with §5.8's hello {"mode":"git","repo":"<net>/<repo>","service"}
// and pipes git's stdio to the session (EvsGitRemoteHelper). The daemon resolves <net> (CORE's DaemonModeHandler,
// daemon_git.go) and hands the session to EvsClient.ServeGit, which runs the system git-upload-pack or
// git-receive-pack on the repo's bare repository behind the same hooks as the http and ssh fronts.
//
//	<repo>     id:<repo_id>, the id dashed or as 32 hex digits; a display name from the config repo, which waits on the
//	           config repo's repo names and is refused meanwhile, naming the id form
//	mount      the first use creates an implicit mount under <state>, with no working directory and no listener, and
//	           replays the repo's followed refs before the service starts, so a clone needs no prior mount
//	trust      the hello selects a protocol, never a privilege; only a same-uid process reaches the daemon (§5.8's
//	           peer check); the session signs nothing a person must confirm
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A git session's <repo> that names no repo this client can serve.
var ErrEvsGitRepoName = errors.New("evs: a git repo name that names no repo")

// The id form of <repo>.
const evsGitRepoIdPrefix = "id:"

// The repo a git session's <repo> names: id:<repo_id>, dashed or as 32 hex digits. A display name is refused until
// the config repo carries repos' names, the message naming the id form.
func EvsGitRepoOf(repo string) (Id, error) {
	idText, found := strings.CutPrefix(repo, evsGitRepoIdPrefix)
	if !found {
		return Id{}, fmt.Errorf("%w: repos are named id:<repo_id> until the config repo carries their names", ErrEvsGitRepoName)
	}
	if repoId, err := ParseId(idText); err == nil {
		return repoId, nil
	}
	decoded, err := hex.DecodeString(idText)
	if err != nil || len(decoded) != 16 {
		return Id{}, fmt.Errorf("%w: id:<repo_id> takes a repo id", ErrEvsGitRepoName)
	}
	return Id(decoded), nil
}

// The client's mount registry, nil in head mode or before a host builds one.
func (self *EvsClient) mounts() *EvsMounts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	mounts, _ := self.localTier.(*EvsMounts)
	return mounts
}

// The client's mount registry, or ErrEvsNotBuilt when the host built none: what ur mount and git-remote-ur reach.
func (self *EvsClient) Mounts() (*EvsMounts, error) {
	mounts := self.mounts()
	if mounts == nil {
		return nil, fmt.Errorf("%w: this client has no mount registry", ErrEvsNotBuilt)
	}
	return mounts, nil
}

// Serves one git session (DaemonGitService): see the file header. A session that cannot be served gets git's ERR
// line, naming the reason and nothing the caller sent.
func (self *EvsClient) ServeGit(ctx context.Context, session *DaemonGitSession) error {
	mounts := self.mounts()
	if mounts == nil {
		return refuseDaemonGit(session.Stream, "ur: this daemon runs no local git tier for the network")
	}
	repoId, err := EvsGitRepoOf(session.Repo)
	if err != nil {
		return refuseDaemonGit(session.Stream, "ur: "+err.Error())
	}
	mount, ok := mounts.Get(repoId)
	if !ok {
		// the first use: an implicit mount with no directory and no listener, replayed before it serves
		if mount, err = mounts.Add(ctx, repoId, &EvsMountArgs{}); err != nil {
			return refuseDaemonGit(session.Stream, "ur: the repo cannot be mounted")
		}
	}
	if err := mount.sync.ReplayFollowed(ctx); err != nil {
		return refuseDaemonGit(session.Stream, "ur: the repo cannot be read from evs now")
	}
	agent := ""
	if session.Hello != nil {
		agent = session.Hello.Agent
	}
	env := []string{}
	verb := ""
	switch session.Service {
	case daemonGitUploadPack:
		verb = "upload-pack"
	case daemonGitReceivePack:
		verb = "receive-pack"
		receiveSession, closeSession := mounts.OpenReceiveSession(mount, agent)
		defer closeSession()
		env = mounts.ReceiveEnvironment(receiveSession)
	default:
		return refuseDaemonGit(session.Stream, "ur: not a git service")
	}
	if code := evsRunGitService(ctx, mount.git, verb, mount.BareDir, env, session.Stream, session.Stream, io.Discard); code != 0 {
		return fmt.Errorf("evs: git %s exited %d", verb, code)
	}
	return nil
}

// Replays main and every git-mode ref the mount follows: what a session's first use and ur mount add do before git
// reads the bare repository.
func (self *EvsGitSyncEngine) ReplayFollowed(ctx context.Context) error {
	refIds, err := self.followed(ctx)
	if err != nil {
		return err
	}
	for _, refId := range refIds {
		if err := self.Replay(ctx, refId); err != nil {
			return err
		}
	}
	return nil
}

// What git-remote-ur runs on.
type EvsGitRemoteHelperArgs struct {
	// The remote's url, ur://<net>/<repo>.
	Url string
	// Dials the daemon's git mode with the hello {repo: <net>/<repo>, service}, answering the session's stream after
	// the hello's answer.
	Dial   func(ctx context.Context, repo string, service string) (io.ReadWriteCloser, error)
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// The <net>/<repo> of a ur:// url, refusing any other form.
func EvsGitRemoteRepo(url string) (string, error) {
	rest, found := strings.CutPrefix(url, "ur://")
	network, repo, cut := strings.Cut(rest, "/")
	repo = strings.TrimSuffix(repo, "/")
	if !found || !cut || network == "" || repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("%w: a remote is ur://<net>/<repo>", ErrEvsGitRepoName)
	}
	return network + "/" + repo, nil
}

// git-remote-ur's protocol (gitremote-helpers(7)): capabilities answered with connect alone, and connect <service>
// with an empty line once the daemon's session is open, after which git's stdio is the session's until it ends. It
// answers the process's exit code.
func EvsGitRemoteHelper(ctx context.Context, args *EvsGitRemoteHelperArgs) int {
	fail := func(format string, values ...any) int {
		fmt.Fprintf(args.Stderr, "git-remote-ur: "+format+"\n", values...)
		return 1
	}
	repo, err := EvsGitRemoteRepo(args.Url)
	if err != nil {
		return fail("%v", err)
	}
	reader := bufio.NewReader(args.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && line == "" {
				return 0
			}
			return fail("git's command could not be read")
		}
		command := strings.TrimSuffix(line, "\n")
		switch {
		case command == "capabilities":
			if _, err := io.WriteString(args.Stdout, "connect\n\n"); err != nil {
				return fail("git closed the helper")
			}
		case strings.HasPrefix(command, "connect "):
			service := strings.TrimPrefix(command, "connect ")
			if service != daemonGitUploadPack && service != daemonGitReceivePack {
				return fail("no service %q", service)
			}
			stream, err := args.Dial(ctx, repo, service)
			if err != nil {
				return fail("the daemon did not take the session: %v", err)
			}
			defer stream.Close()
			if _, err := io.WriteString(args.Stdout, "\n"); err != nil {
				return fail("git closed the helper")
			}
			go func() {
				io.Copy(stream, reader)
				if closer, ok := stream.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				}
			}()
			if _, err := io.Copy(args.Stdout, stream); err != nil {
				return fail("the session ended early")
			}
			return 0
		case command == "":
			return 0
		default:
			return fail("no command %q", command)
		}
	}
}
