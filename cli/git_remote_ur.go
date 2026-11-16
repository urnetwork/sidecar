// git-remote-ur (§4.10, §11.11's helper and names rows; EVS1-M2-38): ur run by git as git-remote-ur, by its argv[0],
// for a remote ur://<net>/<repo>. It answers capabilities with connect and pipes git's stdio to §5.8's git hello
// {"mode":"git","repo":"<net>/<repo>","service"} on the instance's daemon, which it spawns when none answers, as ur's
// commands do (sidecar.EvsGitRemoteHelper). The instance is UR_INSTANCE's, git passing no flag of ours. The Windows zip
// carries a copy of ur.exe named git-remote-ur.exe, which commands.go's argv[0] check takes in any case.
//
// The daemon's side is the git service this file assigns: EvsClient.ServeGit on the session's network's evs client,
// which ur daemon's composition builds per network (daemon_clients.go) and answers once the network's config follower
// stands. Before that, or with urDaemonEvsClient unset, a git session gets git's ERR line saying why.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urnetwork/sidecar"
)

func init() {
	urGitRemoteEntry = runGitRemoteUr
	urDaemonGitService = urServeGit
}

// A hosted Sidecar's evs client: the daemon's composition's (daemon_clients.go), once the network's config follower
// stands. Nil, as a test may set it: git sessions are refused with git's ERR line, and ur mount and the ur evs commands
// refuse, saying so.
var urDaemonEvsClient func(running *sidecar.Sidecar) (*sidecar.EvsClient, error)

// What the evs commands answer while the daemon builds no evs client.
var errUrNoEvsClient = errors.New("this daemon builds no evs client for its network yet, so it serves no repo")

// A daemon session's stream, closed with its client.
type urDaemonStream struct {
	io.ReadWriter
	client *sidecar.DaemonClient
}

// Ends the session.
func (self *urDaemonStream) Close() error {
	return self.client.Close()
}

// The git service the daemon's git mode hands each session to.
func urServeGit(ctx context.Context, session *sidecar.DaemonGitSession) error {
	if urDaemonEvsClient == nil {
		return urRefuseGit(session.Stream, "ur: "+errUrNoEvsClient.Error())
	}
	client, err := urDaemonEvsClient(session.Sidecar)
	if err != nil {
		return urRefuseGit(session.Stream, "ur: "+err.Error())
	}
	return client.ServeGit(ctx, session)
}

// Writes git's ERR pkt-line with message.
func urRefuseGit(stream io.Writer, message string) error {
	line, err := sidecar.EvsPktLine{Kind: sidecar.EvsPktLineData, Payload: []byte("ERR " + message + "\n")}.Encode()
	if err == nil {
		stream.Write(line)
	}
	return sidecar.ErrDaemonGitRefused
}

// git-remote-ur <remote> <url>: see the file header.
func runGitRemoteUr(ctx context.Context, cli *urCli, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(cli.stderr, "git-remote-ur: git runs this as git-remote-ur <remote> <url>")
		return urExitUsage
	}
	instance, err := sidecar.SidecarInstanceName(cli.getenv("UR_INSTANCE"))
	if err != nil {
		fmt.Fprintf(cli.stderr, "git-remote-ur: %s\n", err)
		return urExitUsage
	}
	cli.instance = instance
	// the clone's git-lfs agent, written from GIT_DIR during the fetch so the first checkout's smudge finds it
	// (§11.11's agent row); a clone it cannot configure still fetches, and the tip check refuses what never arrived
	if err := urConfigureRemoteLfs(ctx, cli, args[1]); err != nil {
		fmt.Fprintf(cli.stderr, "git-remote-ur: git-lfs's agent is not configured: %s\n", err)
	}
	return sidecar.EvsGitRemoteHelper(ctx, &sidecar.EvsGitRemoteHelperArgs{
		Url: args[1],
		Dial: func(ctx context.Context, repo string, service string) (io.ReadWriteCloser, error) {
			hello := cli.hello(sidecar.DaemonModeGit)
			hello.Repo, hello.Service = repo, service
			client, err := cli.connectDaemon(ctx, hello, nil)
			if err != nil {
				return nil, err
			}
			return &urDaemonStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Stdin:  cli.stdin,
		Stdout: cli.stdout,
		Stderr: cli.stderr,
	})
}

// Writes the git-lfs agent's keys into the config of the clone git runs this helper for, GIT_DIR's, naming this ur
// and the url's repo. Nothing without GIT_DIR, which git sets for a remote helper.
func urConfigureRemoteLfs(ctx context.Context, cli *urCli, url string) error {
	gitDir := cli.getenv("GIT_DIR")
	if gitDir == "" {
		return nil
	}
	repo, err := sidecar.EvsGitRemoteRepo(url)
	if err != nil {
		return err
	}
	gitDir, err = filepath.Abs(gitDir)
	if err != nil {
		return err
	}
	urPath, err := os.Executable()
	if err != nil {
		return err
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return err
	}
	if gitPath, err = filepath.Abs(gitPath); err != nil {
		return err
	}
	runner, err := sidecar.NewEvsGitRunner(ctx, gitPath, os.TempDir(), sidecar.DefaultEvsSettings(), nil)
	if err != nil {
		return err
	}
	return sidecar.EvsLfsConfigureClone(ctx, runner, gitDir, urPath, sidecar.EvsLfsAgentArgsFor(repo))
}
