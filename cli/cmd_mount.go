// ur mount (§11.11, owner decision 24; EVS1-M2-38) and git's credential helper for a mount's http front
// (plan-EVS1-git-http-credential):
//
//	ur mount add <dir> --repo=<repo_id> [--agent=<label>]   mounts the repo for stock git, the daemon serving it from a
//	                                                        plain bare repository, its committer set in <dir>'s clone
//	ur mount share <dir> <member_id>                        files a RepoGrant, or an EvsShare for an owner-bound kind
//	ur git-credential <operation>                           git's credential helper: Basic's user and the mount's
//	                                                        secret for a host the daemon serves, over its peer-checked
//	                                                        socket, never a url or an environment variable
//
// A mount's work is the daemon's, through its control methods over the network's evs client, which ur daemon's
// composition builds once a host makes one per network (CORE's): until then the methods refuse, saying so. ur mount add
// without --repo would create the repo, which files §8.8's RepoCreate through the core's statement poster
// (CORE-M2-02); until that lands it takes an existing repo's id. ur mount share files through the same poster and
// refuses until it lands. The add prints the ssh host key a client pins; the http front's port and the fingerprint
// of a self-signed certificate are printed by the listener that serves them (EVS1-M2-37's).

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur mount and ur git-credential call.
const (
	urMethodMountAdd      = "evs.mount.add"
	urMethodGitCredential = "evs.git.credential"
)

func init() {
	registerUrCommand(&urCommand{
		name: "mount",
		usage: strings.Join([]string{
			"  ur mount add <dir> --repo=<repo_id> [--agent=<label>]",
			"  ur mount share <dir> <member_id>",
		}, "\n"),
		summary: "serve a repo to stock git from a local bare repository, which the daemon keeps in sync with evs",
		run:     runUrMount,
	})
	registerUrCommand(&urCommand{
		name:    "git-credential",
		usage:   "  ur git-credential <operation>",
		summary: "git's credential helper for a mount's http front, which ur mount add configures",
		run:     runUrGitCredential,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urMountMethods)
}

// What the evs methods act on: the only hosted network's evs client.
type urEvsTarget interface {
	evsClient() (*sidecar.EvsClient, error)
}

// The only hosted network's evs client, which the daemon's composition builds (urDaemonEvsClient).
func (self *urDaemonNetwork) evsClient() (*sidecar.EvsClient, error) {
	if urDaemonEvsClient == nil {
		return nil, errUrNoEvsClient
	}
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return urDaemonEvsClient(running)
}

// evs.mount.add's params and reply.
type urMountAddParams struct {
	Dir    string `json:"dir"`
	RepoId string `json:"repo_id"`
	Agent  string `json:"agent,omitempty"`
}

type urMountAddReply struct {
	RepoId  string `json:"repo_id"`
	BareDir string `json:"bare_dir"`
	// The ssh host key's known_hosts line.
	SshHostKey string `json:"ssh_host_key,omitempty"`
}

// evs.git.credential's params and reply: git's credential fields, and Basic's user and password.
type urGitCredentialParams struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Path     string `json:"path"`
}

type urGitCredentialReply struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// The mount methods over target, when it hosts a Sidecar.
func urMountMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodMountAdd,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urMountAddParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				repoId, err := sidecar.EvsGitRepoOf("id:" + params.RepoId)
				if err != nil {
					return nil, errors.New("a mount takes --repo=<repo_id> until ur can create a repo")
				}
				if !filepath.IsAbs(params.Dir) {
					return nil, errors.New("a mount names its directory by an absolute path")
				}
				client, err := evs.evsClient()
				if err != nil {
					return nil, err
				}
				mounts, err := client.Mounts()
				if err != nil {
					return nil, err
				}
				mount, err := mounts.Add(ctx, repoId, &sidecar.EvsMountArgs{Dir: params.Dir, AgentLabel: params.Agent})
				if err != nil {
					return nil, err
				}
				if err := mount.Sync().ReplayFollowed(ctx); err != nil {
					return nil, fmt.Errorf("the repo is mounted and its first sync did not finish: %w", err)
				}
				reply := &urMountAddReply{RepoId: repoId.String(), BareDir: mount.BareDir}
				if hostKey, err := mounts.SshHostKey(); err == nil {
					reply.SshHostKey = sidecar.EvsGitSshHostKeyLine(hostKey)
				}
				return reply, nil
			},
		},
		{
			Name: urMethodGitCredential,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urGitCredentialParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				client, err := evs.evsClient()
				if err != nil {
					return nil, err
				}
				mounts, err := client.Mounts()
				if err != nil {
					return nil, err
				}
				return urGitCredentialOf(mounts, params), nil
			},
		},
	}
}

// Basic's user and the mount's secret for a host the daemon serves and a path naming a mount; nothing for any other
// (plan-EVS1-git-http-credential). The hosts are the loopback ones until the http front's listener tells this method
// its other names.
func urGitCredentialOf(mounts *sidecar.EvsMounts, params *urGitCredentialParams) *urGitCredentialReply {
	if params.Protocol != "http" && params.Protocol != "https" {
		return &urGitCredentialReply{}
	}
	host := params.Host
	if index := strings.LastIndex(host, ":"); index != -1 && !strings.HasSuffix(host, "]") {
		host = host[:index]
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return &urGitCredentialReply{}
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(params.Path, "/"), "/")
	repoId, err := sidecar.EvsGitRepoOf("id:" + strings.TrimSuffix(first, ".git"))
	if err != nil {
		return &urGitCredentialReply{}
	}
	mount, ok := mounts.Get(repoId)
	if !ok || mount.HttpPassword() == "" {
		return &urGitCredentialReply{}
	}
	return &urGitCredentialReply{Username: sidecar.EvsGitHttpUser, Password: mount.HttpPassword()}
}

// ur mount add or share.
func runUrMount(ctx context.Context, cli *urCli, options docopt.Opts) error {
	dir, _ := options.String("<dir>")
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	switch {
	case urOptionBool(options, "share"):
		return errors.New("ur mount share files a RepoGrant or an EvsShare, which waits on ur's statement poster (CORE-M2-02)")
	case urOptionBool(options, "add"):
		repoId, _ := options.String("--repo")
		agent, _ := options.String("--agent")
		reply := &urMountAddReply{}
		if err := cli.callDaemon(ctx, urMethodMountAdd, &urMountAddParams{Dir: absolute, RepoId: repoId, Agent: agent}, false, reply); err != nil {
			return err
		}
		cli.printf("repo %s is mounted for %s\n", reply.RepoId, absolute)
		cli.printf("  the daemon serves it from %s\n", reply.BareDir)
		if reply.SshHostKey != "" {
			cli.printf("  over ssh its host key is %s\n", reply.SshHostKey)
		}
		cli.printf("  a clone also reaches it as ur://<network>/id:%s\n", reply.RepoId)
		return nil
	}
	return errors.New("ur mount takes add or share")
}

// ur git-credential get: git's credential fields on stdin, Basic's user and password on stdout for a mount the daemon
// serves, nothing for any other host; store and erase do nothing, the secret living in the daemon.
func runUrGitCredential(ctx context.Context, cli *urCli, options docopt.Opts) error {
	operation, _ := options.String("<operation>")
	if operation != "get" {
		return nil
	}
	params := &urGitCredentialParams{}
	scanner := bufio.NewScanner(cli.stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch name {
		case "protocol":
			params.Protocol = value
		case "host":
			params.Host = value
		case "path":
			params.Path = value
		}
	}
	reply := &urGitCredentialReply{}
	if err := cli.callDaemon(ctx, urMethodGitCredential, params, false, reply); err != nil {
		return err
	}
	if reply.Username != "" {
		fmt.Fprintf(cli.stdout, "username=%s\npassword=%s\n", reply.Username, reply.Password)
	}
	return nil
}
