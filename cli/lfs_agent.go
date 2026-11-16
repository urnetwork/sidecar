// ur lfs-agent (§11.11's agent row; EVS2-M10-25): git-lfs's standalone custom transfer agent, which ur mount add and
// git-remote-ur write into a clone's config (sidecar.EvsLfsConfigureClone), so git-lfs moves objects through the
// daemon with no LFS server:
//
//	ur lfs-agent --repo=<repo>    git-lfs runs it; <repo> is id:<repo_id>, or <net>/id:<repo_id> from git-remote-ur
//
// The protocol is the root's (sidecar.RunEvsLfsAgent). Each object is one control call to the instance's daemon,
// evs.lfs.upload or evs.lfs.download, naming the file git-lfs holds or the one the agent made under the clone's
// lfs/tmp: the two run as one uid, so object bytes never cross the socket. The daemon's side is the network's
// git-lfs store (sidecar.EvsLfsStore), one per repo, which refuses, saying so, while the daemon builds no evs client
// (urDaemonEvsClient). A failure comes back as a code and a message, so git-lfs prints the object and, for one a prune
// took, when its prune committed.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur lfs-agent calls.
const (
	urMethodLfsUpload   = "evs.lfs.upload"
	urMethodLfsDownload = "evs.lfs.download"
)

// The kinds of failure a method's reply carries, which the agent turns back into the root's errors.
const (
	urLfsFailureMissing  = "missing"
	urLfsFailureTooLarge = "too_large"
	urLfsFailureInvalid  = "invalid"
	urLfsFailureOther    = "failed"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "lfs-agent",
		usage:   "  ur lfs-agent --repo=<repo>",
		summary: "git-lfs's transfer agent for a repo ur serves, which git-lfs runs itself",
		run:     runUrLfsAgent,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urLfsMethods)
}

// evs.lfs.upload's and evs.lfs.download's params and reply.
type urLfsParams struct {
	Repo string `json:"repo"`
	Oid  string `json:"oid"`
	Size int64  `json:"size"`
	Path string `json:"path"`
}

type urLfsReply struct {
	// empty on success, else one of urLfsFailure*
	Failure string `json:"failure,omitempty"`
	Message string `json:"message,omitempty"`
	// a missing object's prune, in ms since the epoch; 0 for one never stored
	RemovedMs int64 `json:"removed_ms,omitempty"`
}

// The repo an agent's --repo names: id:<repo_id>, optionally after <net>/, as git-remote-ur's url carries it.
func urLfsRepoId(repo string) (sidecar.Id, error) {
	if _, after, found := strings.Cut(repo, "/"); found {
		repo = after
	}
	return sidecar.EvsGitRepoOf(repo)
}

// The git-lfs methods over target, when it hosts a Sidecar: one store per repo, kept for the daemon's life.
func urLfsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	stores := &urLfsStores{repoIdStores: map[sidecar.Id]*sidecar.EvsLfsStore{}}
	handle := func(download bool) func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
		return func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urLfsParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			repoId, err := urLfsRepoId(params.Repo)
			if err != nil {
				return nil, err
			}
			oid, err := sidecar.EvsLfsOidDecodeHex(params.Oid)
			if err != nil {
				return nil, err
			}
			client, err := evs.evsClient()
			if err != nil {
				return nil, err
			}
			store := stores.of(client, repoId)
			if download {
				_, err = store.DownloadFile(ctx, oid, params.Path)
			} else {
				_, err = store.UploadFile(ctx, oid, params.Size, params.Path)
			}
			return urLfsReplyOf(err), nil
		}
	}
	return []*sidecar.DaemonMethod{
		{Name: urMethodLfsUpload, Handler: handle(false)},
		{Name: urMethodLfsDownload, Handler: handle(true)},
	}
}

// The daemon's stores, by repo.
type urLfsStores struct {
	stateLock    sync.Mutex
	client       *sidecar.EvsClient
	repoIdStores map[sidecar.Id]*sidecar.EvsLfsStore
}

// The store of repoId on client, made once; a new client starts the stores again.
func (self *urLfsStores) of(client *sidecar.EvsClient, repoId sidecar.Id) *sidecar.EvsLfsStore {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.client != client {
		self.client, self.repoIdStores = client, map[sidecar.Id]*sidecar.EvsLfsStore{}
	}
	store, ok := self.repoIdStores[repoId]
	if !ok {
		store = sidecar.NewEvsLfsStore(client.Repo(repoId))
		self.repoIdStores[repoId] = store
	}
	return store
}

// A store call's outcome as the reply carries it: the oid and why, never a path.
func urLfsReplyOf(err error) *urLfsReply {
	var missing *sidecar.EvsLfsMissingError
	switch {
	case err == nil:
		return &urLfsReply{}
	case errors.As(err, &missing):
		reply := &urLfsReply{Failure: urLfsFailureMissing, Message: err.Error()}
		if !missing.RemovedAt.IsZero() {
			reply.RemovedMs = missing.RemovedAt.UnixMilli()
		}
		return reply
	case errors.Is(err, sidecar.ErrEvsFileTooLarge):
		return &urLfsReply{Failure: urLfsFailureTooLarge, Message: err.Error()}
	case errors.Is(err, sidecar.ErrEvsLfsObjectInvalid):
		return &urLfsReply{Failure: urLfsFailureInvalid, Message: err.Error()}
	}
	return &urLfsReply{Failure: urLfsFailureOther, Message: err.Error()}
}

// The error a reply stands for, nil for success.
func (self *urLfsReply) err(oid sidecar.EvsLfsOid) error {
	switch self.Failure {
	case "":
		return nil
	case urLfsFailureMissing:
		missing := &sidecar.EvsLfsMissingError{Oid: oid}
		if self.RemovedMs != 0 {
			missing.RemovedAt = time.UnixMilli(self.RemovedMs)
		}
		return missing
	case urLfsFailureTooLarge:
		return fmt.Errorf("%w: %s", sidecar.ErrEvsFileTooLarge, self.Message)
	case urLfsFailureInvalid:
		return fmt.Errorf("%w: %s", sidecar.ErrEvsLfsObjectInvalid, self.Message)
	}
	return errors.New(self.Message)
}

// The agent's backend: one control call per object.
type urLfsBackend struct {
	cli  *urCli
	repo string
}

func (self *urLfsBackend) Upload(ctx context.Context, oid sidecar.EvsLfsOid, size int64, path string) error {
	return self.call(ctx, urMethodLfsUpload, oid, size, path)
}

func (self *urLfsBackend) Download(ctx context.Context, oid sidecar.EvsLfsOid, size int64, path string) error {
	return self.call(ctx, urMethodLfsDownload, oid, size, path)
}

// One call, its reply's failure as an error.
func (self *urLfsBackend) call(ctx context.Context, method string, oid sidecar.EvsLfsOid, size int64, path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	reply := &urLfsReply{}
	params := &urLfsParams{Repo: self.repo, Oid: oid.String(), Size: size, Path: absolute}
	if err := self.cli.callDaemon(ctx, method, params, false, reply); err != nil {
		return err
	}
	return reply.err(oid)
}

// Where a download's file is made: the clone's git directory's lfs/tmp, from GIT_DIR or the working directory up.
func urLfsAgentTempDir(cli *urCli) (string, error) {
	gitDir := cli.getenv("GIT_DIR")
	if gitDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		for dir := cwd; ; dir = filepath.Dir(dir) {
			if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
				gitDir = filepath.Join(dir, ".git")
				break
			}
			if filepath.Dir(dir) == dir {
				return "", errors.New("ur lfs-agent runs inside a git clone")
			}
		}
	}
	gitDir, err := filepath.Abs(gitDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "lfs", "tmp"), nil
}

// ur lfs-agent: see the file header. Its exit code is the protocol's.
func runUrLfsAgent(ctx context.Context, cli *urCli, options docopt.Opts) error {
	repo := urOptionString(options, "--repo")
	if _, err := urLfsRepoId(repo); err != nil {
		return err
	}
	tempDir, err := urLfsAgentTempDir(cli)
	if err != nil {
		return err
	}
	code := sidecar.RunEvsLfsAgent(ctx, &sidecar.EvsLfsAgentArgs{
		Backend: &urLfsBackend{cli: cli, repo: repo}, Stdin: cli.stdin, Stdout: cli.stdout, Stderr: cli.stderr,
		TempDir: tempDir, ProgressByteCount: sidecar.DefaultEvsSettings().LfsProgressByteCount,
	})
	if code != 0 {
		return fmt.Errorf("the git-lfs agent stopped")
	}
	return nil
}
