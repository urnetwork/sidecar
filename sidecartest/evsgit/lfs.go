//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// git-lfs in the git world (§11.11's agent, touch and smudge rows; FS-73, X19; EVS2-M10-29): every clone runs stock
// git-lfs, whose standalone transfer agent is a test binary standing in for `ur lfs-agent`. It speaks git-lfs's protocol
// through the root's agent (sidecar.RunEvsLfsAgent) and relays each object to the device's daemon over §5.8's control
// mode, where the device's ur/lfs store (sidecar.EvsLfsStore) uploads, touches or reads it, as ur daemon's
// evs.lfs.upload and evs.lfs.download do (cli/lfs_agent.go, a package this one cannot import). Only the relay between
// the two processes is this world's own: the protocol, the store, the daemon and git-lfs are the system's.
//
//	agent     a test binary that builds a world names a test of its own in WorldLfs.AgentCommand which calls
//	          LfsAgentHelper; git-lfs execs it, and it relays to the daemon whose socket LfsSocketVariable names
//	git-lfs   the binary WorldLfs.GitLfs names, first on every device git's PATH, installed in each clone with `git lfs
//	          install --local`, the agent's keys written before the checkout (sidecar.EvsLfsConfigureClone), so the
//	          first smudge already reads through the daemon, and lfs.skipdownloaderrors leaves a pruned object's pointer
//	calls     the daemon records what it served each agent: an upload as the creation or the touch it wrote, and each
//	          download, so a clause counts what an ordinary push wrote (LfsCalls)
//
// Its methods are safe for concurrent use as the devices are.

package evsgit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The environment variable naming the daemon socket an agent relays to.
const LfsSocketVariable = "UR_TEST_EVS_GIT_LFS_SOCKET"

// The control methods an agent calls, as ur lfs-agent's are named.
const (
	lfsMethodUpload   = "evs.lfs.upload"
	lfsMethodDownload = "evs.lfs.download"
)

// The kinds of failure a reply carries, which the agent turns back into the root's errors, as ur's do.
const (
	lfsFailureMissing  = "missing"
	lfsFailureTooLarge = "too_large"
	lfsFailureInvalid  = "invalid"
	lfsFailureOther    = "failed"
)

// git-lfs in a world.
type WorldLfs struct {
	// What each clone's git-lfs execs as its transfer agent: the test binary and a -test.run naming the test that calls
	// LfsAgentHelper. Required.
	AgentCommand []string
	// The git-lfs every device's git runs, an absolute path. Required.
	GitLfs string
}

// One object a device's daemon served an agent.
type LfsCall struct {
	Oid      sidecar.EvsLfsOid
	Download bool
	// An upload's outcome: the store created the object, or touched the version it held, and the newest version after.
	Created bool
	Touched bool
	Version uint64
	Err     error
}

// What a device's daemon served its agents, in order.
type lfsCalls struct {
	stateLock sync.Mutex
	calls     []*LfsCall
}

func (self *lfsCalls) add(call *LfsCall) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

// Every object the device's daemon served its agents since the last ResetLfsCalls.
func (self *Device) LfsCalls() []*LfsCall {
	if self.lfsCalls == nil {
		return nil
	}
	self.lfsCalls.stateLock.Lock()
	defer self.lfsCalls.stateLock.Unlock()
	return slices.Clone(self.lfsCalls.calls)
}

// Forgets the calls served so far.
func (self *Device) ResetLfsCalls() {
	if self.lfsCalls == nil {
		return
	}
	self.lfsCalls.stateLock.Lock()
	defer self.lfsCalls.stateLock.Unlock()
	self.lfsCalls.calls = nil
}

// evs.lfs.upload's and evs.lfs.download's params and reply, as ur's.
type lfsParams struct {
	Oid  string `json:"oid"`
	Size int64  `json:"size"`
	Path string `json:"path"`
}

type lfsReply struct {
	// empty on success, else one of lfsFailure*
	Failure string `json:"failure,omitempty"`
	Message string `json:"message,omitempty"`
	// a missing object's prune, in ms since the epoch; 0 for one never stored
	RemovedMs int64 `json:"removed_ms,omitempty"`
}

// A store call's outcome as the reply carries it: the oid and why, never a path.
func lfsReplyOf(err error) *lfsReply {
	var missing *sidecar.EvsLfsMissingError
	switch {
	case err == nil:
		return &lfsReply{}
	case errors.As(err, &missing):
		reply := &lfsReply{Failure: lfsFailureMissing, Message: err.Error()}
		if !missing.RemovedAt.IsZero() {
			reply.RemovedMs = missing.RemovedAt.UnixMilli()
		}
		return reply
	case errors.Is(err, sidecar.ErrEvsFileTooLarge):
		return &lfsReply{Failure: lfsFailureTooLarge, Message: err.Error()}
	case errors.Is(err, sidecar.ErrEvsLfsObjectInvalid):
		return &lfsReply{Failure: lfsFailureInvalid, Message: err.Error()}
	}
	return &lfsReply{Failure: lfsFailureOther, Message: err.Error()}
}

// The error a reply stands for, nil for success.
func (self *lfsReply) err(oid sidecar.EvsLfsOid) error {
	switch self.Failure {
	case "":
		return nil
	case lfsFailureMissing:
		missing := &sidecar.EvsLfsMissingError{Oid: oid}
		if self.RemovedMs != 0 {
			missing.RemovedAt = time.UnixMilli(self.RemovedMs)
		}
		return missing
	case lfsFailureTooLarge:
		return fmt.Errorf("%w: %s", sidecar.ErrEvsFileTooLarge, self.Message)
	case lfsFailureInvalid:
		return fmt.Errorf("%w: %s", sidecar.ErrEvsLfsObjectInvalid, self.Message)
	}
	return errors.New(self.Message)
}

// The device's daemon serving its clones' agents: evs.lfs.upload and evs.lfs.download over the device's store, each
// recorded. Called while the device is made, before its daemon runs.
func (self *Device) serveLfs(daemon *sidecar.Daemon) {
	t := self.world.t
	t.Helper()
	lfs := self.world.settings.Lfs
	if len(lfs.AgentCommand) == 0 || !filepath.IsAbs(lfs.GitLfs) {
		t.Fatal("a world's git-lfs names its agent command and git-lfs by its absolute path")
	}
	// the world's git-lfs first on PATH, and a home of the device's own, outside any clone's work tree
	for _, directory := range []string{self.lfsBin(), self.lfsHome()} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(lfs.GitLfs, filepath.Join(self.lfsBin(), "git-lfs")); err != nil {
		t.Fatal(err)
	}
	self.Lfs = sidecar.NewEvsLfsStore(self.Client.Repo(self.world.repoId))
	self.lfsCalls = &lfsCalls{}
	handle := func(download bool) func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
		return func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &lfsParams{}
			if err := json.Unmarshal(call.Params, params); err != nil {
				return nil, err
			}
			oid, err := sidecar.EvsLfsOidDecodeHex(params.Oid)
			if err != nil {
				return nil, err
			}
			if download {
				_, err := self.Lfs.DownloadFile(ctx, oid, params.Path)
				self.lfsCalls.add(&LfsCall{Oid: oid, Download: true, Err: err})
				return lfsReplyOf(err), nil
			}
			// the newest version before, so the record says whether the upload created the object or touched it
			before, err := self.Lfs.Newest(ctx, []sidecar.EvsLfsOid{oid}, true)
			if err != nil {
				self.lfsCalls.add(&LfsCall{Oid: oid, Err: err})
				return lfsReplyOf(err), nil
			}
			object, err := self.Lfs.UploadFile(ctx, oid, params.Size, params.Path)
			record := &LfsCall{Oid: oid, Err: err}
			if err == nil {
				record.Created = !before[0].Present()
				record.Touched = before[0].Present() && before[0].Version < object.Version
				record.Version = object.Version
			}
			self.lfsCalls.add(record)
			return lfsReplyOf(err), nil
		}
	}
	for _, method := range []*sidecar.DaemonMethod{
		{Name: lfsMethodUpload, Handler: handle(false)},
		{Name: lfsMethodDownload, Handler: handle(true)},
	} {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
}

// Where the device keeps the git-lfs its git finds first.
func (self *Device) lfsBin() string {
	return filepath.Join(self.directory, "lfs-bin")
}

// The home the device's git runs with in a world with git-lfs.
func (self *Device) lfsHome() string {
	return filepath.Join(self.directory, "lfs-home")
}

// The environment a device's git runs with in a world with git-lfs, beside the world's git-lfs first on its PATH
// (Device.gitSearchPath): a home of the device's own, since a clone's work tree is no home, and the socket its agents
// relay to. Empty without git-lfs.
func (self *Device) lfsEnvironment() []string {
	if self.world.settings.Lfs == nil {
		return nil
	}
	return []string{
		"HOME=" + self.lfsHome(),
		"GIT_TERMINAL_PROMPT=0",
		LfsSocketVariable + "=" + self.socket,
	}
}

// git-lfs installed in a clone, its agent the world's, written as ur mount add and git-remote-ur write it.
func (self *Device) configureLfs(dir string) {
	t := self.world.t
	t.Helper()
	self.MustGit(dir, "lfs", "install", "--local")
	gitDir := strings.TrimSpace(self.MustGit(dir, "rev-parse", "--absolute-git-dir"))
	command := self.world.settings.Lfs.AgentCommand
	if err := sidecar.EvsLfsConfigureClone(self.world.ctx, self.Mount.GitRunner(), gitDir, command[0], strings.Join(command[1:], " ")); err != nil {
		t.Fatal(err)
	}
}

// The test a WorldLfs.AgentCommand names: git-lfs's transfer agent for one clone, relaying each object to the daemon
// whose socket LfsSocketVariable names, then exiting with the protocol's code. It returns at once when the variable is
// unset, so the test passes as itself.
func LfsAgentHelper() {
	socket := os.Getenv(LfsSocketVariable)
	if socket == "" {
		return
	}
	tempDir, err := lfsAgentTempDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lfs agent: %v\n", err)
		os.Exit(1)
	}
	relay := &lfsRelay{socket: socket}
	code := sidecar.RunEvsLfsAgent(context.Background(), &sidecar.EvsLfsAgentArgs{
		Backend: relay, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		TempDir: tempDir, ProgressByteCount: sidecar.DefaultEvsSettings().LfsProgressByteCount,
	})
	relay.close()
	os.Exit(code)
}

// Where a download's file is made, as ur lfs-agent finds it: the clone's git directory's lfs/tmp, from GIT_DIR or the
// working directory up.
func lfsAgentTempDir() (string, error) {
	gitDir := os.Getenv("GIT_DIR")
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
				return "", errors.New("the agent runs inside a git clone")
			}
		}
	}
	gitDir, err := filepath.Abs(gitDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "lfs", "tmp"), nil
}

// The agent's backend: one control call to the daemon per object, on one session.
type lfsRelay struct {
	socket string

	stateLock sync.Mutex
	client    *sidecar.DaemonClient
}

func (self *lfsRelay) Upload(ctx context.Context, oid sidecar.EvsLfsOid, size int64, path string) error {
	return self.call(ctx, lfsMethodUpload, oid, size, path)
}

func (self *lfsRelay) Download(ctx context.Context, oid sidecar.EvsLfsOid, size int64, path string) error {
	return self.call(ctx, lfsMethodDownload, oid, size, path)
}

// One call, its reply's failure as an error.
func (self *lfsRelay) call(ctx context.Context, method string, oid sidecar.EvsLfsOid, size int64, path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.client == nil {
		client, err := sidecar.DialDaemon(ctx, self.socket, &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl, Version: daemonVersion})
		if err != nil {
			return err
		}
		self.client = client
	}
	reply := &lfsReply{}
	if err := self.client.Call(ctx, method, &lfsParams{Oid: oid.String(), Size: size, Path: absolute}, false, reply); err != nil {
		// a session a failed call left is not used again
		self.client.Close()
		self.client = nil
		return err
	}
	return reply.err(oid)
}

func (self *lfsRelay) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.client != nil {
		self.client.Close()
		self.client = nil
	}
}
