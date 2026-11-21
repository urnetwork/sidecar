//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs transfer agent (§11.11's agent, touch and smudge rows; D-EVS-41, FI-9, FS-73, X19; EVS2-M10-25):
// git-lfs's standalone custom transfer protocol (git-lfs's docs/custom-transfers.md), which `ur lfs-agent` speaks on
// its stdin and stdout and serves through the daemon over §5.8's socket, so git-lfs moves objects with no LFS server.
//
//	protocol   newline-delimited JSON: init, answered {} before any transfer; upload and download, each answered by
//	           a complete event naming the oid, a download's with the path of a file holding the object, or with
//	           error {code, message}; a progress event before a large object's complete; terminate ends it, answered by
//	           nothing. An event it does not know is answered with an error naming the oid it carries
//	paths      the agent and the daemon run as one uid, so object bytes never cross the socket: an upload names the
//	           file git-lfs holds, and a download a file the agent made under the clone's lfs/tmp, which the daemon
//	           fills and git-lfs then moves into its store
//	upload     for each object git-lfs asks it to upload, before the ref update (git-lfs's pre-push hook), the store
//	           touches the object's path where it holds the object, else creates it (EvsLfsStore.UploadFile)
//	download   read through the store; a pruned object answers an error naming it and when its prune committed, and
//	           lfs.skipdownloaderrors leaves the pointer in the checkout
//	processes  git-lfs starts several agent processes for one operation (confirmed on git-lfs 3.8.0), so an agent
//	           keeps no exclusive state: the store is the daemon's, and a second creation is a success
//	config     ur mount add and git-remote-ur write lfs.standalonetransferagent, lfs.customtransfer.ur.path and .args
//	           and lfs.skipdownloaderrors into the clone (EvsLfsConfigureClone). `git lfs env` prints a meaningless
//	           endpoint for ur://, which nothing relies on. A clone with no local ur has no agent, and the tip check
//	           refuses what never arrived (evs_lfs_tipcheck.go)
//
// An object past LfsObjectMaxByteCount is refused by name (EVS_FILE_TOO_LARGE). An oid is never logged with a path
// (I-13), and an error carries the oid alone.
//
// Desktop legs only. RunEvsLfsAgent is safe for concurrent use with distinct streams.

package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The custom transfer agent's name in a clone's config: lfs.customtransfer.ur.*.
const EvsLfsAgentName = "ur"

// git-lfs's error codes the agent answers with: an HTTP-like status git-lfs prints beside the message.
const (
	evsLfsAgentCodeNotFound  = 404
	evsLfsAgentCodeTooLarge  = 413
	evsLfsAgentCodeInvalid   = 422
	evsLfsAgentCodeFailed    = 500
	evsLfsAgentCodeMalformed = 400
)

// What the agent's daemon does with each object.
type EvsLfsAgentBackend interface {
	// Stores or touches the object whose bytes are in the file at path.
	Upload(ctx context.Context, oid EvsLfsOid, size int64, path string) error
	// Writes the object's bytes to the file at path, which the agent made empty.
	Download(ctx context.Context, oid EvsLfsOid, size int64, path string) error
}

// One agent run's streams and backend.
type EvsLfsAgentArgs struct {
	Backend EvsLfsAgentBackend
	Stdin   io.Reader
	Stdout  io.Writer
	// git-lfs prints what the agent writes here to its own standard error; never an oid with a path.
	Stderr io.Writer
	// Where a download's file is made: the clone's lfs/tmp, made when missing.
	TempDir string
	// A complete event of an object this large or larger is preceded by a progress event.
	ProgressByteCount int64
}

// One message of git-lfs's protocol, either way: the fields each event uses.
type evsLfsAgentMessage struct {
	Event               string            `json:"event,omitempty"`
	Operation           string            `json:"operation,omitempty"`
	Remote              string            `json:"remote,omitempty"`
	Concurrent          bool              `json:"concurrent,omitempty"`
	ConcurrentTransfers int               `json:"concurrenttransfers,omitempty"`
	Oid                 string            `json:"oid,omitempty"`
	Size                int64             `json:"size,omitempty"`
	Path                string            `json:"path,omitempty"`
	BytesSoFar          int64             `json:"bytesSoFar,omitempty"`
	BytesSinceLast      int64             `json:"bytesSinceLast,omitempty"`
	Error               *evsLfsAgentError `json:"error,omitempty"`
	Action              json.RawMessage   `json:"action,omitempty"`
}

// An error git-lfs prints for one object.
type evsLfsAgentError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Runs the agent until terminate or its input ends: see the file header. It answers the process's exit code.
func RunEvsLfsAgent(ctx context.Context, args *EvsLfsAgentArgs) int {
	reader := bufio.NewReaderSize(args.Stdin, 64*1024)
	encoder := json.NewEncoder(args.Stdout)
	reply := func(message *evsLfsAgentMessage) bool {
		if err := encoder.Encode(message); err != nil {
			fmt.Fprintf(args.Stderr, "ur lfs-agent: git-lfs closed the agent\n")
			return false
		}
		return true
	}
	initialized := false
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			if errors.Is(err, io.EOF) {
				return 0
			}
			fmt.Fprintf(args.Stderr, "ur lfs-agent: git-lfs's input: %v\n", err)
			return 1
		}
		message := &evsLfsAgentMessage{}
		if err := json.Unmarshal(line, message); err != nil {
			fmt.Fprintf(args.Stderr, "ur lfs-agent: a line that is no JSON\n")
			return 1
		}
		switch message.Event {
		case "init":
			initialized = true
			if !reply(&evsLfsAgentMessage{}) {
				return 1
			}
			continue
		case "terminate":
			return 0
		}
		answer := &evsLfsAgentMessage{Event: "complete", Oid: message.Oid}
		oid, oidErr := EvsLfsOidDecodeHex(message.Oid)
		switch {
		case !initialized:
			answer.Error = &evsLfsAgentError{Code: evsLfsAgentCodeMalformed, Message: "ur lfs-agent: a transfer before init"}
		case message.Event != "upload" && message.Event != "download":
			answer.Error = &evsLfsAgentError{Code: evsLfsAgentCodeMalformed, Message: fmt.Sprintf("ur lfs-agent: no event %q", message.Event)}
		case oidErr != nil:
			answer.Error = &evsLfsAgentError{Code: evsLfsAgentCodeMalformed, Message: "ur lfs-agent: an oid that is no SHA-256"}
		case message.Event == "upload":
			if err := args.Backend.Upload(ctx, oid, message.Size, message.Path); err != nil {
				answer.Error = evsLfsAgentErrorOf(oid, err)
			}
		default:
			path, err := evsLfsAgentDownload(ctx, args, oid, message.Size)
			if err != nil {
				answer.Error = evsLfsAgentErrorOf(oid, err)
			} else {
				answer.Path = path
			}
		}
		if answer.Error == nil && 0 < args.ProgressByteCount && args.ProgressByteCount <= message.Size {
			if !reply(&evsLfsAgentMessage{Event: "progress", Oid: message.Oid, BytesSoFar: message.Size, BytesSinceLast: message.Size}) {
				return 1
			}
		}
		if !reply(answer) {
			return 1
		}
	}
}

// A download into a new file under the agent's temporary directory, removed when the backend fails.
func evsLfsAgentDownload(ctx context.Context, args *EvsLfsAgentArgs, oid EvsLfsOid, size int64) (string, error) {
	if err := os.MkdirAll(args.TempDir, 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(args.TempDir, "ur-"+oid.String()+"-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	file.Close()
	if err := args.Backend.Download(ctx, oid, size, path); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// What git-lfs is told of a failure: the oid and why, never a path.
func evsLfsAgentErrorOf(oid EvsLfsOid, err error) *evsLfsAgentError {
	code := evsLfsAgentCodeFailed
	switch {
	case errors.Is(err, ErrEvsLfsObjectMissing):
		code = evsLfsAgentCodeNotFound
	case errors.Is(err, ErrEvsFileTooLarge):
		code = evsLfsAgentCodeTooLarge
	case errors.Is(err, ErrEvsLfsObjectInvalid):
		code = evsLfsAgentCodeInvalid
	}
	message := err.Error()
	if !strings.Contains(message, oid.String()) {
		message = fmt.Sprintf("%s: %s", oid, message)
	}
	return &evsLfsAgentError{Code: code, Message: "ur: " + message}
}

// Stores the object in the file at path, or touches it where the store holds it, so a prune sees a version newer than
// its window (§11.11's touch row): see the file header. An object past LfsObjectMaxByteCount is refused by name before
// the file is read.
func (self *EvsLfsStore) UploadFile(ctx context.Context, oid EvsLfsOid, size int64, path string) (*EvsLfsObject, error) {
	if size < 0 || self.settings.LfsObjectMaxByteCount < size {
		return nil, &EvsLfsTooLargeError{Oid: oid, Size: size}
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s's file by a relative path", ErrEvsWriteInvalid, oid)
	}
	newest, err := self.newest(ctx, []EvsLfsOid{oid}, false)
	if err != nil {
		return nil, err
	}
	if newest[0].Present() {
		_, err := self.Touch(ctx, newest)
		var conflict *EvsPathConflictError
		switch {
		case errors.As(err, &conflict):
			// it moved: read it again, and store it when a prune took it
			newest, err = self.newest(ctx, []EvsLfsOid{oid}, true)
			if err != nil {
				return nil, err
			}
			if newest[0].Present() {
				return newest[0], nil
			}
		case err != nil:
			return nil, err
		default:
			touched, err := self.newest(ctx, []EvsLfsOid{oid}, false)
			if err != nil {
				return nil, err
			}
			return touched[0], nil
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return self.Put(ctx, oid, size, file)
}

// Writes the object to the file at path, made by the agent: see the file header.
func (self *EvsLfsStore) DownloadFile(ctx context.Context, oid EvsLfsOid, path string) (*EvsLfsObject, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s's file by a relative path", ErrEvsWriteInvalid, oid)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	object, err := self.Get(ctx, oid, file)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	return object, nil
}

// Writes the agent's keys into a clone's config, gitDir the clone's git directory: lfs.standalonetransferagent names
// the agent, whose path and args run it, and lfs.skipdownloaderrors leaves a pruned object's pointer in the checkout.
// agentPath is ur's absolute path, and agentArgs its arguments, `lfs-agent --repo=<repo>`.
func EvsLfsConfigureClone(ctx context.Context, git *EvsGitRunner, gitDir string, agentPath string, agentArgs string) error {
	if !filepath.IsAbs(gitDir) || !filepath.IsAbs(agentPath) {
		return fmt.Errorf("%w: a clone and an agent by absolute paths", errInvalidSettings)
	}
	configFile := filepath.Join(gitDir, "config")
	for _, setting := range [][]string{
		{"lfs.standalonetransferagent", EvsLfsAgentName},
		{"lfs.customtransfer." + EvsLfsAgentName + ".path", agentPath},
		{"lfs.customtransfer." + EvsLfsAgentName + ".args", agentArgs},
		{"lfs.customtransfer." + EvsLfsAgentName + ".concurrent", "true"},
		{"lfs.skipdownloaderrors", "true"},
	} {
		if _, err := git.Run(ctx, "", "config", "--file", configFile, setting[0], setting[1]); err != nil {
			return err
		}
	}
	return nil
}

// Sets the command ur mount add writes into a mount's clone as its git-lfs agent: ur's absolute path, run with
// `lfs-agent --repo=id:<repo_id>`. Unset, a mount's clone gets no agent, and pushes of git-lfs content are refused by
// the tip check as objects that never arrived.
func (self *EvsMounts) SetLfsAgentPath(path string) error {
	if path != "" && !filepath.IsAbs(path) {
		return fmt.Errorf("%w: the git-lfs agent by a relative path", errInvalidSettings)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lfsAgentPath = path
	return nil
}

// The agent's args for a mount of repoId.
func EvsLfsAgentArgsFor(repo string) string {
	return "lfs-agent --repo=" + repo
}
