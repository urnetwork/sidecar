//go:build !js && !ios && !android && !ios_extension

// §5.8's hello: the first line of every local session, newline-delimited JSON with ur_local 1, naming the mode the
// session speaks and the version of the ur that opened it. The mode selects a protocol, never a privilege (D-CORE-9).
// A hello of another version is refused, so a just-upgraded ur restarts an old daemon rather than relaying through it.
//
// The daemon answers one line of its own, {"ur_local":1,"version":<its version>}, with "error" set when it refuses
// the session; §5.8 writes no answer, so this one is a reading, kept to what a client needs to tell a refusal from a
// session and to restart a daemon of another version.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// The hello's format values (§5.8).
const (
	daemonLocalProtocol = 1
	// The modes.
	DaemonModeMcp     = "mcp"
	DaemonModeControl = "control"
	DaemonModeHook    = "hook"
	DaemonModeGit     = "git"
	// A mount's git hook relayed by ur git-hook (DESIGN-DETAILS 8.2.8): service names the hook.
	DaemonModeGitHook = "git-hook"
	// git's services.
	daemonGitUploadPack  = "git-upload-pack"
	daemonGitReceivePack = "git-receive-pack"
	// git-hook's hooks.
	daemonGitHookPreReceive  = "pre-receive"
	daemonGitHookProcReceive = "proc-receive"
	// The longest hello line read before the session closes: far past any real one, which a cwd of a few hundred
	// bytes bounds, and far below the request bound, so a hello cannot hold memory.
	daemonHelloMaxByteCount = 16 * 1024
)

// The daemon's refusals of a hello, in its answer's error.
const (
	DaemonHelloErrorVersionSkew = "version_skew"
	DaemonHelloErrorMalformed   = "malformed"
	DaemonHelloErrorMode        = "mode"
)

// A hello the daemon refuses. The error names what was wrong, never the line.
var ErrDaemonHello = errors.New("daemon hello refused")

// §5.8's hello, as a session opens with it.
type DaemonHello struct {
	UrLocal int `json:"ur_local"`
	// mcp, control, hook or git.
	Mode string `json:"mode"`
	// The ur's version, which must be the daemon's.
	Version string `json:"version"`
	// mcp, control and hook: who is calling, for runs and records (§16).
	Harness string `json:"harness,omitempty"`
	Agent   string `json:"agent,omitempty"`
	// The caller's working directory, from which the daemon finds .ur (§5.8). A path on this device, never
	// logged (I-13).
	Cwd string `json:"cwd,omitempty"`
	Pid int64  `json:"pid,omitempty"`
	// git: <net>/<repo> and the service.
	Repo    string `json:"repo,omitempty"`
	Service string `json:"service,omitempty"`
	// The process at the session's other end, as the system reports it: the daemon fills it, never the line, so the
	// ancestry rules (§16.7) read a pid the caller cannot choose. 0 where the system names none.
	PeerPid int64 `json:"-"`
}

// The daemon's answer to a hello.
type daemonHelloAnswer struct {
	UrLocal int    `json:"ur_local"`
	Version string `json:"version"`
	Error   string `json:"error,omitempty"`
}

// Decodes and checks one hello line against version: exactly one JSON object with ur_local 1, a known mode with the
// fields it takes, and version equal to the daemon's. A refusal names its error code, never the line.
func parseDaemonHello(line []byte, version string) (*DaemonHello, string, error) {
	if daemonHelloMaxByteCount < len(line) {
		return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: too long", ErrDaemonHello)
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	hello := &DaemonHello{}
	if err := decoder.Decode(hello); err != nil {
		return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: not a hello", ErrDaemonHello)
	}
	if decoder.More() {
		return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: more than one value", ErrDaemonHello)
	}
	if hello.UrLocal != daemonLocalProtocol {
		return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: not ur_local %d", ErrDaemonHello, daemonLocalProtocol)
	}
	if hello.Version != version {
		return nil, DaemonHelloErrorVersionSkew, fmt.Errorf("%w: another version", ErrDaemonHello)
	}
	switch hello.Mode {
	case DaemonModeMcp, DaemonModeControl, DaemonModeHook:
		if hello.Repo != "" || hello.Service != "" {
			return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: git fields in mode %s", ErrDaemonHello, hello.Mode)
		}
	case DaemonModeGit:
		network, repo, found := strings.Cut(hello.Repo, "/")
		if !found || network == "" || repo == "" || strings.Contains(repo, "/") || path.Clean(hello.Repo) != hello.Repo {
			return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: git's repo is not <net>/<repo>", ErrDaemonHello)
		}
		if hello.Service != daemonGitUploadPack && hello.Service != daemonGitReceivePack {
			return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: git's service", ErrDaemonHello)
		}
	case DaemonModeGitHook:
		if hello.Repo != "" || (hello.Service != daemonGitHookPreReceive && hello.Service != daemonGitHookProcReceive) {
			return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: git-hook's hook", ErrDaemonHello)
		}
	default:
		return nil, DaemonHelloErrorMode, fmt.Errorf("%w: no such mode", ErrDaemonHello)
	}
	if hello.Pid < 0 {
		return nil, DaemonHelloErrorMalformed, fmt.Errorf("%w: a negative pid", ErrDaemonHello)
	}
	return hello, "", nil
}

// One hello line, the client's half: the hello and its newline.
func encodeDaemonHello(hello *DaemonHello) ([]byte, error) {
	hello.UrLocal = daemonLocalProtocol
	encoded, err := json.Marshal(hello)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
