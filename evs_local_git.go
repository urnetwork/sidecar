//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The local tier's git runner (§11.11): the system git, never a library, run by its absolute path with a clean
// environment, so no user or system config, credential helper, askpass or proxy of the daemon's environment reaches
// it, and no credential ever rides in a url or a variable (I-7). go-git is the tests' oracle only, never the server.
// A git below 2.34, the floor of §22.9's matrix (receive.procReceiveRefs and receive.advertiseAtomic need 2.29), is
// refused with a message that names the version found and the one needed.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// §22.9's matrix floor.
var evsLocalGitMinVersion = [3]int{2, 34, 0}

var (
	// The system git is older than the local tier needs.
	ErrEvsGitTooOld = errors.New("evs: git too old")
	// A git command failed. Its output is not repeated, since it may name paths (I-13).
	ErrEvsGitFailed = errors.New("evs: git failed")
)

// The system git, by its absolute path.
type EvsGitRunner struct {
	gitPath  string
	version  [3]int
	settings *EvsSettings
	clock    Clock
	// HOME for every command: a directory of the daemon's, holding no config
	home string
}

// The runner of the git at gitPath, which must be absolute, its version read and held to the floor. home is the
// daemon-owned directory git sees as HOME.
func NewEvsGitRunner(ctx context.Context, gitPath string, home string, settings *EvsSettings, clock Clock) (*EvsGitRunner, error) {
	if !filepath.IsAbs(gitPath) || !filepath.IsAbs(home) {
		return nil, fmt.Errorf("%w: git and its home by absolute paths", errInvalidSettings)
	}
	self := &EvsGitRunner{gitPath: gitPath, settings: settings, clock: clockOrReal(clock), home: home}
	out, err := self.Run(ctx, "", "--version")
	if err != nil {
		return nil, err
	}
	version, err := evsParseGitVersion(string(out))
	if err != nil {
		return nil, err
	}
	if evsCompareGitVersion(version, evsLocalGitMinVersion) < 0 {
		return nil, fmt.Errorf("%w: found git %d.%d.%d, and the local tier needs %d.%d or later", ErrEvsGitTooOld,
			version[0], version[1], version[2], evsLocalGitMinVersion[0], evsLocalGitMinVersion[1])
	}
	self.version = version
	return self, nil
}

// The version `git --version` prints: "git version 2.43.0", any suffix after the third number ignored.
func evsParseGitVersion(text string) ([3]int, error) {
	fields := strings.Fields(text)
	if len(fields) < 3 || fields[0] != "git" || fields[1] != "version" {
		return [3]int{}, fmt.Errorf("%w: an unreadable git version", ErrEvsGitFailed)
	}
	version := [3]int{}
	parts := strings.SplitN(fields[2], ".", 4)
	for i := 0; i < 3 && i < len(parts); i += 1 {
		digits := parts[i]
		end := 0
		for end < len(digits) && '0' <= digits[end] && digits[end] <= '9' {
			end += 1
		}
		number, err := strconv.Atoi(digits[:end])
		if err != nil {
			return [3]int{}, fmt.Errorf("%w: an unreadable git version", ErrEvsGitFailed)
		}
		version[i] = number
	}
	return version, nil
}

// Orders versions.
func evsCompareGitVersion(a [3]int, b [3]int) int {
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// The git version found.
func (self *EvsGitRunner) Version() [3]int {
	return self.version
}

// The environment every command runs in: nothing of the daemon's, so no config, credential or proxy leaks in.
func (self *EvsGitRunner) environment() []string {
	return []string{
		"HOME=" + self.home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"LC_ALL=C",
	}
}

// Runs git with args in dir (none: no -C), bounded by GitCommandTimeout, answering its standard output. A failure is
// ErrEvsGitFailed with the exit status, never git's own text.
func (self *EvsGitRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.GitCommandTimeout, cancel)
	defer stop()
	fullArgs := args
	if dir != "" {
		if !filepath.IsAbs(dir) {
			return nil, fmt.Errorf("%w: a git directory by a relative path", errInvalidSettings)
		}
		fullArgs = append([]string{"-C", dir}, args...)
	}
	command := exec.CommandContext(runCtx, self.gitPath, fullArgs...)
	command.Env = self.environment()
	command.Dir = self.home
	stdout := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = &bytes.Buffer{}
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		exitCode := -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
		return nil, fmt.Errorf("%w: %s exited %d", ErrEvsGitFailed, firstWordOf(args), exitCode)
	}
	return stdout.Bytes(), nil
}

// The git subcommand, for an error that names no path.
func firstWordOf(args []string) string {
	if len(args) == 0 {
		return "git"
	}
	return args[0]
}

// A long-lived git process with its standard input and output piped: one a reader such as cat-file --batch keeps open
// and asks in turn. It runs in Run's environment, bounded by ctx and by Close, not by GitCommandTimeout; its standard
// error is dropped, since it may name paths (I-13).
type EvsGitProcess struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	Stdin   io.WriteCloser
	Stdout  io.ReadCloser
}

// Starts git with args in dir, which must be absolute.
func (self *EvsGitRunner) Start(ctx context.Context, dir string, args ...string) (*EvsGitProcess, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("%w: a git directory by a relative path", errInvalidSettings)
	}
	runCtx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(runCtx, self.gitPath, append([]string{"-C", dir}, args...)...)
	command.Env = self.environment()
	command.Dir = self.home
	command.Stderr = io.Discard
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := command.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("%w: %s did not start", ErrEvsGitFailed, firstWordOf(args))
	}
	return &EvsGitProcess{command: command, cancel: cancel, Stdin: stdin, Stdout: stdout}, nil
}

// Ends it: its input closed and the process stopped, so a reader that left output unread never blocks it, then
// waited for.
func (self *EvsGitProcess) Close() error {
	self.Stdin.Close()
	self.cancel()
	self.command.Wait()
	return nil
}
