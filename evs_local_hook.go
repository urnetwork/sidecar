//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The receive path's hooks (DESIGN-DETAILS 8.2.8): each hook file in a mount's <repo>.hooks execs `ur git-hook
// <name>`, which dials the daemon's control socket (§5.8's peer-uid check) in its git-hook mode, names the receive
// session the daemon set in UR_GIT_SESSION when it started git-receive-pack, and relays stdin, stdout and stderr. The
// session id names a session and grants nothing: a session is the daemon's, open only while its git-receive-pack runs,
// and every hook still answers to the mount's rules. For pre-receive the relay also carries GIT_OBJECT_DIRECTORY and
// GIT_ALTERNATE_OBJECT_DIRECTORIES, which the daemon gives its git runner for that hook alone, after checking that
// both lie inside the mount's bare repository, so it reads the quarantined objects.
//
//	hello     {"ur_local":1,"mode":"git-hook","version",...,"service":"pre-receive"|"proc-receive"}
//	header    one JSON line: {session, object_directory, alternate_object_directories}
//	frames    each a channel byte, a 4-byte big-endian length and that many bytes: 0 stdin, 1 stdin's end from the
//	          relay; 2 stdout, 3 stderr, 4 the exit code (one byte) from the daemon, which ends the session
//
// git's environment holds no credential: the daemon starts git-receive-pack in the runner's clean environment with
// UR_GIT_SESSION and the instance's name added, never a token (I-7). A relay that cannot reach the daemon exits 1,
// which refuses the push: a hook never fails open.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The hooks the daemon installs in each mount's hooks directory.
const (
	EvsGitHookPreReceive  = "pre-receive"
	EvsGitHookProcReceive = "proc-receive"
)

// The variable naming a receive session in git-receive-pack's environment, which its hooks hand back.
const EvsGitSessionVariable = "UR_GIT_SESSION"

// The quarantine variables pre-receive relays (git's tmp-objdir).
const (
	evsGitObjectDirectoryVariable      = "GIT_OBJECT_DIRECTORY"
	evsGitAlternateDirectoriesVariable = "GIT_ALTERNATE_OBJECT_DIRECTORIES"
)

// A hook session's frames.
const (
	evsGitHookStdin    = 0
	evsGitHookStdinEnd = 1
	evsGitHookStdout   = 2
	evsGitHookStderr   = 3
	evsGitHookExit     = 4
)

// The most one frame carries, and the most a header line holds: format values of this local protocol.
const (
	evsGitHookFrameMaxByteCount  = 64 * 1024
	evsGitHookHeaderMaxByteCount = 64 * 1024
)

// A hook session that does not hold its framing, or names no open session.
var ErrEvsGitHookInvalid = errors.New("evs: a git hook session that does not frame")

// What `ur git-hook` sends after its hello.
type EvsGitHookHeader struct {
	Session string `json:"session"`
	// pre-receive's quarantine, as git set them.
	ObjectDirectory            string `json:"object_directory,omitempty"`
	AlternateObjectDirectories string `json:"alternate_object_directories,omitempty"`
}

// Writes one frame.
func writeEvsGitHookFrame(writer io.Writer, channel byte, payload []byte) error {
	if evsGitHookFrameMaxByteCount < len(payload) {
		return fmt.Errorf("%w: a frame of %d bytes", ErrEvsGitHookInvalid, len(payload))
	}
	frame := make([]byte, 0, 5+len(payload))
	frame = append(frame, channel)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	_, err := writer.Write(frame)
	return err
}

// Reads one frame.
func readEvsGitHookFrame(reader io.Reader) (byte, []byte, error) {
	header := [5]byte{}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if evsGitHookFrameMaxByteCount < length {
		return 0, nil, fmt.Errorf("%w: a frame of %d bytes", ErrEvsGitHookInvalid, length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, fmt.Errorf("%w: a frame cut short", ErrEvsGitHookInvalid)
	}
	return header[0], payload, nil
}

// Writes p as frames of one channel. Safe for concurrent use with the session's other writer.
type evsGitHookFrameWriter struct {
	lock    *sync.Mutex
	writer  io.Writer
	channel byte
}

// Writes p in frames.
func (self *evsGitHookFrameWriter) Write(p []byte) (int, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	written := 0
	for written < len(p) {
		end := min(len(p), written+evsGitHookFrameMaxByteCount)
		if err := writeEvsGitHookFrame(self.writer, self.channel, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// The hook's stdin as the relay's frames carry it, ending at its end frame.
type evsGitHookStdinReader struct {
	reader  io.Reader
	pending []byte
	ended   bool
}

// Reads stdin's bytes.
func (self *evsGitHookStdinReader) Read(p []byte) (int, error) {
	for len(self.pending) == 0 {
		if self.ended {
			return 0, io.EOF
		}
		channel, payload, err := readEvsGitHookFrame(self.reader)
		if err != nil {
			return 0, err
		}
		switch channel {
		case evsGitHookStdin:
			self.pending = payload
		case evsGitHookStdinEnd:
			self.ended = true
		default:
			return 0, fmt.Errorf("%w: a frame of channel %d from the relay", ErrEvsGitHookInvalid, channel)
		}
	}
	n := copy(p, self.pending)
	self.pending = self.pending[n:]
	return n, nil
}

// One receive session: a git-receive-pack the daemon started for a mount, and who pushes through it.
type EvsGitReceiveSession struct {
	// 16 random bytes in hex: UR_GIT_SESSION's value.
	Id    string
	Mount *EvsLocalRepo
	// The pushing agent's label, empty for the sidecar itself (§5.5).
	Agent string
}

// Opens a receive session on mount: the variables git-receive-pack runs with, and the close, which every caller runs
// once receive-pack has exited.
func (self *EvsMounts) OpenReceiveSession(mount *EvsLocalRepo, agent string) (*EvsGitReceiveSession, func()) {
	idBytes := make([]byte, 16)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(idBytes)
	session := &EvsGitReceiveSession{Id: hex.EncodeToString(idBytes), Mount: mount, Agent: agent}
	self.stateLock.Lock()
	if self.sessions == nil {
		self.sessions = map[string]*EvsGitReceiveSession{}
	}
	self.sessions[session.Id] = session
	self.stateLock.Unlock()
	var once sync.Once
	return session, func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.sessions, session.Id)
		})
	}
}

// Whether this registry opened the receive session id and it is still open: what a daemon hosting several networks
// asks each network's registry before it hands a hook session to one.
func (self *EvsMounts) HasReceiveSession(id string) bool {
	return self.receiveSession(id) != nil
}

// The open session of id, nil for none.
func (self *EvsMounts) receiveSession(id string) *EvsGitReceiveSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sessions[id]
}

// What git-receive-pack runs with for session, beside the runner's clean environment: its id, and the variables
// hookEnvironment adds (the instance's name, so ur finds its daemon).
func (self *EvsMounts) ReceiveEnvironment(session *EvsGitReceiveSession) []string {
	env := []string{EvsGitSessionVariable + "=" + session.Id}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append(env, self.hookEnvironment...)
}

// Sets what each hook file execs, its hook's name appended, and the variables receive-pack adds for it: the daemon's
// own ur and git-hook in production (`ur git-hook <name>`), a test binary in tests. Each mount's hook files are
// written again.
func (self *EvsMounts) SetHookCommand(command []string, environment []string) error {
	self.stateLock.Lock()
	self.hookCommand = append([]string{}, command...)
	self.hookEnvironment = append([]string{}, environment...)
	mounts := make([]*EvsLocalRepo, 0, len(self.repoIdMounts))
	for _, mount := range self.repoIdMounts {
		mounts = append(mounts, mount)
	}
	self.stateLock.Unlock()
	for _, mount := range mounts {
		if err := mount.writeHooks(command); err != nil {
			return err
		}
	}
	return nil
}

// Writes the mount's pre-receive and proc-receive files, each execing command with its own name, every word quoted
// for the shell git runs it with. With no command each refuses every push, so a mount whose host has not set one fails
// closed rather than letting receive-pack move a ref evs never took.
func (self *EvsLocalRepo) writeHooks(command []string) error {
	quote := func(word string) string {
		return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
	}
	for _, hook := range []string{EvsGitHookPreReceive, EvsGitHookProcReceive} {
		script := "#!/bin/sh\necho 'ur: this repository takes pushes only through the ur daemon that serves it' >&2\nexit 1\n"
		if 0 < len(command) {
			words := []string{}
			for _, word := range append(append([]string{}, command...), hook) {
				words = append(words, quote(word))
			}
			script = "#!/bin/sh\nexec " + strings.Join(words, " ") + "\n"
		}
		path := filepath.Join(self.HooksDir, hook)
		temp := path + ".tmp"
		if err := os.WriteFile(temp, []byte(script), 0o700); err != nil {
			return err
		}
		if err := os.Rename(temp, path); err != nil {
			return err
		}
	}
	return nil
}

// Serves one hook session from ur git-hook (the daemon's git-hook mode): its header names a receive session this
// registry opened, and pre-receive or proc-receive runs on its mount, its stdout, stderr and exit code framed back.
// A session it does not know exits 1 with a line saying so.
func (self *EvsMounts) ServeGitHook(ctx context.Context, hook string, stream io.ReadWriter) error {
	reader := bufio.NewReaderSize(stream, 4096)
	writeLock := &sync.Mutex{}
	stdout := &evsGitHookFrameWriter{lock: writeLock, writer: stream, channel: evsGitHookStdout}
	stderr := &evsGitHookFrameWriter{lock: writeLock, writer: stream, channel: evsGitHookStderr}
	exit := func(code byte) error {
		writeLock.Lock()
		defer writeLock.Unlock()
		return writeEvsGitHookFrame(stream, evsGitHookExit, []byte{code})
	}
	line, err := readDaemonLine(reader, evsGitHookHeaderMaxByteCount)
	if err != nil {
		return fmt.Errorf("%w: no header", ErrEvsGitHookInvalid)
	}
	header := &EvsGitHookHeader{}
	if err := json.Unmarshal(line, header); err != nil {
		return fmt.Errorf("%w: a header that does not parse", ErrEvsGitHookInvalid)
	}
	session := self.receiveSession(header.Session)
	if session == nil {
		fmt.Fprintln(stderr, "ur: this push's receive session is not open in the daemon")
		return exit(1)
	}
	receiver := session.Mount.receiver
	stdin := &evsGitHookStdinReader{reader: reader}
	code := 1
	switch hook {
	case EvsGitHookPreReceive:
		code = receiver.preReceive(ctx, session, header, stdin, stdout, stderr)
	case EvsGitHookProcReceive:
		code = receiver.procReceive(ctx, session, stdin, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "ur: no such git hook")
	}
	return exit(byte(code))
}

// Ends a hook session that nothing serves: message on its stderr, and exit 1, which refuses the push.
func RefuseEvsGitHook(stream io.Writer, message string) error {
	if err := writeEvsGitHookFrame(stream, evsGitHookStderr, []byte(message+"\n")); err != nil {
		return err
	}
	return writeEvsGitHookFrame(stream, evsGitHookExit, []byte{1})
}

// What a relay of one hook runs on.
type EvsGitHookRelayArgs struct {
	// pre-receive or proc-receive.
	Hook string
	// Opens the daemon's session in its git-hook mode for Hook, its hello answered: ur's DialDaemon's stream.
	Dial func(ctx context.Context) (io.ReadWriteCloser, error)
	// The hook's environment.
	Getenv func(name string) string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Relays one hook to the daemon (ur git-hook <name>), answering the exit code the daemon sends; 1 for anything that
// stops it first, which refuses the push.
func EvsGitHookRelay(ctx context.Context, args *EvsGitHookRelayArgs) int {
	fail := func(format string, values ...any) int {
		fmt.Fprintf(args.Stderr, "ur git-hook: "+format+"\n", values...)
		return 1
	}
	header := &EvsGitHookHeader{Session: args.Getenv(EvsGitSessionVariable)}
	if header.Session == "" {
		return fail("no receive session: this repository takes pushes only through ur's daemon")
	}
	if args.Hook == EvsGitHookPreReceive {
		header.ObjectDirectory = args.Getenv(evsGitObjectDirectoryVariable)
		header.AlternateObjectDirectories = args.Getenv(evsGitAlternateDirectoriesVariable)
	}
	stream, err := args.Dial(ctx)
	if err != nil {
		return fail("the daemon did not answer: %v", err)
	}
	defer stream.Close()
	encoded, err := json.Marshal(header)
	if err != nil {
		return fail("%v", err)
	}
	if _, err := stream.Write(append(encoded, '\n')); err != nil {
		return fail("the daemon closed the session")
	}
	go func() {
		buffer := make([]byte, evsGitHookFrameMaxByteCount)
		for {
			n, err := args.Stdin.Read(buffer)
			if 0 < n {
				if writeEvsGitHookFrame(stream, evsGitHookStdin, buffer[:n]) != nil {
					return
				}
			}
			if err != nil {
				writeEvsGitHookFrame(stream, evsGitHookStdinEnd, nil)
				return
			}
		}
	}()
	for {
		channel, payload, err := readEvsGitHookFrame(stream)
		if err != nil {
			return fail("the daemon ended the session")
		}
		switch channel {
		case evsGitHookStdout:
			args.Stdout.Write(payload)
		case evsGitHookStderr:
			args.Stderr.Write(payload)
		case evsGitHookExit:
			if len(payload) != 1 {
				return fail("the daemon's exit is not a code")
			}
			return int(payload[0])
		default:
			return fail("the daemon sent a frame of channel %d", channel)
		}
	}
}

// Whether path is dir or below it, both absolute, each read through its symbolic links as git reads it (macOS's /var
// is /private/var), so neither a link nor a .. leads outside.
func evsPathWithin(path string, dir string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(dir) {
		return false
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(realDir, realPath)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

// The quarantine's variables, each directory checked to lie inside the mount's bare repository: the only directories
// the daemon's git runs on for a hook.
func (self *EvsLocalRepo) quarantineEnvironment(header *EvsGitHookHeader) ([]string, error) {
	if header.ObjectDirectory == "" {
		return nil, nil
	}
	if !evsPathWithin(header.ObjectDirectory, self.BareDir) {
		return nil, fmt.Errorf("%w: a quarantine outside the mount's repository", ErrEvsGitHookInvalid)
	}
	env := []string{evsGitObjectDirectoryVariable + "=" + header.ObjectDirectory}
	if header.AlternateObjectDirectories != "" {
		for _, dir := range filepath.SplitList(header.AlternateObjectDirectories) {
			if !evsPathWithin(dir, self.BareDir) {
				return nil, fmt.Errorf("%w: an alternate object directory outside the mount's repository", ErrEvsGitHookInvalid)
			}
		}
		env = append(env, evsGitAlternateDirectoriesVariable+"="+header.AlternateObjectDirectories)
	}
	return env, nil
}
