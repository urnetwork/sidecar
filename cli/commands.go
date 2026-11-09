// ur's dispatch (§4.10, §5.8): one registry of commands, each in its own cmd_<name>.go, which registers itself with
// registerUrCommand at init, so an area adds a command without touching a shared file (C-21). --instance is global,
// taken off the arguments before a command parses its own with docopt. Bare ur speaks MCP when stdin is not a
// terminal and prints help on one (owner decision 57); ur run as git-remote-ur goes to that entry (§4.10), which
// §11's track registers.
//
// Spellings DESIGN.md does not state follow plan-CORE-cli-ui-missing's answers (ur keychain pass, ur lock, --replace,
// ur login --recover, --port), each a one-line rename here once cli/UI.md is copied in (QD-024).
//
// Nothing here writes a log to stdout, which an MCP relay owns: a command's output is for the person and its logs go
// to stderr. Nothing here takes a secret from argv, the environment or stdin: a pass comes only from the terminal
// (tty.go), and the one credential argv carries, `ur connect --token`, is a single-use auth key spent by the
// enrollment it starts.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur's exit codes.
const (
	urExitOk      = 0
	urExitFailed  = 1
	urExitUsage   = 2
	urProgramName = "ur"
	// argv[0] that makes this binary git's remote helper (§4.10)
	urGitRemoteName = "git-remote-ur"
)

// A command a person types after ur.
type urCommand struct {
	// The word that selects it.
	name string
	// Its docopt usage lines, each starting "ur <name>", without the "Usage:" heading.
	usage string
	// One line for the help listing.
	summary string
	// Runs it with what docopt parsed. An error is printed to stderr, and ur exits 1.
	run func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// Every command, by name. Written only by registerUrCommand, at init.
var urCommands = map[string]*urCommand{}

// The entry ur runs as git-remote-ur, which §11's track registers. Nil until then.
var urGitRemoteEntry func(ctx context.Context, cli *urCli, args []string) int

// Adds a command. A second command of one name is a programming error, found at start.
func registerUrCommand(command *urCommand) {
	if command == nil || command.name == "" || command.run == nil || urCommands[command.name] != nil {
		panic(fmt.Sprintf("ur command %q registered twice or without a run", command.name))
	}
	urCommands[command.name] = command
}

// Tunables of the ur process itself.
type urSettings struct {
	// How long a relay or a control call waits for a daemon it spawned to answer: 10 s, past a cold start's
	// keychain and Argon2id run on a slow host.
	SpawnWaitTimeout time.Duration
	// How often it dials again while it waits: 50 ms.
	SpawnRetryInterval time.Duration
	// How long a control call may take, a person's confirmation aside: SidecarLocalSettings.RequestTimeout's 30 s
	// and a little more, so the daemon's own bound answers first.
	CallTimeout time.Duration
}

// The defaults, a fresh value each call.
func defaultUrSettings() *urSettings {
	return &urSettings{
		SpawnWaitTimeout:   10 * time.Second,
		SpawnRetryInterval: 50 * time.Millisecond,
		CallTimeout:        35 * time.Second,
	}
}

// What `ur login` gets from TEAM-M1-08's ur-cli in this process (§5.6, §7.8): a single-use, user-owned auth key of
// at most 5 min, and drop, which erases the OAuth token it was minted with. invite is --invite's link, or empty.
type urLoginFunction func(ctx context.Context, cli *urCli, invite string) (authKey string, drop func(), err error)

// One ur process: its instance, its streams and the seams a test replaces. Every field is set by newUrCli.
type urCli struct {
	settings *urSettings
	instance string
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	// whether stdin is a terminal, which decides what bare ur does
	stdinIsTerminal func() bool
	// opens the controlling terminal for a pass or a confirmation, never stdin
	openTty func() (urTty, error)
	// the instance's socket or pipe
	socketPath func(instance string) (string, error)
	// dials the daemon and sends the hello
	dialDaemon func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error)
	// starts `ur daemon` detached with args after "daemon", its output going nowhere near stdout
	spawnDaemon func(args []string) error
	// TEAM-M1-08's ur-cli login, nil until it lands
	login urLoginFunction
	// §16's offer to register a presence key after a login, nil until it lands
	offerPresenceKey func(ctx context.Context, cli *urCli) error
	// fills a daemon's service urls from §18.9's host table (cmd_daemon.go)
	serviceUrls func(settings *sidecar.SidecarSettings) error
	// a process's environment, for UR_INSTANCE
	getenv func(name string) string
	// the working directory and pid a hello names
	cwd func() (string, error)
	pid int
}

// This process's ur.
func newUrCli() *urCli {
	return &urCli{
		settings:        defaultUrSettings(),
		stdin:           os.Stdin,
		stdout:          os.Stdout,
		stderr:          os.Stderr,
		stdinIsTerminal: func() bool { return isTerminal(os.Stdin) },
		openTty:         openOsTty,
		socketPath:      sidecar.DaemonSocketPath,
		dialDaemon:      sidecar.DialDaemon,
		spawnDaemon:     spawnDetachedDaemon,
		login:           urcliLoginEntry,
		serviceUrls:     urServiceUrlsFromHostTable,
		getenv:          os.Getenv,
		cwd:             os.Getwd,
		pid:             os.Getpid(),
	}
}

// The ur-cli login TEAM-M1-08 registers. Nil until it lands, which `ur login` refuses (C-14).
var urcliLoginEntry urLoginFunction

// Runs one ur invocation, args as os.Args gives them, and answers the exit code.
func (self *urCli) main(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return urExitUsage
	}
	if base := strings.TrimSuffix(filepath.Base(args[0]), ".exe"); base == urGitRemoteName {
		if urGitRemoteEntry == nil {
			fmt.Fprintln(self.stderr, "git-remote-ur: the git remote helper is not built yet")
			return urExitFailed
		}
		return urGitRemoteEntry(ctx, self, args[1:])
	}
	rest, instanceFlag, err := takeInstanceFlag(args[1:])
	if err != nil {
		fmt.Fprintf(self.stderr, "ur: %s\n", err)
		return urExitUsage
	}
	instance := instanceFlag
	if instance == "" {
		instance = self.getenv("UR_INSTANCE")
	}
	self.instance, err = sidecar.SidecarInstanceName(instance)
	if err != nil {
		fmt.Fprintf(self.stderr, "ur: %s\n", err)
		return urExitUsage
	}

	if len(rest) == 0 {
		if self.stdinIsTerminal() {
			self.printHelp(self.stdout)
			return urExitOk
		}
		// a harness spawned bare ur on a pipe: speak MCP (owner decision 57)
		return self.runCommand(ctx, urCommands["mcp"], []string{"mcp"})
	}
	switch rest[0] {
	case "--version", "version":
		fmt.Fprintf(self.stdout, "ur %s\n", sidecar.Version)
		return urExitOk
	case "-h", "--help", "help":
		self.printHelp(self.stdout)
		return urExitOk
	}
	command, ok := urCommands[rest[0]]
	if !ok {
		fmt.Fprintf(self.stderr, "ur: no command %q\n", rest[0])
		self.printHelp(self.stderr)
		return urExitUsage
	}
	return self.runCommand(ctx, command, rest)
}

// Parses args with command's usage and runs it.
func (self *urCli) runCommand(ctx context.Context, command *urCommand, args []string) int {
	if command == nil {
		fmt.Fprintln(self.stderr, "ur: that command is not built yet")
		return urExitFailed
	}
	if slices.Contains(args[1:], "-h") || slices.Contains(args[1:], "--help") {
		fmt.Fprintf(self.stdout, "Usage:\n%s\n", command.usage)
		return urExitOk
	}
	parser := &docopt.Parser{HelpHandler: docopt.NoHelpHandler, SkipHelpFlags: true}
	options, err := parser.ParseArgs("Usage:\n"+command.usage+"\n", append([]string{}, args...), "")
	if err != nil {
		fmt.Fprintf(self.stderr, "Usage:\n%s\n", command.usage)
		return urExitUsage
	}
	if err := command.run(ctx, self, options); err != nil {
		// a credential never reaches an error's text: errors carry codes, and RedactAuthKey covers a key
		fmt.Fprintf(self.stderr, "ur %s: %s\n", command.name, sidecar.RedactAuthKey(err.Error()))
		return urExitFailed
	}
	return urExitOk
}

// Every command's summary, sorted.
func (self *urCli) printHelp(out io.Writer) {
	fmt.Fprintln(out, "ur: the URnetwork sidecar. Run with no command on a pipe, ur speaks MCP.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage: ur [--instance=<name>] <command> [options]")
	fmt.Fprintln(out, "")
	names := []string{}
	for name := range urCommands {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Fprintf(out, "  %-18s %s\n", name, urCommands[name].summary)
	}
}

// args without the global --instance, given as --instance <name> or --instance=<name> anywhere before a lone --,
// and its value.
func takeInstanceFlag(args []string) ([]string, string, error) {
	rest := []string{}
	instance := ""
	for i := 0; i < len(args); i += 1 {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if value, ok := strings.CutPrefix(arg, "--instance="); ok {
			instance = value
			continue
		}
		if arg == "--instance" {
			if len(args) <= i+1 {
				return nil, "", errors.New("--instance takes a name")
			}
			instance = args[i+1]
			i += 1
			continue
		}
		rest = append(rest, arg)
	}
	return rest, instance, nil
}

// The hello of a session of mode, naming this process.
func (self *urCli) hello(mode string) *sidecar.DaemonHello {
	hello := &sidecar.DaemonHello{Mode: mode, Version: sidecar.Version, Pid: int64(self.pid)}
	if cwd, err := self.cwd(); err == nil {
		hello.Cwd = cwd
	}
	return hello
}

// A session of hello's mode with the instance's daemon, spawning one when none answers (§5.8). spawnArgs are what
// follows `ur daemon` for a daemon spawned here. A daemon of another version is refused, never relayed through.
func (self *urCli) connectDaemon(ctx context.Context, hello *sidecar.DaemonHello, spawnArgs []string) (*sidecar.DaemonClient, error) {
	socketPath, err := self.socketPath(self.instance)
	if err != nil {
		return nil, err
	}
	refused := func(err error) error {
		var refusal *sidecar.DaemonHelloRefusal
		if !errors.As(err, &refusal) {
			return nil
		}
		if refusal.Code == sidecar.DaemonHelloErrorVersionSkew {
			return fmt.Errorf("the daemon of instance %s runs version %q, and this ur is %q: stop it and run ur again", self.instance, refusal.Version, sidecar.Version)
		}
		return fmt.Errorf("the daemon refused the session: %s", refusal.Code)
	}
	client, err := self.dialDaemon(ctx, socketPath, hello)
	if err == nil {
		return client, nil
	}
	if refusal := refused(err); refusal != nil {
		return nil, refusal
	}
	// none answers: spawn one, once, and wait for it
	if err := self.spawnDaemon(append([]string{"--instance", self.instance, "--auto-spawned"}, spawnArgs...)); err != nil {
		return nil, fmt.Errorf("no daemon answers and none could start: %w", err)
	}
	deadline := time.After(self.settings.SpawnWaitTimeout)
	for {
		client, err := self.dialDaemon(ctx, socketPath, hello)
		if err == nil {
			return client, nil
		}
		if refusal := refused(err); refusal != nil {
			return nil, refusal
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("the daemon it started did not answer: %w", err)
		case <-time.After(self.settings.SpawnRetryInterval):
		}
	}
}

// Calls a control method of the instance's daemon, spawning one when none answers. confirmed says the person
// confirmed it on /dev/tty (D-CORE-13).
func (self *urCli) callDaemon(ctx context.Context, method string, params any, confirmed bool, result any, spawnArgs ...string) error {
	callCtx, cancel := context.WithTimeout(ctx, self.settings.CallTimeout)
	defer cancel()
	client, err := self.connectDaemon(callCtx, self.hello(sidecar.DaemonModeControl), spawnArgs)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Call(callCtx, method, params, confirmed, result)
}

// Prints to stdout, for the person.
func (self *urCli) printf(format string, args ...any) {
	fmt.Fprintf(self.stdout, format, args...)
}

// Decodes exactly one JSON value into value, refusing a field it does not know.
func jsonUnmarshalStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("more than one value")
	}
	return nil
}
