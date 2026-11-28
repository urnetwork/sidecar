// LiveHarness: a real harness binary against a gateway, for the compute rota's per-release run (DESIGN-COMPUTE §14.10,
// §18's gateway row), where UR_CONFORMANCE_HARNESS names the binary. The run is the person's: `codex --profile ur
// exec <prompt>` under a temporary HOME holding the profile §8.8 gives `ur install-harness codex --gateway` to write
// (~/.codex/ur.config.toml: model_provider ur, the model, web_search disabled, the provider on the gateway's base URL
// with wire_api responses, external_web_access false, and a credential command), so the harness reaches the gateway
// through its own config, unchanged (R-CCTX-10). Until GW-M12-07's install lands, the profile is written here in §8.8's
// form, and its credential command is a script printing a token the caller minted for the run, in place of
// `ur gateway token --harness codex`, which needs the daemon.
//
// A host with no binary reads open: UR_CONFORMANCE_HARNESS unset, or naming nothing that runs. Open is never a pass:
// the conformance ledger records it as open, and only a run that exits 0 against the gateway passes.

package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The environment variable naming the harness binary a live run runs.
const ConformanceHarnessEnv = "UR_CONFORMANCE_HARNESS"

// What a live run reads, as the conformance ledger records a run: identifiers.
const (
	LiveResultPass = "pass"
	LiveResultFail = "fail"
	LiveResultOpen = "open"
)

// The live runner's settings (QD-702).
type LiveSettings struct {
	// How long the harness may take for its prompt: 10 minutes, past a remote model's slowest first token.
	RunTimeout time.Duration
	// How long --version may take: 30 seconds.
	VersionTimeout time.Duration
	// The most bytes of the harness's output a result keeps: 16 KiB.
	OutputByteCount int
	// The stream idle timeout the profile writes: §8.8's 300000 ms.
	StreamIdleTimeoutMillis int
}

// The defaults, the only place one is set.
func DefaultLiveSettings() *LiveSettings {
	return &LiveSettings{
		RunTimeout:              10 * time.Minute,
		VersionTimeout:          30 * time.Second,
		OutputByteCount:         16 * 1024,
		StreamIdleTimeoutMillis: 300000,
	}
}

// What a live run runs.
type LiveHarnessArgs struct {
	// The harness: codex.
	Harness string
	// The binary; empty takes UR_CONFORMANCE_HARNESS's value.
	Binary string
	// The gateway's base URL, and a token minted for the run, which the profile's credential command prints.
	BaseUrl string
	Token   string
	// The canonical name the profile sets as the harness's model.
	Model string
	// What the harness is asked.
	Prompt string
	// Where the temporary HOME is made: a test's temporary directory.
	Directory string
	// Nil takes DefaultLiveSettings.
	Settings *LiveSettings
}

// What a live run read.
type LiveResult struct {
	// LiveResultPass, LiveResultFail or LiveResultOpen.
	Result string
	// What the binary's --version printed: the release the run got.
	Version string
	// Why it did not pass.
	Reason string
	// The harness's output, at most the settings' bytes, the end kept.
	Output string
}

// A live run (see the file header).
type LiveHarness struct {
	args     *LiveHarnessArgs
	settings *LiveSettings
}

// A live run over args.
func NewLiveHarness(args *LiveHarnessArgs) *LiveHarness {
	settings := args.Settings
	if settings == nil {
		settings = DefaultLiveSettings()
	}
	return &LiveHarness{args: args, settings: settings}
}

// The binary a run would run, and why it reads open where there is none.
func (self *LiveHarness) binary() (string, string) {
	binary := self.args.Binary
	if binary == "" {
		binary = os.Getenv(ConformanceHarnessEnv)
	}
	if binary == "" {
		return "", ConformanceHarnessEnv + " names no " + self.args.Harness + " binary"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Sprintf("no %s binary runs at %q", self.args.Harness, binary)
	}
	return path, ""
}

// The end of output, at most the settings' bytes.
func (self *LiveHarness) tail(output []byte) string {
	if len(output) <= self.settings.OutputByteCount {
		return string(output)
	}
	return string(output[len(output)-self.settings.OutputByteCount:])
}

// Runs the harness once (see the file header). Open where no binary runs; fail where the harness does not exit 0 or
// its profile cannot be written.
func (self *LiveHarness) Run(ctx context.Context) *LiveResult {
	binary, openReason := self.binary()
	if binary == "" {
		return &LiveResult{Result: LiveResultOpen, Reason: openReason}
	}
	if self.args.Harness != HarnessCodex {
		return &LiveResult{Result: LiveResultOpen, Reason: "no live run is built for " + self.args.Harness}
	}
	result := &LiveResult{}
	versionCtx, cancel := context.WithTimeout(ctx, self.settings.VersionTimeout)
	versionOutput, err := exec.CommandContext(versionCtx, binary, "--version").CombinedOutput()
	cancel()
	if err != nil {
		return &LiveResult{Result: LiveResultFail, Reason: fmt.Sprintf("--version: %v", err), Output: self.tail(versionOutput)}
	}
	result.Version = strings.TrimSpace(string(versionOutput))
	home := filepath.Join(self.args.Directory, "home")
	codexHome := filepath.Join(home, ".codex")
	if err := self.writeCodexProfile(home, codexHome); err != nil {
		return &LiveResult{Result: LiveResultFail, Version: result.Version, Reason: fmt.Sprintf("the profile: %v", err)}
	}
	workdir := filepath.Join(self.args.Directory, "work")
	if err := os.MkdirAll(workdir, 0o700); err != nil {
		return &LiveResult{Result: LiveResultFail, Version: result.Version, Reason: err.Error()}
	}
	runCtx, cancel := context.WithTimeout(ctx, self.settings.RunTimeout)
	defer cancel()
	command := exec.CommandContext(runCtx, binary, "--profile", "ur", "exec", "--skip-git-repo-check", self.args.Prompt)
	command.Dir = workdir
	command.Env = append(os.Environ(), "HOME="+home, "CODEX_HOME="+codexHome)
	output, err := command.CombinedOutput()
	result.Output = self.tail(output)
	if err != nil {
		result.Result, result.Reason = LiveResultFail, fmt.Sprintf("%s exited: %v", self.args.Harness, err)
		return result
	}
	result.Result = LiveResultPass
	return result
}

// §8.8's Codex profile under home, its credential command a script printing the run's token.
func (self *LiveHarness) writeCodexProfile(home string, codexHome string) error {
	if self.args.BaseUrl == "" || self.args.Token == "" || self.args.Model == "" {
		return errors.New("a live run needs the gateway's base URL, a token and a model")
	}
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return err
	}
	tokenCommand := filepath.Join(home, "ur-gateway-token")
	script := "#!/bin/sh\nprintf '%s' " + shellQuote(self.args.Token) + "\n"
	if err := os.WriteFile(tokenCommand, []byte(script), 0o700); err != nil {
		return err
	}
	profile := bytes.Buffer{}
	fmt.Fprintf(&profile, "model_provider = %s\n", tomlString("ur"))
	fmt.Fprintf(&profile, "model = %s\n", tomlString(self.args.Model))
	fmt.Fprintf(&profile, "web_search = %s\n", tomlString("disabled"))
	fmt.Fprintf(&profile, "\n[model_providers.ur]\n")
	fmt.Fprintf(&profile, "name = %s\n", tomlString("URnetwork compute"))
	fmt.Fprintf(&profile, "base_url = %s\n", tomlString(strings.TrimSuffix(self.args.BaseUrl, "/")+"/v1"))
	fmt.Fprintf(&profile, "wire_api = %s\n", tomlString("responses"))
	fmt.Fprintf(&profile, "stream_idle_timeout_ms = %d\n", self.settings.StreamIdleTimeoutMillis)
	fmt.Fprintf(&profile, "\n[model_providers.ur.capabilities]\nexternal_web_access = false\n")
	fmt.Fprintf(&profile, "\n[model_providers.ur.auth]\ncommand = %s\nargs = []\n", tomlString(tokenCommand))
	return os.WriteFile(filepath.Join(codexHome, "ur.config.toml"), profile.Bytes(), 0o600)
}

// A TOML basic string.
func tomlString(value string) string {
	return strconv.Quote(value)
}

// A POSIX shell single-quoted word.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
