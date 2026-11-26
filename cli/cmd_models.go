// ur models (DESIGN-COMPUTE §6.3, §6.5, §15.1, §16.4; R-INFER-1, D-INFER-7; INFER-M11-08): the catalog, local model
// pulls and the person's models key from the terminal, over the daemon's model methods (the root's infer_daemon.go,
// registered here with every other control method), each on the call's network:
//
//	ur models [--local | --tee | --provider=<p>] [--json]
//	    the catalog for this device and policy by canonical name: each model's label, efforts, whether this device may
//	    use it and why not, a local model's file and whether it is pulled, and its provider's disclosure line from the
//	    newest verified policy, none where the policy has none; the local model §6.5's defaults recommend
//	ur models pull <name>
//	    a local model and, on a desktop, its engine's files: progress by chunks done, resumed where a cut left it, and a
//	    chunk that fails its check every time stopping with download_corrupt naming it (CO-49); the pull runs in the
//	    daemon, so an interrupt stops the watching, not the pull
//	ur models remove <name>
//	    a local model's files, every state of them
//	ur models settings [--json]
//	    the person's models key (§16.4)
//	ur models set [--default=<name>] [--tee-only=<on|off>] [--sign-in-mail=<mode>] [--allow=<glob>...]
//	ur models set --harness=<h> --tier=<t> <name>
//	    a change to the models key: printed, then taken on a yes at /dev/tty, refused without a terminal and, by the
//	    daemon, to a caller with a harness process among its ancestors (DESIGN §5.8); a Confirm method, never MCP
//
// Every name and label printed comes from a signed source, the release manifest for a local model and the newest
// verified policy for a remote one; a name only the broker's catalog carries prints between the untrusted-data markers,
// so a process a run binds reads it as data. Every string passes HarnessSanitizeLine before it reaches the terminal.
// The daemon builds the instance's one local engine and pull here, which every network it hosts shares
// (startUrLocalInference): ur-engine beside ur, confined (INFER-M11-05), over <state>/engine and <state>/models.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur models's forms.
const urModelsUsage = "  ur models [--local | --tee | --provider=<p>] [--json] [--network=<net>]\n" +
	"  ur models pull <name> [--network=<net>]\n" +
	"  ur models remove <name> [--network=<net>]\n" +
	"  ur models settings [--json] [--network=<net>]\n" +
	"  ur models set [--default=<name>] [--tee-only=<on_off>] [--sign-in-mail=<mode>] [--allow=<glob>...] [--network=<net>]\n" +
	"  ur models set --harness=<h> --tier=<t> <name> [--network=<net>]"

// A model set changes nothing.
var errUrModelsSetNothing = errors.New("ur models set changes nothing: name --default, --tee-only, --sign-in-mail, --allow or a harness's tier")

// Registers ur models and the daemon's model and inference methods.
func init() {
	registerUrCommand(&urCommand{
		name:    "models",
		usage:   urModelsUsage,
		summary: "the models this device may use, local model pulls and the person's models key",
		run:     runUrModels,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urModelsMethods)
}

// The instance's local engine and pull (§6.5), which runUrDaemon builds and every hosted network shares; nil while none
// is built: before the daemon starts, or where its state is in memory.
var urDaemonLocalInference *urLocalInference

// What models.set answers a caller under a harness.
var errUrModelsSetUnderHarness = errors.New("the models key is set by a person, never under a harness process (§16.4)")

// Whether the call's process has a harness process of its network's runs among its ancestors; true where the daemon
// cannot name the caller or its network. A test replaces it.
var urModelsUnderHarness = func(ctx context.Context, call *sidecar.DaemonCall) bool {
	pid := urCallPid(call)
	if pid <= 0 || call.Sidecar == nil {
		return true
	}
	return call.Sidecar.HarnessAncestor(ctx, pid)
}

// The daemon's model and inference methods over its pull, on a target that hosts Sidecars.
func urModelsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	args := &sidecar.DaemonInferArgs{}
	if local := urDaemonLocalInference; local != nil {
		args.Pull, args.Ctx, args.Settings = local.pull, local.ctx, local.settings
	}
	return urModelsGuardMethods(sidecar.DaemonInferMethods(args))
}

// methods with models.set refused under a harness before its handler runs, as the root's handler refuses it too; the
// rest as they are.
func urModelsGuardMethods(methods []*sidecar.DaemonMethod) []*sidecar.DaemonMethod {
	guarded := []*sidecar.DaemonMethod{}
	for _, method := range methods {
		if method.Name != sidecar.DaemonMethodModelsSet {
			guarded = append(guarded, method)
			continue
		}
		copied := *method
		handler := method.Handler
		copied.Handler = func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			if urModelsUnderHarness(ctx, call) {
				return nil, errUrModelsSetUnderHarness
			}
			return handler(ctx, call)
		}
		guarded = append(guarded, &copied)
	}
	return guarded
}

// The instance's local engine, ur-engine's process client, and the pull every network's models.pull takes.
type urLocalInference struct {
	ctx      context.Context
	settings *sidecar.InferSettings
	engine   *sidecar.InferEngineProcess
	pull     *sidecar.InferPull
}

// What a pull reaches the api and the engine's release through: a hosted network's api transport, bound to its egress,
// the first the daemon hosts, since the downloads carry no credential of any network's (CO-49).
type urDaemonApiTransport struct {
	daemon *sidecar.Daemon
}

// See http.RoundTripper.
func (self *urDaemonApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	for _, hosted := range self.daemon.Sidecars() {
		if transport := hosted.Sidecar.InferDownloadTransport(); transport != nil {
			return transport.RoundTrip(request)
		}
	}
	if request.Body != nil {
		request.Body.Close()
	}
	return nil, errors.New("no network runs on this daemon to pull a model through")
}

// The instance's local engine and pull over stateDirectory's engine and models, which the daemon closes at its end;
// nil, logged, where they do not build, which leaves every network with no local engine.
func startUrLocalInference(ctx context.Context, stateDirectory string, settings *sidecar.SidecarSettings, daemon *sidecar.Daemon, log sidecar.Logger) *urLocalInference {
	inferSettings := settings.Infer
	if inferSettings == nil {
		inferSettings = sidecar.DefaultInferSettings()
	}
	local := &urLocalInference{ctx: ctx, settings: inferSettings}
	pull, err := sidecar.NewInferPull(&sidecar.InferPullArgs{
		ApiUrl:          settings.ApiUrl,
		Transport:       &urDaemonApiTransport{daemon: daemon},
		ModelDirectory:  sidecar.InferModelDirectory(stateDirectory),
		EngineDirectory: sidecar.InferEngineDirectory(stateDirectory),
		Device: func(ctx context.Context) (*sidecar.InferDeviceCapabilities, error) {
			return local.engine.Capabilities(ctx)
		},
		Settings: inferSettings,
		Clock:    settings.Clock,
		Log:      log,
	})
	if err != nil {
		log.Warningf("[ur]no local model pulls here: %s", err)
		return nil
	}
	engine, err := sidecar.NewInferEngineProcess(&sidecar.InferEngineProcessArgs{
		EngineDirectory: sidecar.InferEngineDirectory(stateDirectory),
		ModelDirectory:  sidecar.InferModelDirectory(stateDirectory),
		StateDirectory:  stateDirectory,
		Models:          pull,
		Settings:        inferSettings,
		Clock:           settings.Clock,
		Log:             log,
	})
	if err != nil {
		log.Warningf("[ur]no local engine runs here: %s", err)
		return nil
	}
	local.pull, local.engine = pull, engine
	return local
}

// Makes the instance's engine running's local engine.
func (self *urLocalInference) attach(running *sidecar.Sidecar, log sidecar.Logger) {
	if self == nil {
		return
	}
	if err := running.SetInferLocalEngine(self.engine); err != nil {
		log.Warningf("[ur]a network runs no local model: %s", err)
	}
}

// Ends every helper.
func (self *urLocalInference) close() {
	if self != nil {
		self.engine.Close()
	}
}

// Calls a control method of the daemon with no bound but ctx's, each notification it sends handed to notified: a
// pull's progress and a prompt's events, which run as long as they take. The dial is bounded as every call's is.
func urCallDaemonFollowing(ctx context.Context, cli *urCli, method string, params any, confirmed bool, result any,
	notified func(method string, params json.RawMessage)) error {
	dialCtx, cancel := context.WithTimeout(ctx, cli.settings.CallTimeout)
	client, err := cli.connectDaemon(dialCtx, cli.hello(sidecar.DaemonModeControl), nil)
	cancel()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.CallNotified(ctx, method, params, confirmed, result, notified)
}

// ur models: a subcommand where docopt matched one, else the list.
func runUrModels(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	jsonOut, _ := options.Bool("--json")
	switch {
	case urOptionBool(options, "pull"):
		name, _ := options.String("<name>")
		return runUrModelsPull(ctx, cli, network, name)
	case urOptionBool(options, "remove"):
		name, _ := options.String("<name>")
		if err := cli.callDaemon(ctx, sidecar.DaemonMethodModelsRemove, &sidecar.DaemonModelsRemoveParams{Network: network, Name: name}, false, nil); err != nil {
			return err
		}
		cli.printf("removed %s's files from this device\n", sidecar.HarnessSanitizeLine(name))
		return nil
	case urOptionBool(options, "settings"):
		return runUrModelsSettings(ctx, cli, network, jsonOut)
	case urOptionBool(options, "set"):
		return runUrModelsSet(ctx, cli, network, options)
	}
	params := &sidecar.DaemonModelsListParams{Network: network}
	params.Local = urOptionBool(options, "--local")
	params.Tee = urOptionBool(options, "--tee")
	params.Provider, _ = options.String("--provider")
	listing := &sidecar.InferModelsListing{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodModelsList, params, false, listing); err != nil {
		return err
	}
	if jsonOut {
		encoded, err := json.Marshal(listing)
		if err != nil {
			return err
		}
		cli.stdout.Write(sidecar.HarnessJsonTerminalSafe(append(encoded, '\n')))
		return nil
	}
	for _, line := range urModelsListingLines(listing) {
		cli.printf("%s\n", line)
	}
	return nil
}

// A name for the terminal: plain where a signed source vouches for it, else between the untrusted-data markers.
func urModelsName(name string, signed bool) string {
	if signed {
		return sidecar.HarnessSanitizeLine(name)
	}
	return sidecar.ComputeUntrustedBegin + " " + sidecar.HarnessSanitizeLine(name) + " " + sidecar.ComputeUntrustedEnd
}

// A size in bytes as a person reads it.
func urModelsSize(byteCount int64) string {
	const gigabyte = 1000 * 1000 * 1000
	const megabyte = 1000 * 1000
	switch {
	case gigabyte <= byteCount:
		return fmt.Sprintf("%.2f GB", float64(byteCount)/gigabyte)
	case megabyte <= byteCount:
		return fmt.Sprintf("%.1f MB", float64(byteCount)/megabyte)
	}
	return fmt.Sprintf("%d bytes", byteCount)
}

// The listing as the terminal shows it: a line a model, its disclosure line indented under it, then why no local or
// remote model is offered, and the recommendation.
func urModelsListingLines(listing *sidecar.InferModelsListing) []string {
	lines := []string{}
	for _, entry := range listing.Entries {
		efforts := []string{}
		for _, effort := range entry.Efforts {
			efforts = append(efforts, string(effort))
		}
		parts := []string{
			urModelsName(entry.Name, entry.Signed),
			urModelsName(string(entry.Label), entry.Signed),
			strings.Join(efforts, "|"),
		}
		if entry.Local != nil {
			state := "not pulled"
			switch entry.Local.State {
			case sidecar.InferPullFileWhole:
				state = "pulled"
			case sidecar.InferPullFilePart:
				state = "partly pulled"
			}
			parts = append(parts, urModelsSize(entry.Local.ByteCount)+", "+state)
		}
		if entry.Unavailable != "" {
			parts = append(parts, "unavailable: "+sidecar.HarnessSanitizeLine(entry.Unavailable))
		}
		if entry.Name == listing.Recommended {
			parts = append(parts, "recommended here")
		}
		lines = append(lines, strings.Join(parts, "  "))
		if entry.DisclosureLine != "" {
			lines = append(lines, "    "+sidecar.HarnessSanitizeLine(entry.DisclosureLine))
		}
	}
	if len(listing.Entries) == 0 {
		lines = append(lines, "no model is offered here")
	}
	if listing.LocalUnavailable != "" {
		lines = append(lines, "no local model: "+sidecar.HarnessSanitizeLine(listing.LocalUnavailable))
	}
	if listing.RemoteUnavailable != "" {
		lines = append(lines, "no remote model: "+sidecar.HarnessSanitizeLine(listing.RemoteUnavailable))
	}
	return lines
}

// One progress line: the file in hand and how far it is.
func urModelsPullLine(reply *sidecar.DaemonModelsPullReply) string {
	progress := reply.Progress
	if progress == nil {
		return fmt.Sprintf("%s: starting", sidecar.HarnessSanitizeLine(reply.Name))
	}
	file := sidecar.HarnessSanitizeLine(progress.File)
	if progress.Phase == sidecar.InferPullPhaseEngine {
		return fmt.Sprintf("engine %s (%d of %d): %s of %s", file, progress.FileIndex, progress.FileCount,
			urModelsSize(progress.DoneByteCount), urModelsSize(progress.ByteCount))
	}
	return fmt.Sprintf("model %s: %d of %d chunks done, %s of %s, from the %s", file, progress.DoneChunkCount,
		progress.ChunkCount, urModelsSize(progress.DoneByteCount), urModelsSize(progress.ByteCount), progress.Source)
}

// What a failed pull says: its code, the chunk download_corrupt names, and why.
func urModelsPullError(pullErr *sidecar.InferPullError) error {
	if pullErr == nil {
		return errors.New("the pull failed")
	}
	where := ""
	if pullErr.Chunk != nil {
		if *pullErr.Chunk < 0 {
			where = " at the index"
		} else {
			where = fmt.Sprintf(" at chunk %d", *pullErr.Chunk)
		}
	}
	fix := ""
	switch pullErr.Code {
	case string(sidecar.InferDownloadErrorCorrupt):
		fix = "; what passed is kept, so ur models pull again resumes there"
	case string(sidecar.InferDownloadErrorUnavailable), string(sidecar.InferErrorCanceled):
		fix = "; ur models pull again resumes at the first chunk missing"
	}
	return fmt.Errorf("%s%s: %s%s", pullErr.Code, where, sidecar.HarnessSanitizeLine(pullErr.Message), fix)
}

// ur models pull: the daemon's pull of name followed to its end, a line at each chunk.
func runUrModelsPull(ctx context.Context, cli *urCli, network string, name string) error {
	params := &sidecar.DaemonModelsPullParams{Network: network, Name: name, Follow: true}
	reply := &sidecar.DaemonModelsPullReply{}
	err := urCallDaemonFollowing(ctx, cli, sidecar.DaemonMethodModelsPull, params, false, reply, func(method string, raw json.RawMessage) {
		if method != sidecar.DaemonNotifyModelsPullProgress {
			return
		}
		progress := &sidecar.DaemonModelsPullReply{}
		if json.Unmarshal(raw, progress) == nil {
			cli.printf("%s\n", urModelsPullLine(progress))
		}
	})
	if err != nil {
		return err
	}
	if reply.State != sidecar.DaemonModelsPullDone {
		return urModelsPullError(reply.Error)
	}
	cli.printf("%s is on this device\n", sidecar.HarnessSanitizeLine(name))
	return nil
}

// The models key's lines.
func urModelsSettingsLines(settings *sidecar.InferModelsSettings) []string {
	lines := []string{}
	if settings.Unreadable {
		lines = append(lines, "the models key does not read, so every model is refused until it is set again: "+sidecar.HarnessSanitizeLine(settings.Reason))
	}
	defaultModel := settings.Default
	if defaultModel == "" {
		defaultModel = "none"
	}
	lines = append(lines, "default: "+sidecar.HarnessSanitizeLine(defaultModel))
	switch {
	case settings.Allow == nil:
		lines = append(lines, "allow: every model")
	case len(settings.Allow) == 0:
		lines = append(lines, "allow: no model")
	default:
		lines = append(lines, "allow: "+sidecar.HarnessSanitizeLine(strings.Join(settings.Allow, " ")))
	}
	teeOnly := "off"
	if settings.TeeOnly {
		teeOnly = "on"
	}
	lines = append(lines, "tee_only: "+teeOnly, "sign_in_mail: "+sidecar.HarnessSanitizeLine(settings.SignInMail))
	harnesses := []string{}
	for harness := range settings.Harness {
		harnesses = append(harnesses, harness)
	}
	slices.Sort(harnesses)
	for _, harness := range harnesses {
		tiers := []string{}
		for tier := range settings.Harness[harness] {
			tiers = append(tiers, tier)
		}
		slices.Sort(tiers)
		for _, tier := range tiers {
			lines = append(lines, fmt.Sprintf("harness %s %s: %s", sidecar.HarnessSanitizeLine(harness), sidecar.HarnessSanitizeLine(tier),
				sidecar.HarnessSanitizeLine(settings.Harness[harness][tier])))
		}
	}
	for _, warning := range settings.Warnings {
		lines = append(lines, "passed over: "+sidecar.HarnessSanitizeLine(warning))
	}
	return lines
}

// ur models settings.
func runUrModelsSettings(ctx context.Context, cli *urCli, network string, jsonOut bool) error {
	settings := &sidecar.InferModelsSettings{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodModelsSettings, &sidecar.DaemonModelsParams{Network: network}, false, settings); err != nil {
		return err
	}
	if jsonOut {
		encoded, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		cli.stdout.Write(sidecar.HarnessJsonTerminalSafe(append(encoded, '\n')))
		return nil
	}
	for _, line := range urModelsSettingsLines(settings) {
		cli.printf("%s\n", line)
	}
	return nil
}

// The change the set's options ask, refused where it changes nothing or an option does not read.
func urModelsSetParams(network string, options docopt.Opts) (*sidecar.DaemonModelsSetParams, error) {
	params := &sidecar.DaemonModelsSetParams{Network: network}
	changed := false
	if value, err := options.String("--default"); err == nil && value != "" {
		params.Default = &value
		changed = true
	}
	if value, err := options.String("--tee-only"); err == nil && value != "" {
		on := false
		switch value {
		case "on":
			on = true
		case "off":
		default:
			return nil, errors.New("--tee-only is on or off")
		}
		params.TeeOnly = &on
		changed = true
	}
	if value, err := options.String("--sign-in-mail"); err == nil && value != "" {
		if value != string(sidecar.HarnessSignInMailWithhold) && value != string(sidecar.HarnessSignInMailAllow) {
			return nil, errors.New("--sign-in-mail is withhold or allow")
		}
		params.SignInMail = &value
		changed = true
	}
	if globs, ok := options["--allow"].([]string); ok && 0 < len(globs) {
		allow := slices.Clone(globs)
		params.Allow = &allow
		changed = true
	}
	if harness, _ := options.String("--harness"); harness != "" {
		params.Harness = harness
		params.Tier, _ = options.String("--tier")
		params.Model, _ = options.String("<name>")
		changed = true
	}
	if !changed {
		return nil, errUrModelsSetNothing
	}
	return params, nil
}

// The change as the person reads it before saying yes: each field from what it is to what it would be.
func urModelsSetLines(now *sidecar.InferModelsSettings, params *sidecar.DaemonModelsSetParams) []string {
	lines := []string{}
	change := func(field string, from string, to string) {
		lines = append(lines, fmt.Sprintf("%s: %s -> %s", field, sidecar.HarnessSanitizeLine(from), sidecar.HarnessSanitizeLine(to)))
	}
	onOff := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	if params.Default != nil {
		change("default", now.Default, *params.Default)
	}
	if params.TeeOnly != nil {
		change("tee_only", onOff(now.TeeOnly), onOff(*params.TeeOnly))
	}
	if params.SignInMail != nil {
		change("sign_in_mail", now.SignInMail, *params.SignInMail)
	}
	if params.Allow != nil {
		from := "every model"
		if now.Allow != nil {
			from = strings.Join(now.Allow, " ")
		}
		change("allow", from, strings.Join(*params.Allow, " "))
	}
	if params.Harness != "" {
		change("harness "+params.Harness+" "+params.Tier, now.Harness[params.Harness][params.Tier], params.Model)
	}
	return lines
}

// ur models set: the change printed, a yes taken on /dev/tty, then the Confirm method; refused without a terminal.
func runUrModelsSet(ctx context.Context, cli *urCli, network string, options docopt.Opts) error {
	params, err := urModelsSetParams(network, options)
	if err != nil {
		return err
	}
	now := &sidecar.InferModelsSettings{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodModelsSettings, &sidecar.DaemonModelsParams{Network: network}, false, now); err != nil {
		return err
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	for _, line := range urModelsSetLines(now, params) {
		fmt.Fprintln(tty, line)
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "set the models key?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	written := &sidecar.InferModelsSettings{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodModelsSet, params, true, written); err != nil {
		return err
	}
	for _, line := range urModelsSettingsLines(written) {
		cli.printf("%s\n", line)
	}
	return nil
}
