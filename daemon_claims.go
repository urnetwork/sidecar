//go:build !js && !ios && !android && !sdk_mobile_bind

// The claims setting (§16.10's claims row, §16.11's runs paragraph, D-CORE-18; owner decision 170; QD-116, QD-577;
// CORE-M6-02): whether, and how, a harness session's run is announced in its team's directory, off < prompt < auto, per
// member and per project, fixed for each session with its instructions.
//
//	team      auto, unless an Owner or Admin sets the team's default through ServiceSettings.directory.runs (§7.9;
//	          ConfigState.DirectorySettings), a value this build does not know reading off. A network whose verified
//	          state holds no directory is personal, or cannot be judged, and announces nothing: off
//	member    the harness config's claims, {"default", "projects": {<project key>: value}} with agents.<label>'s
//	          override, in the author's vault (plan-MCP-harness-config-schema), read through SidecarClaimsConfig; the
//	          member's value for the project, else its default, replaces the team's. None read, the team's stands, as
//	          for a tagged sidecar, which reads no vault (QD-577)
//	.ur       a committed .ur's claims narrows that value at once and widens it only once the member has confirmed it
//	          for the project, on /dev/tty or in an app and never through MCP, since a committed file must not widen
//	          what a member shares (D-CORE-18). Until then the session runs the narrower value and names the wider one
//	          pending
//	confirm   the person's own choice for the project, made against the .ur value then committed, in the network's
//	          sealed claims/ state (directory.claims and directory.claims.confirm, daemon_directory.go): it decides
//	          while .ur still says the same, so a changed .ur is judged afresh; a choice wider than the session's value
//	          is the person's act and takes the Confirm method, a narrower one needs none
//	session   a session's value is resolved once, at its first ask, and kept: a later change to .ur, the harness
//	          config, the team's default or a confirmation leaves an open session as it began (DaemonSessionClaims).
//	          go-sdk's Instructions are per Server, so MCP-M6-01 picks a session's Server by its value at the session's
//	          start, and RECORD-M6-16 keeps a run's value from its SessionStart
//
// A sidecar that cannot read its state closes toward announcing nothing: off.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// §16.10's claims values, ordered: a larger one shares more. Zero is none.
type SidecarClaims int

const (
	// Announces nothing: the default in personal networks.
	SidecarClaimsOff SidecarClaims = 1
	// The instructions ask the agent to claim its task, and the claim announces the run.
	SidecarClaimsPrompt SidecarClaims = 2
	// Announces each run at its start: the default in team networks.
	SidecarClaimsAuto SidecarClaims = 3
)

// A claims value that is none of §16.10's.
var ErrSidecarClaims = errors.New("claims is off, prompt or auto")

// The network's claims state: claims/ under file class claims, one file a project, named by its key's SHA-256.
const (
	sidecarClaimsDirectoryName = "claims"
	sidecarClaimsClass         = "claims"
)

// Where a session's value came from.
const (
	// A personal network, or one whose state names no directory: off.
	SidecarClaimsSourcePersonal = "personal"
	// The team's default.
	SidecarClaimsSourceTeam = "team"
	// The member's default in the harness config.
	SidecarClaimsSourceMember = "member"
	// The member's value for the project in the harness config.
	SidecarClaimsSourceProject = "project"
	// .ur's narrower value.
	SidecarClaimsSourceCommitted = "committed"
	// The person's confirmed choice for the project.
	SidecarClaimsSourceConfirmed = "confirmed"
)

// The value text names, or ErrSidecarClaims.
func ParseSidecarClaims(text string) (SidecarClaims, error) {
	switch text {
	case "off":
		return SidecarClaimsOff, nil
	case "prompt":
		return SidecarClaimsPrompt, nil
	case "auto":
		return SidecarClaimsAuto, nil
	}
	return 0, ErrSidecarClaims
}

// off, prompt or auto, "" for none.
func (self SidecarClaims) String() string {
	switch self {
	case SidecarClaimsOff:
		return "off"
	case SidecarClaimsPrompt:
		return "prompt"
	case SidecarClaimsAuto:
		return "auto"
	}
	return ""
}

// Whether it is one of §16.10's values.
func (self SidecarClaims) Known() bool {
	return SidecarClaimsOff <= self && self <= SidecarClaimsAuto
}

// ServiceSettings.directory.runs as a claims value: auto, prompt or off, and off for anything else.
func sidecarClaimsOfRuns(runs protocol.DirectoryRunsMode) SidecarClaims {
	switch runs {
	case protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_AUTO:
		return SidecarClaimsAuto
	case protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_PROMPT:
		return SidecarClaimsPrompt
	}
	return SidecarClaimsOff
}

// A member's claims setting as the harness config holds it, agents.<label>'s override applied by its reader.
type SidecarMemberClaims struct {
	// The member's default for every project; 0 for none.
	Default SidecarClaims
	// By SidecarProjectKey; a value that is not Known is passed over.
	Projects map[string]SidecarClaims
}

// The member's claims from the harness config in the author's vault (plan-MCP-harness-config-schema #1, QD-577): its
// reader is the vault's, which applies agents.<label>'s override. nil with no error when the config sets none or
// cannot be read, so the team's default stands, and the reader names a config_unreadable gap in the run's Coverage.
// Safe for concurrent use.
type SidecarClaimsConfig interface {
	MemberClaims(ctx context.Context, networkId Id, agentLabel string) (*SidecarMemberClaims, error)
}

// The person's choice of a project's value, made on /dev/tty, in an app, or without either for a narrowing, against
// the .ur value committed then.
type SidecarClaimsConfirmation struct {
	ProjectKey string `json:"project_key"`
	// .ur's value when the person chose, "" for none: the choice decides while .ur says the same.
	Committed string `json:"committed"`
	Claims    string `json:"claims"`
	// When it was made, on the daemon's clock.
	ConfirmedMillis int64 `json:"confirmed_millis"`
}

// What a session's value rests on.
type SidecarClaimsInputs struct {
	// The network's verified state holds a team directory.
	Team bool
	// ServiceSettings.directory.runs as ConfigState.DirectorySettings honors it; 0 for auto, §16.11's default.
	TeamDefault SidecarClaims
	// The member's harness config setting; nil for none read.
	Member *SidecarMemberClaims
	// The session's project (SidecarProjectKey).
	ProjectKey string
	// .ur's claims; 0 for none.
	Committed SidecarClaims
	// The person's choice for the project; nil for none.
	Confirmation *SidecarClaimsConfirmation
}

// What a session runs under.
type SidecarClaimsResolution struct {
	Claims SidecarClaims
	// .ur's wider value, waiting for the member's confirmation; 0 when none waits.
	Pending SidecarClaims
	// SidecarClaimsSource*.
	Source string
	// The session's project and the label its runs announce when it is no evs repo (SidecarProject.ProjectLabel).
	ProjectKey   string
	ProjectLabel string
}

// D-CORE-18's rule over inputs (see the file header). Never answers a value wider than the member's, or the team's
// where the member sets none, but for the person's own confirmed choice.
func ResolveSidecarClaims(inputs *SidecarClaimsInputs) *SidecarClaimsResolution {
	resolution := &SidecarClaimsResolution{ProjectKey: inputs.ProjectKey}
	if !inputs.Team {
		resolution.Claims = SidecarClaimsOff
		resolution.Source = SidecarClaimsSourcePersonal
		return resolution
	}
	base := SidecarClaimsAuto
	source := SidecarClaimsSourceTeam
	if inputs.TeamDefault != 0 {
		base = SidecarClaimsOff
		if inputs.TeamDefault.Known() {
			base = inputs.TeamDefault
		}
	}
	if member := inputs.Member; member != nil {
		if value, ok := member.Projects[inputs.ProjectKey]; ok && value.Known() && inputs.ProjectKey != "" {
			base = value
			source = SidecarClaimsSourceProject
		} else if member.Default.Known() {
			base = member.Default
			source = SidecarClaimsSourceMember
		}
	}
	if confirmation := inputs.Confirmation; confirmation != nil && confirmation.ProjectKey == inputs.ProjectKey &&
		confirmation.Committed == inputs.Committed.String() {
		if chosen, err := ParseSidecarClaims(confirmation.Claims); err == nil {
			resolution.Claims = chosen
			resolution.Source = SidecarClaimsSourceConfirmed
			return resolution
		}
	}
	switch {
	case !inputs.Committed.Known():
		resolution.Claims = base
		resolution.Source = source
	case inputs.Committed <= base:
		resolution.Claims = inputs.Committed
		resolution.Source = SidecarClaimsSourceCommitted
	default:
		// a committed file asks to share more: the member's value stands until the member confirms
		resolution.Claims = base
		resolution.Source = source
		resolution.Pending = inputs.Committed
	}
	return resolution
}

// The network's claims state.
func sidecarClaimsStore(sidecar *Sidecar) (SidecarStore, error) {
	return sidecar.LocalStore().Directory(sidecarClaimsDirectoryName, sidecarClaimsClass)
}

// A project's file: 32 lowercase hex of its key's SHA-256.
func sidecarClaimsFileName(projectKey string) string {
	sum := sha256.Sum256([]byte(projectKey))
	return hex.EncodeToString(sum[:16])
}

// The person's choice for projectKey; nil with no error for none.
func loadSidecarClaimsConfirmation(store SidecarStore, projectKey string, settings *SidecarProjectSettings) (*SidecarClaimsConfirmation, error) {
	reader, err := store.Open(sidecarClaimsFileName(projectKey))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, settings.ConfirmationByteCount+1))
	if err != nil {
		return nil, err
	}
	if settings.ConfirmationByteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: a claims confirmation past its bound", ErrSidecarStoreFailed)
	}
	confirmation := &SidecarClaimsConfirmation{}
	if err := json.Unmarshal(content, confirmation); err != nil || confirmation.ProjectKey != projectKey {
		return nil, fmt.Errorf("%w: a claims confirmation does not decode", ErrSidecarStoreFailed)
	}
	return confirmation, nil
}

// Keeps the person's choice, replacing the project's earlier one.
func saveSidecarClaimsConfirmation(store SidecarStore, confirmation *SidecarClaimsConfirmation) error {
	content, err := json.Marshal(confirmation)
	if err != nil {
		return err
	}
	writer, err := store.Create(sidecarClaimsFileName(confirmation.ProjectKey))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// The member's claims reader the daemon's settings name, nil for none.
func (self *Daemon) claimsConfig() SidecarClaimsConfig {
	return self.settings.Claims
}

// What a session's value for networkId rests on, read now: the verified state's directory and team default, the
// member's harness config, the session's `.ur` and project, and the person's choice for it. Whatever cannot be read
// closes toward off: an unreadable state is no team, and an unreadable `.ur` asks for off.
func (self *Daemon) claimsInputs(ctx context.Context, session *daemonSession, networkId Id) (*SidecarClaimsInputs, *SidecarProjectTree, *SidecarProject) {
	inputs := &SidecarClaimsInputs{}
	project, projectErr := self.sessionProject(session)
	tree := FindSidecarProjectTree(session.hello.Cwd, self.home(), self.projectSettings())
	if project != nil && project.Directory != "" && tree != nil && !tree.Git {
		// outside every work tree a .ur's own directory is the project's, wherever below it the caller runs
		tree = &SidecarProjectTree{TopLevel: project.Directory}
	}
	inputs.ProjectKey = SidecarProjectKey(tree)
	switch {
	case projectErr != nil:
		inputs.Committed = SidecarClaimsOff
	case project != nil && project.Claims != "":
		committed, err := ParseSidecarClaims(project.Claims)
		if err != nil {
			committed = SidecarClaimsOff
		}
		inputs.Committed = committed
	}
	sidecar, ok := self.SidecarForNetwork(networkId)
	if !ok {
		return inputs, tree, project
	}
	if state, err := sidecar.configState(); err == nil {
		if state.teamDirectoryRepo() != nil {
			inputs.Team = true
			inputs.TeamDefault = SidecarClaimsAuto
			if settings, known := state.DirectorySettings(); known {
				inputs.TeamDefault = sidecarClaimsOfRuns(settings.Runs)
			}
		}
	}
	if config := self.claimsConfig(); config != nil {
		label := session.hello.Agent
		if label == "" && project != nil {
			label = project.Agent
		}
		if member, err := config.MemberClaims(ctx, networkId, label); err == nil {
			inputs.Member = member
		} else if self.log.V(1).Enabled() {
			self.log.Infof("[daemon]the harness config's claims did not read, and the team's default stands: %s", err)
		}
	}
	if inputs.ProjectKey != "" {
		if store, err := sidecarClaimsStore(sidecar); err == nil {
			if confirmation, err := loadSidecarClaimsConfirmation(store, inputs.ProjectKey, self.projectSettings()); err == nil {
				inputs.Confirmation = confirmation
			}
		}
	}
	return inputs, tree, project
}

// A fresh resolution for a session of hello's caller in networkId.
func (self *Daemon) resolveSessionClaims(ctx context.Context, session *daemonSession, networkId Id) *SidecarClaimsResolution {
	inputs, tree, project := self.claimsInputs(ctx, session, networkId)
	resolution := ResolveSidecarClaims(inputs)
	resolution.ProjectLabel = project.ProjectLabel(tree)
	return resolution
}

// One session's claims: each network's resolved at its first ask and kept for the session's life, with the `.ur`
// read once at its start (D-CORE-18). What a session holds from its start: an MCP relay session's, which picks its
// go-sdk Server by it (MCP-M6-01). Safe for concurrent use.
type DaemonSessionClaims struct {
	daemon *Daemon

	stateLock       sync.Mutex
	session         *daemonSession
	networkIdClaims map[Id]*SidecarClaimsResolution
}

// The claims of a session of hello's caller, resolved as its networks are first asked for.
func (self *Daemon) SessionClaims(hello *DaemonHello) *DaemonSessionClaims {
	return &DaemonSessionClaims{
		daemon:          self,
		session:         &daemonSession{hello: hello},
		networkIdClaims: map[Id]*SidecarClaimsResolution{},
	}
}

// The value the session runs under in networkId: resolved at the first ask, then the same for the session's life,
// whatever changes after.
func (self *DaemonSessionClaims) For(ctx context.Context, networkId Id) *SidecarClaimsResolution {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if resolution, ok := self.networkIdClaims[networkId]; ok {
		return resolution
	}
	resolution := self.daemon.resolveSessionClaims(ctx, self.session, networkId)
	self.networkIdClaims[networkId] = resolution
	return resolution
}

// The value a session of hello's caller starts under in networkId, resolved now from its cwd's `.ur` and project, its
// agent, the harness config, the team's default and the person's choice: what a session takes once, at its start,
// and keeps (DaemonSessionClaims; RECORD-M6-16's run at its SessionStart).
func (self *Daemon) ResolveClaims(ctx context.Context, hello *DaemonHello, networkId Id) *SidecarClaimsResolution {
	return self.resolveSessionClaims(ctx, &daemonSession{hello: hello}, networkId)
}

// Records the person's choice of value for the project of hello's caller in networkId, against the `.ur` value
// committed now, and answers the value a new session then starts under. A choice wider than the value a session would
// start under now is the person's act: refused (ErrSidecarClaimsWider) unless confirmed, on /dev/tty or in an app.
func (self *Daemon) ChooseClaims(ctx context.Context, hello *DaemonHello, networkId Id, value SidecarClaims, confirmed bool) (*SidecarClaimsResolution, error) {
	if !value.Known() {
		return nil, ErrSidecarClaims
	}
	sidecar, ok := self.SidecarForNetwork(networkId)
	if !ok {
		return nil, &DaemonNetworkError{Reason: "unknown", Networks: self.hostedNetworkNames()}
	}
	session := &daemonSession{hello: hello}
	inputs, _, _ := self.claimsInputs(ctx, session, networkId)
	if !inputs.Team {
		return nil, fmt.Errorf("%w: a personal network announces no runs", ErrDirectoryNone)
	}
	if inputs.ProjectKey == "" {
		return nil, fmt.Errorf("%w: the caller names no project", ErrSidecarClaims)
	}
	current := ResolveSidecarClaims(inputs)
	if current.Claims < value && !confirmed {
		return nil, fmt.Errorf("%w: from %s to %s", ErrSidecarClaimsWider, current.Claims, value)
	}
	store, err := sidecarClaimsStore(sidecar)
	if err != nil {
		return nil, err
	}
	confirmation := &SidecarClaimsConfirmation{
		ProjectKey:      inputs.ProjectKey,
		Committed:       inputs.Committed.String(),
		Claims:          value.String(),
		ConfirmedMillis: self.clock.Now().UnixMilli(),
	}
	testHookBarrier("daemon.claims.choose.before", inputs.ProjectKey)
	err = saveSidecarClaimsConfirmation(store, confirmation)
	testHookBarrier("daemon.claims.choose.after", inputs.ProjectKey)
	if err != nil {
		return nil, err
	}
	return self.resolveSessionClaims(ctx, session, networkId), nil
}

// A claims value wider than the session's, which only the person may choose (D-CORE-18).
var ErrSidecarClaimsWider = errors.New("a wider claims value needs the person's confirmation on /dev/tty or in an app")
