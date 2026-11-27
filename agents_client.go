//go:build !ios_extension && !sidecar_http

// AgentsClient (DESIGN-COMPUTE §20.4, §20.5; SKILL-M11-02): one hosted network's agents, on its member's agents repo,
// one a member, and each agent's own agent repo. It reads cards held to their writers (agents_reader.go), registers
// agents and the person's me (agents_register.go, agents_me.go) and retires cards, and is what the Harness's agent_*
// tools, ur agents and the sdk's Agents() build on (SKILL-M11-07, SKILL-M11-08): every surface asks it, never the repo.
//
//	feature   nothing reads or writes while the network's agent_repos feature is off: registration answers
//	          ErrAgentReposOff, wrapping the prompt's AuthFeatureRequiredError, which names who can turn it on (the bot
//	          tab's first run, ur admin settings --feature agent_repos), and writes nothing
//	host      a card's host is the writer's word: a view shows the client name the config gives the card's sidecar_id
//	          (AgentCardView.Host), or for a me card none
//	component one per hosted network, built through registerComputeComponent from this file, so sidecar.go is not
//	          edited: Sidecar.AgentsClient answers it, on the Sidecar's evs client, verified state and keychain
//
// On the compute legs. Safe for concurrent use: each call reads the state and the repo anew.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// The component's name, and its directory and seal class in the device's sealed store.
const (
	agentsComponentName = "agents"
	agentsStoreName     = "agents"
)

var (
	// The network's agent_repos feature is off: nothing was read or written. Wraps the prompt's
	// *AuthFeatureRequiredError, which names the Owners and Admins who can turn it on.
	ErrAgentReposOff = errors.New("agents: the network's agent_repos feature is off")
	// No verified state, no identity or no evs client yet: nothing was read or written.
	ErrAgentsUnavailable = errors.New("agents: no verified state, identity or evs client")
	// The member has no agents repo, and this sidecar may not create it: only an untagged consented device of the
	// member does (§20.4).
	ErrAgentsRepoAbsent = errors.New("agents: the member has no agents repo yet")
	// Every name registration tried was another agent's: the launch's, the harness config's or the derived one, and
	// each suffix up to SkillSettings.NameSuffixMax.
	ErrAgentNameTaken = errors.New("agents: every name tried is another agent's")
	// No standing card at the name.
	ErrAgentCardAbsent = errors.New("agents: no card at that name")
	// The act is not this sidecar's to make: another sidecar's card, or a me card on a device that is no untagged
	// consented device of its member.
	ErrAgentsNotWriter = errors.New("agents: this sidecar does not write that card")
)

// What a client runs on, each seam a function so a test supplies its own.
type AgentsClientArgs struct {
	// This sidecar's id; an error, before it has one, reads and writes nothing.
	Self func() (Id, error)
	// The judgments at the newest verified state; an error reads and writes nothing.
	Authority func() (AgentsAuthority, error)
	// The repo's calls by its id: EvsClient.Repo's. Nil, or nil for a repo, reads and writes nothing.
	Repo func(repoId Id) AgentsRepoAccess
	// Creates an agents or agent repo bound to its creator's member: EvsClient.CreateRepo's, answering its id.
	CreateRepo func(ctx context.Context, args *EvsCreateRepoArgs) (Id, error)
	// The network's agent repo label key (EvsClient.AgentRepoLabelKey, QD-1434): what an agent repo's RepoCreate files
	// its name's keyed label under and a reader checks one by. Nil creates no agent repo and verifies no label.
	LabelKey func(ctx context.Context) (*AgentRepoLabelKey, error)
	// The agent_id this sidecar keeps for a label (Sidecar.ResolveAgentId): an agent's name is its label (§20.5).
	AgentId func(label string) (Id, error)
	// Whether AgentRevoke tombstoned an agent's subkey on this sidecar (Sidecar.AgentRevoked): its card retires.
	AgentRevoked func(agentId Id) (bool, error)
	// The client name the config gives a sidecar, "" for none (§7.7): a view's host.
	HostName func(sidecarId Id) string
	// Nil where the network's agent_repos feature is on; else the prompt's *AuthFeatureRequiredError
	// (Sidecar.CheckAuthFeature). Nil reads every network's as on, which only a test does.
	FeatureCheck func() error
	// record_alarm's one sink (RecordAlarm): a card version passed over. Nil drops it.
	Alarm func(alarm *RecordAlarm)
	// Nil is the system clock.
	Clock Clock
	// Nil is DefaultSkillSettings.
	Settings *SkillSettings
	// The model names' grammar a stub holds a card's model to (§6.3, agents_stub.go). Nil is DefaultInferSettings.
	InferSettings *InferSettings
	// The device's sealed store, read at each use, which holds the outbox of messages composed and not yet landed
	// (agents_outbox.go). Nil, or an error, sends no message.
	Store func() (SidecarStore, error)
}

// One network's agents: see the file header.
type AgentsClient struct {
	args     *AgentsClientArgs
	settings *SkillSettings
	clock    Clock

	stateLock      sync.Mutex
	alarmedPushIds map[Id]bool
	// held across a taken record's read and rewrite in the sealed store (agents_deliver.go), never with stateLock
	takenLock sync.Mutex
}

// A client over args: Self, Authority and Repo are required.
func NewAgentsClient(args *AgentsClientArgs) (*AgentsClient, error) {
	if args == nil || args.Self == nil || args.Authority == nil || args.Repo == nil {
		return nil, fmt.Errorf("%w: agents client args", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSkillSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &AgentsClient{args: args, settings: settings, clock: clock, alarmedPushIds: map[Id]bool{}}, nil
}

// Registers the client on every Sidecar of a compute leg.
func init() {
	registerComputeComponent(agentsComponentName, newSidecarAgents, nil)
}

// The client on sidecar: its evs client, verified state, keychain's agent registrations and config names, each read
// at use, since a Sidecar enrolls after it starts.
func newSidecarAgents(sidecar *Sidecar) (*AgentsClient, error) {
	return NewAgentsClient(&AgentsClientArgs{
		Self: func() (Id, error) {
			identity := sidecar.Identity()
			if identity == nil {
				return Id{}, ErrSidecarNoIdentity
			}
			return identity.SidecarId, nil
		},
		Authority: func() (AgentsAuthority, error) {
			state, err := sidecar.configState()
			if err != nil {
				return nil, err
			}
			return NewAgentsAuthority(state)
		},
		Repo: func(repoId Id) AgentsRepoAccess {
			client := sidecar.EvsClient()
			if client == nil {
				return nil
			}
			return client.Repo(repoId)
		},
		CreateRepo: func(ctx context.Context, args *EvsCreateRepoArgs) (Id, error) {
			client := sidecar.EvsClient()
			if client == nil {
				return Id{}, ErrAgentsUnavailable
			}
			repo, err := client.CreateRepo(ctx, args)
			if repo == nil {
				return Id{}, err
			}
			return repo.RepoId(), err
		},
		LabelKey: func(ctx context.Context) (*AgentRepoLabelKey, error) {
			client := sidecar.EvsClient()
			if client == nil {
				return nil, ErrAgentsUnavailable
			}
			return client.AgentRepoLabelKey(ctx)
		},
		AgentId:      sidecar.ResolveAgentId,
		AgentRevoked: sidecar.AgentRevoked,
		HostName:     agentsHostNames(sidecar),
		FeatureCheck: func() error {
			return sidecar.CheckAuthFeature(AuthFeatureAgentRepos)
		},
		Alarm: func(alarm *RecordAlarm) {
			logId := alarm.LogId
			sidecar.emitEvent(SidecarEvent{Kind: SidecarEventRecordAlarm, RepoId: &logId, SidecarId: alarm.SidecarId, RecordAlarm: alarm.Reason})
		},
		Clock:         sidecar.settings.Clock,
		Settings:      sidecar.settings.Skill,
		InferSettings: sidecar.settings.Infer,
		Store: func() (SidecarStore, error) {
			return sidecar.LocalStore().Directory(agentsStoreName, agentsStoreName)
		},
	})
}

// This Sidecar's agents, or why it has none.
func (self *Sidecar) AgentsClient() (*AgentsClient, error) {
	return sidecarComputeComponent[AgentsClient](self, agentsComponentName)
}

// Whether AgentRevoke tombstoned agentId's subkey here: false for an agent with no record yet.
func (self *Sidecar) AgentRevoked(agentId Id) (bool, error) {
	if agentId == (Id{}) {
		return false, ErrAgentSubkeyArgs
	}
	self.agentSubkeyLock.Lock()
	defer self.agentSubkeyLock.Unlock()
	secrets, _, err := self.agentSubkeySecrets()
	if err != nil {
		return false, err
	}
	return sidecarAgentRevoked(secrets, agentId)
}

// What one call reads at: this sidecar, the judgments, its member and the member's agents repo.
type agentsPlace struct {
	sidecarId    Id
	authority    AgentsAuthority
	memberId     Id
	agentsRepoId Id
	agentsRepo   AgentsRepoAccess
}

// The place a call reads at: ErrAgentReposOff while the feature is off, ErrAgentsUnavailable before a state, an
// identity or an evs client, ErrAgentsRepoAbsent where the member has no agents repo.
func (self *AgentsClient) place() (*agentsPlace, error) {
	if self.args.FeatureCheck != nil {
		if err := self.args.FeatureCheck(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrAgentReposOff, err)
		}
	}
	sidecarId, err := self.args.Self()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentsUnavailable, err)
	}
	authority, err := self.args.Authority()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentsUnavailable, err)
	}
	if !authority.AgentReposOn() {
		return nil, fmt.Errorf("%w: %s is not on at this device's verified state", ErrAgentReposOff, AuthFeatureAgentRepos)
	}
	memberId, found := authority.MemberOf(sidecarId)
	if !found {
		return nil, fmt.Errorf("%w: the config gives this sidecar no member", ErrAgentsUnavailable)
	}
	place := &agentsPlace{sidecarId: sidecarId, authority: authority, memberId: memberId}
	if agentsRepoId, found := authority.AgentsRepo(memberId); found {
		place.agentsRepoId = agentsRepoId
		place.agentsRepo = self.args.Repo(agentsRepoId)
	}
	return place, nil
}

// The keyed label an agent repo named name files (QD-1434), under the network's K_label: an error where this sidecar
// derives none, so no agent repo is created unlabeled.
func (self *AgentsClient) agentRepoLabelMac(ctx context.Context, name AgentName) ([]byte, error) {
	if self.args.LabelKey == nil {
		return nil, fmt.Errorf("%w: no agent repo label key", ErrAgentsUnavailable)
	}
	key, err := self.args.LabelKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentsUnavailable, err)
	}
	return key.Mac(name), nil
}

// Whether repoId is memberId's agent repo labeled agent/<name> (DESIGN-COMPUTE §20.7's check of to.repo and from.repo;
// QD-1434): a standing agent repo the log binds to memberId whose RepoCreate filed name's keyed label, recomputed under
// this sidecar's K_label. What SKILL-M13-01's reader asks before it takes another member's agent's name; within a member
// a card binds its name to its repo (§20.5). ErrAgentReposOff while the feature is off, ErrAgentsUnavailable where this
// sidecar derives no K_label, and false, nil for a repo that is not one. K_label derives from the config repo's K_ref,
// so a label verifies for the network's life (QD-1435).
func (self *AgentsClient) AgentRepoLabeled(ctx context.Context, memberId Id, name AgentName, repoId Id) (bool, error) {
	place, err := self.place()
	if err != nil {
		return false, err
	}
	if _, err := ParseAgentName(string(name), self.settings); err != nil {
		return false, err
	}
	labelMac, err := self.agentRepoLabelMac(ctx, name)
	if err != nil {
		return false, err
	}
	return place.authority.MemberAgentRepoLabeled(memberId, repoId, labelMac), nil
}

// The place, its agents repo required.
func (self *AgentsClient) placeWithRepo() (*agentsPlace, error) {
	place, err := self.place()
	if err != nil {
		return nil, err
	}
	if place.agentsRepo == nil {
		return nil, ErrAgentsRepoAbsent
	}
	return place, nil
}

// Raises record_alarm path_rule for a card version passed over, once a push.
func (self *AgentsClient) alarm(repoId Id, version *EvsHistoryVersion) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.alarmedPushIds[version.PushId] {
			return false
		}
		self.alarmedPushIds[version.PushId] = true
		return true
	}()
	if !first || self.args.Alarm == nil {
		return
	}
	signerId := version.SignerSidecarId
	self.args.Alarm(&RecordAlarm{Reason: SidecarRecordAlarmPathRule, LogId: repoId, SidecarId: &signerId})
}

// A card as a reader takes it, at place.
func (self *AgentsClient) readCard(ctx context.Context, place *agentsPlace, name AgentName) (*AgentCardRead, error) {
	return agentsReaderCheck(ctx, place.agentsRepo, place.authority, place.memberId, name, self.settings, func(version *EvsHistoryVersion) {
		self.alarm(place.agentsRepoId, version)
	})
}

// One card as a person's views and the agent_* tools show it.
type AgentCardView struct {
	*AgentCardRead
	// The client name the config gives the card's sidecar, "" for a me card and for a sidecar the config names none:
	// never the card's own host text (§20.6).
	Host string
}

// The view of a read.
func (self *AgentsClient) view(read *AgentCardRead) *AgentCardView {
	view := &AgentCardView{AgentCardRead: read}
	if read.Card != nil && !read.Card.Person() && self.args.HostName != nil {
		view.Host = self.args.HostName(read.Card.SidecarId)
	}
	return view
}

// The card at name in this member's agents repo, held to its writer: ErrAgentCardAbsent where none stands.
func (self *AgentsClient) Card(ctx context.Context, name AgentName) (*AgentCardView, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	read, err := self.readCard(ctx, place, name)
	if err != nil {
		return nil, err
	}
	if read.Card == nil {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
	}
	return self.view(read), nil
}

// Every card in this member's agents repo, by name, held to its writers: retired ones only where includeRetired, a path
// withheld left out, at most SkillSettings.CardListMaxCount names read.
func (self *AgentsClient) Cards(ctx context.Context, includeRetired bool) ([]*AgentCardView, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	names, err := self.cardNames(ctx, place)
	if err != nil {
		return nil, err
	}
	views := []*AgentCardView{}
	for _, name := range names {
		read, err := self.readCard(ctx, place, name)
		if errors.Is(err, ErrAgentCardWithheld) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if read.Card == nil || (read.Card.IsRetired() && !includeRetired) {
			continue
		}
		views = append(views, self.view(read))
	}
	return views, nil
}

// The names cards/ holds, sorted: each file <name>.json whose name is one, at most CardListMaxCount.
func (self *AgentsClient) cardNames(ctx context.Context, place *agentsPlace) ([]AgentName, error) {
	listing, err := place.agentsRepo.List(ctx, &EvsReadArgs{Path: agentCardDirectory})
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := []AgentName{}
	for _, entry := range listing.Entries {
		fileName, isCard := strings.CutSuffix(string(entry.Name), agentCardFileSuffix)
		if !isCard {
			continue
		}
		name, err := ParseAgentName(fileName, self.settings)
		if err != nil {
			continue
		}
		names = append(names, name)
		if self.settings.CardListMaxCount <= len(names) {
			break
		}
	}
	slices.Sort(names)
	return names, nil
}

// Where a message to name lands (§20.5's step 3, §20.7's open row): the agent's own repo, or for a child with none yet
// its nearest ancestor's that has one, walking the cards' parents at most AncestorWalkMaxCount steps. ErrAgentCardAbsent where
// no card on the way stands or none of them has a repo the log binds to the member.
func (self *AgentsClient) AgentRepo(ctx context.Context, name AgentName) (Id, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return Id{}, err
	}
	visited := map[AgentName]bool{}
	for next := name; next != "" && !visited[next] && len(visited) <= self.settings.AncestorWalkMaxCount; {
		visited[next] = true
		read, err := self.readCard(ctx, place, next)
		if err != nil {
			return Id{}, err
		}
		if read.Card == nil {
			break
		}
		if repoId := read.Card.AgentRepo; repoId != (Id{}) && place.authority.MemberAgentRepo(place.memberId, repoId) {
			return repoId, nil
		}
		next = read.Card.Parent
	}
	return Id{}, fmt.Errorf("%w: %s has no agent repo, nor any ancestor", ErrAgentCardAbsent, name)
}

// Writes card at name over the version base, the read's newest (0 creates), as this sidecar: ErrEvsPathMoved or an
// *EvsPathConflictError where another write landed first.
func (self *AgentsClient) writeCard(ctx context.Context, place *agentsPlace, card *AgentCard, base uint64) (uint64, error) {
	data, err := EncodeAgentCard(card, self.settings)
	if err != nil {
		return 0, err
	}
	result, err := place.agentsRepo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path:      AgentCardPath(card.Name),
		Content:   bytes.NewReader(data),
		IfVersion: &base,
	}}})
	if err != nil {
		return 0, err
	}
	if result == nil || len(result.PathVersions) == 0 {
		return 0, fmt.Errorf("%w: a card's write answered no version", ErrAgentsUnavailable)
	}
	return result.PathVersions[0], nil
}

// Whether err is a write another landed before: the caller reads again.
func agentsWriteConflict(err error) bool {
	var conflict *EvsPathConflictError
	return errors.Is(err, ErrEvsPathMoved) || errors.As(err, &conflict)
}

// Retires the card at name (§20.5): its own writer's act, or for a card idle past SkillSettings.RetireAfterIdle any
// untagged consented device of the member's, setting retired and nothing else. ErrAgentsNotWriter for any other; a card
// already retired answers as it stands.
func (self *AgentsClient) Retire(ctx context.Context, name AgentName) (*AgentCardView, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	for range max(self.settings.CardWriteAttemptCount, 1) {
		read, err := self.readCard(ctx, place, name)
		if err != nil {
			return nil, err
		}
		if read.Card == nil {
			return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
		}
		if read.Card.IsRetired() {
			return self.view(read), nil
		}
		ownWriter := agentCardWriter(place.authority, place.memberId, read.Card, place.sidecarId)
		if !ownWriter {
			idle, err := self.idle(ctx, place, read)
			if err != nil {
				return nil, err
			}
			if !idle || !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
				return nil, fmt.Errorf("%w: %s", ErrAgentsNotWriter, name)
			}
		}
		retired := *read.Card
		retired.Retired = self.clock.Now()
		version, err := self.writeCard(ctx, place, &retired, read.Newest)
		if agentsWriteConflict(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		written := *read
		written.Card, written.Version, written.WriterSidecarId, written.Newest = &retired, version, place.sidecarId, version
		return self.view(&written), nil
	}
	return nil, fmt.Errorf("%w: %s kept moving", ErrAgentsNotWriter, name)
}

// The status path SKILL-M11-03's Harness writes for name (§20.4's layout), whose newest version says when the agent was
// last heard from.
func agentStatusPath(name AgentName) string {
	return "status/" + string(name) + agentCardFileSuffix
}

// Whether read's agent has written no status for SkillSettings.RetireAfterIdle: its status file's newest version, else
// its card's, older than that.
func (self *AgentsClient) idle(ctx context.Context, place *agentsPlace, read *AgentCardRead) (bool, error) {
	last := read.Time
	history, err := place.agentsRepo.History(ctx, &EvsReadArgs{Path: agentStatusPath(read.Name), NewestLife: true})
	switch {
	case errors.Is(err, ErrEvsPathAbsent):
	case err != nil:
		return false, err
	case 0 < len(history.Versions) && history.Versions[0].Time.After(last):
		last = history.Versions[0].Time
	}
	return self.settings.RetireAfterIdle <= self.clock.Now().Sub(last), nil
}

// Retires every card this sidecar's agents hold whose subkey AgentRevoke tombstoned here (§20.5: read from the agent's
// record), answering the names retired.
func (self *AgentsClient) RetireRevoked(ctx context.Context) ([]AgentName, error) {
	if self.args.AgentRevoked == nil {
		return nil, nil
	}
	views, err := self.Cards(ctx, false)
	if err != nil {
		return nil, err
	}
	sidecarId, err := self.args.Self()
	if err != nil {
		return nil, err
	}
	retired := []AgentName{}
	for _, view := range views {
		card := view.Card
		if card.Person() || card.SidecarId != sidecarId {
			continue
		}
		revoked, err := self.args.AgentRevoked(card.AgentId)
		if err != nil {
			return retired, err
		}
		if !revoked {
			continue
		}
		if _, err := self.Retire(ctx, card.Name); err != nil {
			return retired, err
		}
		retired = append(retired, card.Name)
	}
	return retired, nil
}

// Retires every card idle past SkillSettings.RetireAfterIdle, from any untagged consented device of the member
// (§20.5), answering the names retired; the person's me card is the member's and never idles out.
func (self *AgentsClient) RetireIdle(ctx context.Context) ([]AgentName, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	if !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
		return nil, ErrAgentsNotWriter
	}
	views, err := self.Cards(ctx, false)
	if err != nil {
		return nil, err
	}
	retired := []AgentName{}
	for _, view := range views {
		if view.Card.Person() {
			continue
		}
		idle, err := self.idle(ctx, place, view.AgentCardRead)
		if err != nil {
			return retired, err
		}
		if !idle {
			continue
		}
		if _, err := self.Retire(ctx, view.Card.Name); err != nil {
			return retired, err
		}
		retired = append(retired, view.Card.Name)
	}
	return retired, nil
}

// Whether a name may be taken by an agent whose card is not the one standing there: the card is retired, and has been
// NameReuseAfter (§20.5).
func (self *AgentsClient) reusable(card *AgentCard, now time.Time) bool {
	return card.IsRetired() && !now.Before(card.Retired.Add(self.settings.NameReuseAfter))
}
