//go:build !ios_extension && !sidecar_http && !js

// The spend view's labels on the device (DESIGN-COMPUTE §9.13, D-BAL-6, D-BAL-7; BAL-M12-17). The server answers ids
// and typed numbers (I-13), and the device names them, as statements do:
//
//	members    from the config: the viewer's own member as you, every other as the policy's resolution names it
//	sidecars   from the config: each client's name (§7.7)
//	enclaves   by the name their incarnations were admitted with (§11.4), ENC's source
//	agents     by their cards (§20.5) where the viewer may read the member's agents repo, SKILL's source; else as an
//	           agent of that member
//	models     from the catalog (§6.3): a model's or a shape's catalog id, its canonical name
//	providers  from the release's own table of §4.6's fixed codes (QD-1247)
//
// An id the device cannot resolve shows as unknown. A name from a signed source reaches a model as plain text (the
// config, an admission, the signed policy for a TEE model, the release's manifest for a local one, the release for a
// provider), and so does an agent's card an untainted run on the member's untagged device wrote. Any other reaches a
// model only between the untrusted-data markers, labeled with its writer, and taints nothing: a catalog id no signed
// source names (a direct model's, a shape's, one gone from the policy), the broker's, shown only within §6.3's grammar
// and ComputeClientSettings.LabelMaxCharacterCount characters, else as unknown; and an agent name any other writer
// wrote, held to §20.5's name grammar, else unknown. Every name, signed or not, past the bound is unknown, so no
// answer carries an unbounded string to a model.
//
// The sources are seams (BAL plan's ComputeLabeler row): each owner installs its own from its file through
// registerComputeLabelSources, as INFER, SKILL and ENC will, and what none installs this file fills from what has
// landed, the config's names and the inference router's catalog; a source left unset names nothing, so its ids show as
// unknown, and agents as agents of their members. A labeler reads each source once, into a snapshot, so one view is
// named from one moment of each.
//
// The views (ComputeSpendView, ComputeChargesView, ComputeStatementView) hold the server's ids and numbers and the
// device's names beside them, nothing else; every other field of an answer was dropped as it was read
// (compute_client_api.go). Amounts render to the cent, "< $0.01" below one (ComputeMoneyText), and the 7 days in UTC
// with their local bounds beside (ComputeSpendWindowText; Q-BAL-8).
//
// Safe for concurrent use: a labeler is not changed once built.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// How a name reaches a model (§9.13).
type ComputeNameTrust string

const (
	// From a signed source, or an agent's card an untainted run on the member's untagged device wrote: plain text.
	ComputeNamePlain ComputeNameTrust = "plain"
	// From any other writer: only between the untrusted-data markers, labeled with its writer, tainting nothing.
	ComputeNameMarked ComputeNameTrust = "marked"
	// An id the device cannot resolve, or a name outside its grammar or bound.
	ComputeNameUnknown ComputeNameTrust = "unknown"
)

// The fixed markers around untrusted text, §16.6's, which MCP's results carry too.
const (
	ComputeUntrustedBegin = "BEGIN UNTRUSTED DATA"
	ComputeUntrustedEnd   = "END UNTRUSTED DATA"
)

// The words a view names what has no id by.
const (
	// An id the device cannot resolve (§9.13).
	computeNameUnknownText = "unknown"
	// The network's own line: a charge that counts to no member, or a support adjustment's nil sidecar (§9.6).
	computeNameNetworkText = "network"
	// A dimension the charge does not carry: no agent, enclave, model or provider.
	computeNameNoneText = "none"
	// The viewer's own member (§9.13's members from the config).
	computeNameYouText = "you"
	// What writes a catalog id no signed source names (§9.13).
	computeWriterBroker = "broker"
	// An agent's name where the viewer may not read its card: an agent of its member.
	computeAgentOfPrefix = "agent of "
)

// What the device calls one id of an answer, and how it may reach a model.
type ComputeDisplayName struct {
	Text  string           `json:"text"`
	Trust ComputeNameTrust `json:"trust"`
	// Who wrote a marked name: the broker, or an agent card's writer as the config names it.
	Writer string `json:"writer,omitempty"`
}

// The name as a model reads it: plain text, or between the untrusted-data markers with its writer after them, or
// unknown. A marked name holds no marker, since its grammar holds no space.
func (self *ComputeDisplayName) ModelText() string {
	switch self.Trust {
	case ComputeNamePlain:
		return self.Text
	case ComputeNameMarked:
		return ComputeUntrustedBegin + "\n" + self.Text + "\n" + ComputeUntrustedEnd + " (written by " + self.Writer + ")"
	}
	return computeNameUnknownText
}

// A plain name.
func computePlainName(text string) *ComputeDisplayName {
	return &ComputeDisplayName{Text: text, Trust: ComputeNamePlain}
}

// The unknown name.
func computeUnknownName() *ComputeDisplayName {
	return &ComputeDisplayName{Text: computeNameUnknownText, Trust: ComputeNameUnknown}
}

// One agent's card (§20.5) as the agents' source reads it, for a viewer who may read its member's agents repo.
type ComputeAgentCard struct {
	Name string
	// Whom the agent belongs to.
	MemberId *Id
	// Whether an untainted run on the member's untagged device wrote the card, so its name reaches a model as plain
	// text (§20.6's stub rule).
	Trusted bool
	// The card's writer as the config names it: the sidecar or enclave that pushed it, for a name not trusted.
	Writer string
}

// What the device names a view's ids by, each source answering for the ids it knows, from one read a view: a nil
// source names nothing, so its ids show as unknown, and agents as agents of their members. A source's error is the same
// as none for that view. Each source's map is the caller's to keep.
type ComputeLabelSources struct {
	// The config's members, by member id: the viewer's own as you, the rest as the policy's resolution names them.
	Members func(ctx context.Context) (map[Id]string, error)
	// The config's client names, by sidecar id (§7.7).
	Sidecars func(ctx context.Context) (map[Id]string, error)
	// The network's enclaves, by enclave id, each by the name its incarnations were admitted with (§11.4; ENC).
	Enclaves func(ctx context.Context) (map[Id]string, error)
	// The catalog's ids, each canonical name, alias and shape a model or shape answers to, and whether a signed source
	// vouches for it: the signed policy for a TEE model, the release's manifest for a local one (§6.3; INFER).
	Catalog func(ctx context.Context) (map[string]bool, error)
	// The agents' cards the viewer may read, by agent id (§20.5; SKILL).
	Agents func(ctx context.Context) (map[Id]*ComputeAgentCard, error)
}

// An owner's installer of label sources: sets the fields it serves on sources, from an init function in its own file.
type ComputeLabelSourcesInstaller func(sidecar *Sidecar, sources *ComputeLabelSources) error

// One registration of label sources.
type computeLabelSourcesRegistration struct {
	name    string
	install ComputeLabelSourcesInstaller
}

// Every registration, in the order the files' init functions made them. Written only during the package's init.
var computeLabelSourcesRegistrations = []*computeLabelSourcesRegistration{}

// Registers an owner's installer of label sources under name, from an init function in its own file: INFER's catalog,
// SKILL's agents' cards, ENC's enclaves. An empty name, a nil installer or a name registered twice is a build error,
// which panics.
func registerComputeLabelSources(name string, install ComputeLabelSourcesInstaller) {
	registered := slices.ContainsFunc(computeLabelSourcesRegistrations, func(registration *computeLabelSourcesRegistration) bool {
		return registration.name == name
	})
	if name == "" || install == nil || registered {
		panic(fmt.Sprintf("compute label sources %q registered twice or without an installer", name))
	}
	computeLabelSourcesRegistrations = append(computeLabelSourcesRegistrations, &computeLabelSourcesRegistration{name: name, install: install})
}

// The sources of sidecar: each registration's, in order, then this file's defaults for any field none set. Each
// installer fills a fresh set, which is merged in: one that fails installs nothing, and a field another installer
// already set keeps the first one's, the second's logged, so no owner replaces another's source.
func newComputeLabelSources(sidecar *Sidecar, registrations []*computeLabelSourcesRegistration) *ComputeLabelSources {
	sources := &ComputeLabelSources{}
	for _, registration := range registrations {
		installed := &ComputeLabelSources{}
		if err := registration.install(sidecar, installed); err != nil {
			sidecar.log.Warningf("[compute]label sources %s did not install: %s", registration.name, err)
			continue
		}
		conflicts := []string{}
		if installed.Members != nil {
			if sources.Members != nil {
				conflicts = append(conflicts, "members")
			} else {
				sources.Members = installed.Members
			}
		}
		if installed.Sidecars != nil {
			if sources.Sidecars != nil {
				conflicts = append(conflicts, "sidecars")
			} else {
				sources.Sidecars = installed.Sidecars
			}
		}
		if installed.Enclaves != nil {
			if sources.Enclaves != nil {
				conflicts = append(conflicts, "enclaves")
			} else {
				sources.Enclaves = installed.Enclaves
			}
		}
		if installed.Catalog != nil {
			if sources.Catalog != nil {
				conflicts = append(conflicts, "catalog")
			} else {
				sources.Catalog = installed.Catalog
			}
		}
		if installed.Agents != nil {
			if sources.Agents != nil {
				conflicts = append(conflicts, "agents")
			} else {
				sources.Agents = installed.Agents
			}
		}
		if 0 < len(conflicts) {
			sidecar.log.Warningf("[compute]label sources %s set sources another installer set: %v", registration.name, conflicts)
		}
	}
	if sources.Members == nil {
		sources.Members = sidecar.computeConfigMemberNames
	}
	if sources.Sidecars == nil {
		sources.Sidecars = sidecar.computeConfigSidecarNames
	}
	if sources.Catalog == nil {
		sources.Catalog = sidecar.computeCatalogNames
	}
	return sources
}

// The verified config state and the head its base names, cached on this device, for the config's names; false while
// either is not held, or the log is forked.
func (self *Sidecar) computeConfigHead() (*ConfigState, *ConfigHead, bool) {
	authority, ok := self.authority().(*ConfigAuthority)
	if !ok || authority.client == nil || authority.client.Fork() != nil {
		return nil, nil, false
	}
	client := authority.client
	state := client.State()
	if state == nil || state.Base() == nil {
		return nil, nil, false
	}
	base := state.Base()
	var head *ConfigHead
	if held := client.localHead.Load(); held != nil && base.GetConfigVersion() == held.version && bytes.Equal(base.GetConfigHeadSha256(), held.chain[:]) {
		head = held.head
	} else if local, ok := client.args.Heads.(interface {
		CachedConfigHead(uint64, []byte) *ConfigHead
	}); ok {
		head = local.CachedConfigHead(base.GetConfigVersion(), base.GetConfigHeadSha256())
	}
	return state, head, head != nil
}

// The members the config names: this device's own member as you, from its verified admission, and each member the
// policy's resolution names, by the email it resolves.
func (self *Sidecar) computeConfigMemberNames(ctx context.Context) (map[Id]string, error) {
	names := map[Id]string{}
	state, head, ok := self.computeConfigHead()
	if ok {
		resolve := &protocol.ConfigResolution{}
		if err := aclSaveDecode(head, ConfigHeadResolvePath, resolve); err == nil {
			for _, row := range resolve.GetMembers() {
				memberId, err := IdFromBytes(row.GetMemberId())
				if err != nil || state.Member(memberId) == nil {
					continue
				}
				names[memberId] = row.GetEmail()
			}
		}
	}
	if identity := self.currentIdentity(); identity != nil {
		if authority := self.authority(); authority != nil {
			if own := authority.Admission(identity.SidecarId); own != nil && len(own.TagIds) == 0 && own.MemberId != (Id{}) {
				names[own.MemberId] = computeNameYouText
			}
		}
	}
	return names, nil
}

// The client names the config's head gives (§7.7).
func (self *Sidecar) computeConfigSidecarNames(ctx context.Context) (map[Id]string, error) {
	state, head, ok := self.computeConfigHead()
	if !ok {
		return map[Id]string{}, nil
	}
	table, err := head.Names()
	if err != nil {
		return nil, err
	}
	return ConfigNames(table, state.Rows().GetSidecars(), state.TeamScopeLabels())
}

// The catalog this device sees, each canonical name, alias and search id of each entry, a local or TEE entry's
// vouched for by a signed source (the release's manifest, the signed policy), a direct entry's and a search
// endpoint's not (§9.13).
func (self *Sidecar) computeCatalogNames(ctx context.Context) (map[string]bool, error) {
	router, err := self.InferRouter()
	if err != nil {
		return nil, err
	}
	catalog, err := router.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, entry := range catalog.Entries() {
		signed := entry.Kind == InferCatalogKindLocal || entry.Kind == InferCatalogKindTee
		for _, name := range entry.Names() {
			names[name] = signed
		}
		if alias := entry.Alias(); alias != "" {
			names[alias] = signed
		}
		if searchId := entry.SearchId(); searchId != "" {
			names[searchId] = false
		}
	}
	return names, nil
}

// §4.6's fixed provider codes (QD-1247) and their slugs, as the release carries them: identifiers, each fixed for
// good, the same table computeservice's provider.go keeps for the broker.
var computeProviderSlugs = map[int16]string{
	1: "chutes",
	2: "engy",
	3: "saygm",
	4: "hippius",
	5: "lium",
	6: "cathedral",
	7: "reference",
	8: "parallel",
}

// One read of every source, which names one view.
type computeLabelIndex struct {
	members  map[Id]string
	sidecars map[Id]string
	enclaves map[Id]string
	catalog  map[string]bool
	agents   map[Id]*ComputeAgentCard
}

// Names a view's ids by one snapshot of its sources, under §9.13's rules (the file header). Built by
// NewComputeLabeler; not changed after.
type ComputeLabeler struct {
	settings      *ComputeClientSettings
	inferSettings *InferSettings
	index         *computeLabelIndex
}

// A labeler over one read of sources, each read once with ctx; a source that fails names nothing in this view, and
// log, when not nil, says which.
func NewComputeLabeler(ctx context.Context, sources *ComputeLabelSources, settings *ComputeClientSettings, inferSettings *InferSettings, log Logger) *ComputeLabeler {
	if settings == nil {
		settings = DefaultComputeClientSettings()
	}
	if inferSettings == nil {
		inferSettings = DefaultInferSettings()
	}
	if sources == nil {
		sources = &ComputeLabelSources{}
	}
	read := func(kind string, source func() error) {
		if err := source(); err != nil && log != nil && log.V(1).Enabled() {
			log.Infof("[compute]the %s for labels did not read: %s", kind, err)
		}
	}
	index := &computeLabelIndex{
		members:  map[Id]string{},
		sidecars: map[Id]string{},
		enclaves: map[Id]string{},
		catalog:  map[string]bool{},
		agents:   map[Id]*ComputeAgentCard{},
	}
	if sources.Members != nil {
		read("members", func() error {
			members, err := sources.Members(ctx)
			if err == nil && members != nil {
				index.members = members
			}
			return err
		})
	}
	if sources.Sidecars != nil {
		read("sidecars", func() error {
			sidecars, err := sources.Sidecars(ctx)
			if err == nil && sidecars != nil {
				index.sidecars = sidecars
			}
			return err
		})
	}
	if sources.Enclaves != nil {
		read("enclaves", func() error {
			enclaves, err := sources.Enclaves(ctx)
			if err == nil && enclaves != nil {
				index.enclaves = enclaves
			}
			return err
		})
	}
	if sources.Catalog != nil {
		read("catalog", func() error {
			catalog, err := sources.Catalog(ctx)
			if err == nil && catalog != nil {
				index.catalog = catalog
			}
			return err
		})
	}
	if sources.Agents != nil {
		read("agents", func() error {
			agents, err := sources.Agents(ctx)
			if err == nil && agents != nil {
				index.agents = agents
			}
			return err
		})
	}
	return &ComputeLabeler{settings: settings, inferSettings: inferSettings, index: index}
}

// Whether text may be shown at all: valid UTF-8, no control character, at most LabelMaxCharacterCount characters and
// not empty.
func (self *ComputeLabeler) fits(text string) bool {
	if text == "" || !utf8.ValidString(text) || self.settings.LabelMaxCharacterCount < utf8.RuneCountInString(text) {
		return false
	}
	for _, r := range text {
		if r < ' ' || r == 0x7f || (0x80 <= r && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// A plain name from a signed source, or unknown where the source named none or one past the bound.
func (self *ComputeLabeler) signedName(text string, ok bool) *ComputeDisplayName {
	if !ok || !self.fits(text) {
		return computeUnknownName()
	}
	return computePlainName(text)
}

// A member by the config, nil the network's own line.
func (self *ComputeLabeler) Member(memberId *Id) *ComputeDisplayName {
	if memberId == nil {
		return computePlainName(computeNameNetworkText)
	}
	text, ok := self.index.members[*memberId]
	return self.signedName(text, ok)
}

// A sidecar by the config's client name, the nil id a support adjustment's, the network's own line (§9.6).
func (self *ComputeLabeler) Sidecar(sidecarId Id) *ComputeDisplayName {
	if sidecarId == (Id{}) {
		return computePlainName(computeNameNetworkText)
	}
	text, ok := self.index.sidecars[sidecarId]
	return self.signedName(text, ok)
}

// An enclave by the name its incarnations were admitted with; nil for a charge that names none.
func (self *ComputeLabeler) Enclave(enclaveId *Id) *ComputeDisplayName {
	if enclaveId == nil {
		return computePlainName(computeNameNoneText)
	}
	text, ok := self.index.enclaves[*enclaveId]
	return self.signedName(text, ok)
}

// A provider by §4.6's fixed code; 0 for none, as a support adjustment carries.
func (self *ComputeLabeler) Provider(code int16) *ComputeDisplayName {
	if code == 0 {
		return computePlainName(computeNameNoneText)
	}
	slug, ok := computeProviderSlugs[code]
	return self.signedName(slug, ok)
}

// Whether catalogId keeps §6.3's grammar: a canonical model name or alias, a search id, or a shape, which parses as
// an alias (cpu-2 reads provider cpu, model 2); and within the bound.
func (self *ComputeLabeler) catalogIdInGrammar(catalogId string) bool {
	if self.settings.LabelMaxCharacterCount < len(catalogId) {
		return false
	}
	if _, err := InferParseModelName(catalogId, self.inferSettings); err == nil {
		return true
	}
	_, err := InferParseSearchId(catalogId, self.inferSettings)
	return err == nil
}

// A model or shape by its catalog id: plain where a signed source vouches for it, marked as the broker's where it
// keeps §6.3's grammar and bound, else unknown; nil or empty for a charge that names none.
func (self *ComputeLabeler) Catalog(catalogId *string) *ComputeDisplayName {
	if catalogId == nil || *catalogId == "" {
		return computePlainName(computeNameNoneText)
	}
	if !self.catalogIdInGrammar(*catalogId) {
		return computeUnknownName()
	}
	if self.index.catalog[*catalogId] {
		return computePlainName(*catalogId)
	}
	return &ComputeDisplayName{Text: *catalogId, Trust: ComputeNameMarked, Writer: computeWriterBroker}
}

// Whether name keeps §20.5's grammar, [a-z0-9][a-z0-9-]{0,47}, its length the settings' AgentNameMaxByteCount.
func (self *ComputeLabeler) agentNameValid(name string) bool {
	if name == "" || self.settings.AgentNameMaxByteCount < len(name) {
		return false
	}
	for i := 0; i < len(name); i += 1 {
		c := name[i]
		digitOrLetter := 'a' <= c && c <= 'z' || '0' <= c && c <= '9'
		if !digitOrLetter && (i == 0 || c != '-') {
			return false
		}
	}
	return true
}

// An agent by its card where the viewer may read it, plain where an untainted run on the member's untagged device
// wrote the card, else marked with its writer; else as an agent of memberId's member. nil for calls no agent named.
func (self *ComputeLabeler) Agent(agentId *Id, memberId *Id) *ComputeDisplayName {
	if agentId == nil {
		return computePlainName(computeNameNoneText)
	}
	if card, ok := self.index.agents[*agentId]; ok && card != nil {
		if !self.agentNameValid(card.Name) {
			return computeUnknownName()
		}
		if card.Trusted {
			return computePlainName(card.Name)
		}
		writer := card.Writer
		if !self.fits(writer) {
			writer = computeNameUnknownText
		}
		return &ComputeDisplayName{Text: card.Name, Trust: ComputeNameMarked, Writer: writer}
	}
	member := self.Member(memberId)
	if member.Trust != ComputeNamePlain {
		return computeUnknownName()
	}
	return computePlainName(computeAgentOfPrefix + member.Text)
}

// The name of a breakdown row's key, by its view's dimension.
func (self *ComputeLabeler) spendRow(by ComputeSpendBy, row *ComputeSpendRow) *ComputeDisplayName {
	switch by {
	case ComputeSpendByProvider:
		if row.Provider == nil {
			return computeUnknownName()
		}
		return self.Provider(*row.Provider)
	case ComputeSpendByModel:
		return self.Catalog(row.CatalogId)
	case ComputeSpendByEnclave:
		return self.Enclave(row.EnclaveId)
	case ComputeSpendByMember:
		return self.Member(row.MemberId)
	case ComputeSpendByAgent:
		return self.Agent(row.AgentId, row.MemberId)
	}
	return computeUnknownName()
}

// One breakdown row with its name.
type ComputeSpendViewRow struct {
	Name *ComputeDisplayName `json:"name"`
	// The row's key and figures, as answered.
	Row *ComputeSpendRow `json:"row"`
}

// One line of the view: a charge kind, the service it counts to, its figures and its named rows.
type ComputeSpendViewLine struct {
	Service ComputeService         `json:"service"`
	Kind    ComputeChargeKind      `json:"kind"`
	Total   *ComputeSpendFigures   `json:"total"`
	Days    []*ComputeSpendFigures `json:"days"`
	Rows    []*ComputeSpendViewRow `json:"rows"`
}

// §9.13's spend view as the device shows it: each charge kind's line with its named rows, every service together, the
// window's UTC days and their bounds, the holds apart, and the services that cost nothing.
type ComputeSpendView struct {
	By ComputeSpendBy `json:"by"`
	// The window's UTC days, oldest first, the last today so far (Q-BAL-8).
	Days []string `json:"days"`
	// The window's bounds: the first day's start and the last day's end, both midnight UTC.
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	// The totals' since; empty before any charge.
	FirstChargeDay string `json:"first_charge_day"`
	// The settlement time every figure is exact to.
	UpdateTime  time.Time               `json:"update_time"`
	HeldNanoUsd int64                   `json:"held_nano_usd"`
	Lines       []*ComputeSpendViewLine `json:"lines"`
	// Every service together: the lines' sums, exact.
	AllTotal *ComputeSpendFigures   `json:"all_total"`
	AllDays  []*ComputeSpendFigures `json:"all_days"`
	// Web fetch, calendar calls and connected services: at no charge.
	WithoutCharge []string `json:"without_charge"`
}

// The view of spend, its rows named by this labeler.
func (self *ComputeLabeler) SpendView(spend *ComputeSpend) *ComputeSpendView {
	view := &ComputeSpendView{
		By:             spend.By,
		Days:           slices.Clone(spend.Days),
		FirstChargeDay: spend.FirstChargeDay,
		UpdateTime:     spend.UpdateTime,
		HeldNanoUsd:    spend.HeldNanoUsd,
		Lines:          []*ComputeSpendViewLine{},
		AllTotal:       &ComputeSpendFigures{},
		AllDays:        []*ComputeSpendFigures{},
		WithoutCharge:  ComputeServicesWithoutCharge(),
	}
	if 0 < len(spend.Days) {
		first, _ := time.ParseInLocation(computeDayLayout, spend.Days[0], time.UTC)
		last, _ := time.ParseInLocation(computeDayLayout, spend.Days[len(spend.Days)-1], time.UTC)
		view.WindowStart = first
		view.WindowEnd = last.AddDate(0, 0, 1)
	}
	for range spend.Days {
		view.AllDays = append(view.AllDays, &ComputeSpendFigures{})
	}
	for _, line := range spend.Lines {
		viewLine := &ComputeSpendViewLine{
			Service: line.Kind.Service(),
			Kind:    line.Kind,
			Total:   line.Total,
			Days:    line.Days,
			Rows:    []*ComputeSpendViewRow{},
		}
		for _, row := range line.Rows {
			viewLine.Rows = append(viewLine.Rows, &ComputeSpendViewRow{Name: self.spendRow(spend.By, row), Row: row})
		}
		view.Lines = append(view.Lines, viewLine)
		view.AllTotal = view.AllTotal.add(line.Total)
		for index, day := range line.Days {
			if index < len(view.AllDays) {
				view.AllDays[index] = view.AllDays[index].add(day)
			}
		}
	}
	return view
}

// The names of a charge's or a day row's ids.
type ComputeRowNames struct {
	Sidecar  *ComputeDisplayName `json:"sidecar"`
	Member   *ComputeDisplayName `json:"member"`
	Agent    *ComputeDisplayName `json:"agent"`
	Enclave  *ComputeDisplayName `json:"enclave"`
	Model    *ComputeDisplayName `json:"model"`
	Provider *ComputeDisplayName `json:"provider"`
}

// The names of a row's ids.
func (self *ComputeLabeler) rowNames(sidecarId Id, memberId *Id, agentId *Id, enclaveId *Id, catalogId string, provider int16) *ComputeRowNames {
	return &ComputeRowNames{
		Sidecar:  self.Sidecar(sidecarId),
		Member:   self.Member(memberId),
		Agent:    self.Agent(agentId, memberId),
		Enclave:  self.Enclave(enclaveId),
		Model:    self.Catalog(&catalogId),
		Provider: self.Provider(provider),
	}
}

// One charge with its names.
type ComputeChargeViewRow struct {
	Names  *ComputeRowNames  `json:"names"`
	Charge *ComputeChargeRow `json:"charge"`
}

// One page of charges, each named.
type ComputeChargesView struct {
	Charges    []*ComputeChargeViewRow `json:"charges"`
	NextCursor string                  `json:"next_cursor"`
}

// The view of a page of charges, named by this labeler.
func (self *ComputeLabeler) ChargesView(charges *ComputeCharges) *ComputeChargesView {
	view := &ComputeChargesView{Charges: []*ComputeChargeViewRow{}, NextCursor: charges.NextCursor}
	for _, charge := range charges.Charges {
		view.Charges = append(view.Charges, &ComputeChargeViewRow{
			Names:  self.rowNames(charge.SidecarId, charge.MemberId, charge.AgentId, charge.EnclaveId, charge.CatalogId, charge.Provider),
			Charge: charge,
		})
	}
	return view
}

// One statement day row with its names.
type ComputeStatementViewRow struct {
	Names *ComputeRowNames     `json:"names"`
	Row   *ComputeStatementRow `json:"row"`
}

// A month's statement, its rows named, its lots as answered.
type ComputeStatementView struct {
	Month string                     `json:"month"`
	Rows  []*ComputeStatementViewRow `json:"rows"`
	Lots  []*ComputeLotRow           `json:"lots"`
}

// The view of a statement, named by this labeler.
func (self *ComputeLabeler) StatementView(statement *ComputeStatement) *ComputeStatementView {
	view := &ComputeStatementView{Month: statement.Month, Rows: []*ComputeStatementViewRow{}, Lots: statement.Lots}
	for _, row := range statement.Rows {
		view.Rows = append(view.Rows, &ComputeStatementViewRow{
			Names: self.rowNames(row.SidecarId, row.MemberId, row.AgentId, row.EnclaveId, row.CatalogId, row.Provider),
			Row:   row,
		})
	}
	return view
}

// An amount of nano-USD to the cent, rounded half away from zero: "$12.34", "-$0.50" for a credit, "$0.00" for none,
// and "< $0.01" for an amount above zero that rounds to none ("> -$0.01" below zero), so a charge is never shown as
// free (§9.13).
func ComputeMoneyText(nanoUsd int64) string {
	// a cent is 10^7 nano-USD
	const nanoUsdPerCent = 10_000_000
	negative := nanoUsd < 0
	magnitude := uint64(nanoUsd)
	if negative {
		magnitude = uint64(-(nanoUsd + 1)) + 1
	}
	cents := (magnitude + nanoUsdPerCent/2) / nanoUsdPerCent
	if cents == 0 && magnitude != 0 {
		if negative {
			return "> -$0.01"
		}
		return "< $0.01"
	}
	text := fmt.Sprintf("$%d.%02d", cents/100, cents%100)
	if negative && cents != 0 {
		return "-" + text
	}
	return text
}

// The view's window as a person reads it: its UTC days, and their bounds in location beside, as the apps show them
// (Q-BAL-8): "2026-11-18 to 2026-11-24 UTC (local 2026-11-17 16:00 to 2026-11-24 16:00 PST)". Empty for a view
// with no days.
func ComputeSpendWindowText(view *ComputeSpendView, location *time.Location) string {
	if len(view.Days) == 0 {
		return ""
	}
	if location == nil {
		location = time.UTC
	}
	const localLayout = "2006-01-02 15:04"
	start := view.WindowStart.In(location)
	end := view.WindowEnd.In(location)
	return fmt.Sprintf("%s to %s UTC (local %s to %s %s)", view.Days[0], view.Days[len(view.Days)-1],
		start.Format(localLayout), end.Format(localLayout), end.Format("MST"))
}
