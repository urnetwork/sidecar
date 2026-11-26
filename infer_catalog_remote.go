//go:build !ios_extension && !sidecar_http

// The remote catalog on the device (DESIGN-COMPUTE §6.3's sources and version rows, R-INFER-1, R-INFER-8, D-INFER-1,
// R1-14; INFER-M12-01): the broker's GET compute/v1/catalog, fetched through the compute service client and kept, then
// joined with the newest verified compute policy into the router's remote entries (registerInferRemoteCatalog). The
// catalog is unsigned and decides nothing about who reads a prompt:
//
//   - a model the policy does not cover, in a TEE or not, is listed unusable and never run;
//   - a TEE model's label and its provider's id for it come from the policy's providers line, never the catalog's;
//   - a direct model's provider id, zero-retention rule and upstreams come from the policy's models map alone, and the
//     host, receiver and targets the catalog names must equal the policy's, else it is listed unusable;
//   - a catalog in which two entries share a name is refused whole, and the last good one is kept;
//   - an entry that is not whole (a name outside §6.3's grammar, a label its kind does not take, a TEE mark on a model
//     labeled none) is left out, each named in the log.
//
// What the router's checks refuse of the rest, the floor, the providers, tee_only and allow, they list unavailable with
// the reason (infer_check.go's limit), and a filter or floor that leaves no remote entry keeps the local ones and says
// why (§6.3). A request names the version its entries came from (§6.3, §9.6): WithVersion asks with it, and on the
// broker's catalog_stale fetches the catalog and asks once more, so a modified client never keeps an old price.
//
// Each area's section (ENC's shapes, SRCH's search ids) joins through registerInferCatalogSection from its own file,
// as computeCatalogRegisterSection's builders do at the broker.
//
// Fetching never holds a call on the network: a kept catalog is listed at once, one past RemoteCatalogMaxAge fetched again
// in the background, and with none kept yet a list waits for the first fetch at most RemoteCatalogFirstFetchWait, so a
// local call on a device that cannot reach the broker waits that long once. A fetch that fails keeps the last good
// catalog and is not tried again for RemoteCatalogFailureRetryInterval.
//
// Safe for concurrent use: one fetch runs at a time, on a goroutine of its own that ends with the Sidecar, and
// stateLock guards what it kept.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The catalog route, from the broker's base url.
const inferRemoteCatalogPath = "/v1/catalog"

var (
	// A request the broker refused catalog_stale twice: once with the version held, and again with the version a
	// fresh fetch gave (§6.3).
	ErrInferCatalogStale = errors.New("the remote catalog's version is stale")
	// A catalog answer that cannot be a catalog: two entries of one name, or more models than the format takes.
	ErrInferCatalogAnswer = errors.New("remote catalog refused")
	// No catalog is kept yet, and the first fetch has not answered within RemoteCatalogFirstFetchWait.
	ErrInferCatalogFetching = errors.New("the remote catalog is being fetched")
)

// The broker's catalog code a request is refused with when it names a version the broker no longer takes.
const inferCatalogStaleCode = "catalog_stale"

// Turns one area's section of the catalog into catalog entries, from that area's own file (SRCH's search ids): none
// may be local or a model's, and a section that does not read lists none.
type InferCatalogSectionReader func(body []byte, settings *InferSettings) ([]*InferCatalogEntry, error)

// The section readers by section name. Written only during the package's init.
var inferCatalogSectionReaders = map[string]InferCatalogSectionReader{}

// Registers the reader of the catalog section name, from an init function in its area's own file. An empty name, a nil
// reader or a name registered twice is a build error, which panics.
func registerInferCatalogSection(name string, read InferCatalogSectionReader) {
	if _, registered := inferCatalogSectionReaders[name]; name == "" || read == nil || registered {
		panic(fmt.Sprintf("remote catalog section %q registered twice or without a reader", name))
	}
	inferCatalogSectionReaders[name] = read
}

// The catalog's kind of a model.
func inferCatalogKindOf(kind protocol.InferCatalogModelKind) (InferCatalogKind, bool) {
	switch kind {
	case protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_TEE:
		return InferCatalogKindTee, true
	case protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT:
		return InferCatalogKindDirect, true
	}
	return "", false
}

// One answer's model as a catalog entry, its fields as the broker wrote them: the policy has not joined it yet.
func inferCatalogModelEntry(model *protocol.InferCatalogModel) *InferCatalogEntry {
	kind, _ := inferCatalogKindOf(model.GetKind())
	efforts := make([]InferEffort, len(model.GetEfforts()))
	for i, effort := range model.GetEfforts() {
		efforts[i] = InferEffort(effort)
	}
	modalities := make([]InferModality, len(model.GetModalities()))
	for i, modality := range model.GetModalities() {
		modalities[i] = InferModality(modality)
	}
	return &InferCatalogEntry{
		Provider:         model.GetProvider(),
		Model:            model.GetModel(),
		Kind:             kind,
		Label:            ComputeLabel(model.GetLabel()),
		Efforts:          efforts,
		DefaultEffort:    InferEffort(model.GetDefaultEffort()),
		ContextWindow:    model.GetContextWindow(),
		MaxOutput:        model.GetMaxOutput(),
		Tools:            model.GetTools(),
		StructuredOutput: model.GetStructuredOutput(),
		Modalities:       modalities,
		License:          model.GetLicense(),
		Remote: &InferRemoteModel{
			ProviderModelId:              model.GetProviderModelId(),
			InputNanoUsdPerMillion:       model.GetInputNanoUsdPerMillion(),
			OutputNanoUsdPerMillion:      model.GetOutputNanoUsdPerMillion(),
			CachedInputNanoUsdPerMillion: model.GetCachedInputNanoUsdPerMillion(),
			ServingCodeUnmeasured:        model.GetServingCodeUnmeasured(),
		},
	}
}

// One model of a catalog answer, as InferCatalogAnswerEntries reads it.
type InferCatalogAnswerEntry struct {
	// The model as the broker wrote it.
	Model *protocol.InferCatalogModel
	// Its catalog entry, before the policy joins it.
	Entry *InferCatalogEntry
}

// The answer's models as catalog entries, in its order: each that is whole, beside a fault for each left out (a kind
// that is no remote model's, a name outside §6.3's grammar, a label its kind does not take, a TEE mark on a model
// labeled none, a negative price). ErrInferCatalogAnswer where two of them share a name or a model, or the answer holds
// more models than settings.ProviderModelIdMaxCount, which refuses the answer whole: what the device refuses of a
// catalog (§6.3), and what the broker's build holds itself to before it publishes.
func InferCatalogAnswerEntries(answer *protocol.InferCatalogAnswer, settings *InferSettings) ([]*InferCatalogAnswerEntry, []string, error) {
	if answer == nil {
		return nil, nil, fmt.Errorf("%w: no answer", ErrInferCatalogAnswer)
	}
	if settings.ProviderModelIdMaxCount < len(answer.GetModels()) {
		return nil, nil, fmt.Errorf("%w: more than %d models", ErrInferCatalogAnswer, settings.ProviderModelIdMaxCount)
	}
	entries := []*InferCatalogAnswerEntry{}
	faults := []string{}
	for _, model := range answer.GetModels() {
		if model == nil {
			faults = append(faults, "an empty model")
			continue
		}
		if _, ok := inferCatalogKindOf(model.GetKind()); !ok {
			faults = append(faults, "a model of no remote kind")
			continue
		}
		entry := inferCatalogModelEntry(model)
		if fault := entry.fault(settings); fault != "" {
			faults = append(faults, fault)
			continue
		}
		entries = append(entries, &InferCatalogAnswerEntry{Model: model, Entry: entry})
	}
	checked := make([]*InferCatalogEntry, len(entries))
	for i, entry := range entries {
		checked[i] = entry.Entry
	}
	if _, err := NewInferCatalog(checked, settings); err != nil {
		return nil, faults, fmt.Errorf("%w: %w", ErrInferCatalogAnswer, err)
	}
	return entries, faults, nil
}

// entry joined with policy (§6.3's sources row): the label and the provider's id from the policy, a direct model's
// host, receiver and targets held to the policy's, and unusable, with why, where the policy does not cover it. A nil
// policy covers nothing.
func inferJoinCatalogEntry(answerEntry *InferCatalogAnswerEntry, policy *ComputePolicy) *InferCatalogEntry {
	entry := answerEntry.Entry.clone()
	model := answerEntry.Model
	unusable := func(reason string) *InferCatalogEntry {
		entry.Unavailable = reason
		return entry
	}
	if policy == nil {
		return unusable("no verified compute policy is current, so no remote model is usable")
	}
	switch entry.Kind {
	case InferCatalogKindTee:
		provider := policy.Provider(entry.Provider)
		if provider == nil || !provider.Label.Tee() {
			return unusable("the compute policy lists no TEE provider " + entry.Provider + ", so the model is unusable")
		}
		providerModelId := provider.ProviderModelId(entry.Model)
		if providerModelId == "" {
			return unusable("the compute policy does not cover the model, so it is unusable")
		}
		// the label is the policy's: A2 is an instance's, which the TEE path holds each instance to (§4.3)
		entry.Label = provider.Label
		entry.Remote.ProviderModelId = providerModelId
		entry.Remote.Profiles = []string{}
		for _, profile := range provider.Profiles {
			if profile != nil && !policy.ProfileRevoked(profile.Id) {
				entry.Remote.Profiles = append(entry.Remote.Profiles, profile.Id)
			}
		}
	case InferCatalogKindDirect:
		direct := policy.DirectProvider(entry.Provider)
		if direct == nil || policy.Provider(entry.Provider) != nil {
			return unusable("the compute policy lists no direct provider " + entry.Provider + ", so the model is unusable")
		}
		policyModel := direct.Model(entry.Model)
		if policyModel == nil || policyModel.ProviderModelId == "" {
			return unusable("the compute policy does not cover the model, so it is unusable")
		}
		// where a call goes is the policy's alone: the catalog's words must be its words
		if model.GetHost() != "" && model.GetHost() != direct.ApiHost {
			return unusable("the broker's catalog names a host the compute policy does not pin, so the model is unusable")
		}
		if model.GetReceiverHotkey() != "" && model.GetReceiverHotkey() != direct.ReceiverHotkey {
			return unusable("the broker's catalog names a receiver the compute policy does not pin, so the model is unusable")
		}
		for _, target := range model.GetTargets() {
			listed := slices.ContainsFunc(direct.Targets, func(policyTarget *ComputePolicyDirectTarget) bool {
				return policyTarget != nil && policyTarget.Method == target.GetMethod() && policyTarget.Path == target.GetPath()
			})
			if !listed {
				return unusable("the broker's catalog names a target the compute policy does not list, so the model is unusable")
			}
		}
		entry.Label = ComputeLabelNone
		entry.Remote.ProviderModelId = policyModel.ProviderModelId
		entry.Remote.Profiles = nil
		entry.Remote.ServingCodeUnmeasured = false
	}
	return entry
}

// What fetches the broker's catalog.
type inferCatalogFetcher interface {
	// GET compute/v1/catalog's answer, or why there is none.
	FetchCatalog(ctx context.Context) (*protocol.InferCatalogAnswer, error)
}

// What builds an inferRemoteCatalog.
type inferRemoteCatalogArgs struct {
	// Background fetches end with it: the Sidecar's.
	Ctx     context.Context
	Fetcher inferCatalogFetcher
	// The newest verified compute policy while it is current; an error with none.
	Policy   func() (*ComputePolicy, error)
	Settings *InferSettings
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// The remote catalog the router lists. See the file header.
type inferRemoteCatalog struct {
	ctx      context.Context
	fetcher  inferCatalogFetcher
	policy   func() (*ComputePolicy, error)
	settings *InferSettings
	clock    Clock
	log      Logger

	stateLock sync.Mutex
	// the fetch in flight, closed as it ends; nil while none runs
	fetching chan struct{}
	// the last good answer and its entries, nil before the first
	answer    *protocol.InferCatalogAnswer
	entries   []*InferCatalogAnswerEntry
	fetchedAt time.Time
	// the last fetch's failure, kept FailureRetryInterval, and when
	failure   error
	failureAt time.Time
}

var _ InferRemoteCatalog = (*inferRemoteCatalog)(nil)

// A remote catalog over args.
func newInferRemoteCatalog(args *inferRemoteCatalogArgs) (*inferRemoteCatalog, error) {
	if args == nil || args.Ctx == nil || args.Fetcher == nil || args.Policy == nil || args.Settings == nil {
		return nil, errors.New("remote catalog: a context, a fetcher, the policy and settings")
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &inferRemoteCatalog{
		ctx:      args.Ctx,
		fetcher:  args.Fetcher,
		policy:   args.Policy,
		settings: args.Settings,
		clock:    clock,
		log:      log,
	}, nil
}

// See InferRemoteCatalog: the kept catalog joined with the newest verified policy, and its sections' entries. An error
// where no catalog was fetched good yet.
func (self *inferRemoteCatalog) Entries(ctx context.Context) ([]*InferCatalogEntry, error) {
	answer, entries, err := self.current(ctx)
	if answer == nil {
		return nil, err
	}
	policy, policyErr := self.policy()
	if policyErr != nil {
		policy = nil
	}
	joined := make([]*InferCatalogEntry, 0, len(entries))
	for _, entry := range entries {
		joined = append(joined, inferJoinCatalogEntry(entry, policy))
	}
	for _, section := range answer.GetSections() {
		read, ok := inferCatalogSectionReaders[section.GetName()]
		if !ok {
			continue
		}
		sectionEntries, err := read(section.GetBody(), self.settings)
		if err != nil {
			self.log.Warningf("[infer]the remote catalog's %s section does not read: %s", section.GetName(), err)
			continue
		}
		for _, entry := range sectionEntries {
			if entry != nil && entry.Kind == InferCatalogKindSearch {
				joined = append(joined, entry.clone())
			}
		}
	}
	return joined, nil
}

// The version the kept catalog is, which a request names (§6.3). An error where no catalog was ever fetched good.
func (self *inferRemoteCatalog) Version(ctx context.Context) (uint64, error) {
	answer, _, err := self.current(ctx)
	if answer == nil {
		return 0, err
	}
	return answer.GetVersion(), nil
}

// Calls ask with the version the kept catalog is; where ask answers the broker's catalog_stale, fetches the catalog and
// asks once more with the version the fetch gave (§6.3). ErrInferCatalogStale where the second is refused stale too, or
// the fetch gives no newer version; else ask's own answer.
func (self *inferRemoteCatalog) WithVersion(ctx context.Context, ask func(version uint64) error) error {
	version, err := self.Version(ctx)
	if err != nil {
		return err
	}
	err = ask(version)
	if !inferCatalogStale(err) {
		return err
	}
	if err := self.fetchNow(ctx); err != nil {
		return fmt.Errorf("%w: the catalog did not fetch again: %w", ErrInferCatalogStale, err)
	}
	newer, err := self.Version(ctx)
	if err != nil {
		return err
	}
	if newer == version {
		return fmt.Errorf("%w: the broker refused version %d and still answers it", ErrInferCatalogStale, version)
	}
	err = ask(newer)
	if inferCatalogStale(err) {
		return fmt.Errorf("%w: version %d too", ErrInferCatalogStale, newer)
	}
	return err
}

// Whether err is the broker's catalog_stale refusal.
func inferCatalogStale(err error) bool {
	var refusal *ComputeServiceError
	return errors.As(err, &refusal) && refusal.Code == inferCatalogStaleCode
}

// The kept answer and its entries: at once where one is kept, a fetch started in the background where it is older than
// RemoteCatalogMaxAge; with none kept, the first fetch waited for at most RemoteCatalogFirstFetchWait. A failed fetch
// keeps the last good answer, and is not tried again for RemoteCatalogFailureRetryInterval; with none kept, its error.
func (self *inferRemoteCatalog) current(ctx context.Context) (*protocol.InferCatalogAnswer, []*InferCatalogAnswerEntry, error) {
	answer, entries, fresh, failure := self.kept()
	if answer != nil {
		if !fresh && failure == nil {
			self.fetch()
		}
		return answer, entries, nil
	}
	if failure != nil {
		return nil, nil, failure
	}
	done := self.fetch()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-self.clock.After(self.settings.RemoteCatalogFirstFetchWait):
	}
	answer, entries, _, failure = self.kept()
	switch {
	case answer != nil:
		return answer, entries, nil
	case failure != nil:
		return nil, nil, failure
	}
	return nil, nil, ErrInferCatalogFetching
}

// The kept answer and entries, whether they are fresh, and the last failure while it stands.
func (self *inferRemoteCatalog) kept() (*protocol.InferCatalogAnswer, []*InferCatalogAnswerEntry, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	fresh := self.answer != nil && 0 < self.settings.RemoteCatalogMaxAge && now.Sub(self.fetchedAt) < self.settings.RemoteCatalogMaxAge
	var failure error
	if self.failure != nil && 0 < self.settings.RemoteCatalogFailureRetryInterval &&
		now.Sub(self.failureAt) < self.settings.RemoteCatalogFailureRetryInterval {
		failure = self.failure
	}
	return self.answer, self.entries, fresh, failure
}

// Starts a fetch on a goroutine of its own where none is in flight, and answers the channel that closes as the one in
// flight ends.
func (self *inferRemoteCatalog) fetch() <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fetching != nil {
		return self.fetching
	}
	done := make(chan struct{})
	self.fetching = done
	go func() {
		defer func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.fetching = nil
			close(done)
		}()
		self.fetchOnce(self.ctx)
	}()
	return done
}

// A fetch now, waited for: the one in flight where one is, else a new one. Its failure, nil where it kept a catalog.
func (self *inferRemoteCatalog) fetchNow(ctx context.Context) error {
	started := self.clock.Now()
	select {
	case <-self.fetch():
	case <-ctx.Done():
		return ctx.Err()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failure != nil && !self.failureAt.Before(started) {
		return self.failure
	}
	return nil
}

// The channel that closes once no fetch is in flight: a test's wait for a fetch started in the background.
func (self *inferRemoteCatalog) idle() <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fetching != nil {
		return self.fetching
	}
	done := make(chan struct{})
	close(done)
	return done
}

// One fetch, which keeps the answer where it is good: an answer whose entries collide, that is no catalog, or that is
// older than the version kept is refused, and the last good one kept (§6.3).
func (self *inferRemoteCatalog) fetchOnce(ctx context.Context) {
	answer, err := self.fetcher.FetchCatalog(ctx)
	var entries []*InferCatalogAnswerEntry
	if err == nil {
		var faults []string
		entries, faults, err = InferCatalogAnswerEntries(answer, self.settings)
		if 0 < len(faults) {
			self.log.Warningf("[infer]the remote catalog's version %d left out %d entries: %s", answer.GetVersion(), len(faults), strings.Join(faults, "; "))
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err == nil && self.answer != nil && answer.GetVersion() < self.answer.GetVersion() {
		// never taken, since a modified broker could offer an old price
		err = fmt.Errorf("%w: version %d after %d", ErrInferCatalogAnswer, answer.GetVersion(), self.answer.GetVersion())
	}
	if err != nil {
		if self.log.V(1).Enabled() {
			self.log.Infof("[infer]the remote catalog did not fetch: %s", err)
		}
		self.failure = err
		self.failureAt = self.clock.Now()
		return
	}
	self.answer = answer
	self.entries = entries
	self.fetchedAt = self.clock.Now()
	self.failure = nil
}

// Registers the remote catalog, which every Sidecar's router then lists.
func init() {
	registerInferRemoteCatalog(newSidecarInferRemoteCatalog)
}

// The remote catalog over sidecar's compute service client and its compute policy gate, each looked up at use.
func newSidecarInferRemoteCatalog(sidecar *Sidecar, settings *InferSettings) (InferRemoteCatalog, error) {
	ctx := sidecar.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return newInferRemoteCatalog(&inferRemoteCatalogArgs{
		Ctx:     ctx,
		Fetcher: &inferSidecarCatalogFetcher{sidecar: sidecar, settings: settings},
		Policy: func() (*ComputePolicy, error) {
			gate, err := sidecar.ComputePolicyGate()
			if err != nil {
				return nil, err
			}
			return gate.PolicyCurrent()
		},
		Settings: settings,
		Clock:    sidecar.clock,
		Log:      sidecar.log,
	})
}

// The catalog's fetch through the Sidecar's compute service client.
type inferSidecarCatalogFetcher struct {
	sidecar  *Sidecar
	settings *InferSettings
}

// See inferCatalogFetcher.
func (self *inferSidecarCatalogFetcher) FetchCatalog(ctx context.Context) (*protocol.InferCatalogAnswer, error) {
	client, err := self.sidecar.ComputeServiceClient()
	if err != nil {
		return nil, err
	}
	answer := &protocol.InferCatalogAnswer{}
	if err := client.Get(ctx, inferRemoteCatalogPath, answer, self.settings.RemoteCatalogMaxByteCount); err != nil {
		return nil, err
	}
	return answer, nil
}

// This Sidecar's remote catalog, which a remote path asks a request's version of (WithVersion), or why there is none.
func (self *Sidecar) inferRemoteCatalog() (*inferRemoteCatalog, error) {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return nil, err
	}
	if infer.router.remoteCatalogErr != nil {
		return nil, infer.router.remoteCatalogErr
	}
	catalog, ok := infer.router.remoteCatalog.(*inferRemoteCatalog)
	if !ok {
		return nil, errors.New("no remote catalog runs on this Sidecar")
	}
	return catalog, nil
}
