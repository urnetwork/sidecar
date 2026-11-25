// The provider registry and its gating (DESIGN-COMPUTE §4.6, §4.7, D-PROV-7; compute-plan-adapters-before-commitment,
// QD-1233). Each adapter registers its constructor at init from its own computeservice/provider_<slug>.go through
// registerComputeProvider, as the routes do, so no adapter edits this file and nothing names a provider but its own
// file. A registry builds, once, the adapter of each provider this deployment's settings enable in its env, and serves
// an adapter for new work only while both hold:
//
//   - the settings enable the provider in the env (ComputeProviderSettings.Enabled), which for the reference provider
//     takes a development, CI or staging env, so a production registry never builds it (D-ENC-2, CO-21);
//   - its compute_provider row reads gated (§4.7), read at most StatusMaxAge ago: a row that is absent, foreign, or
//     not gated refuses the provider, and a read that fails refuses every provider, never keeps one serving past the
//     age (provider_store.go).
//
// So a disabled adapter's models and shapes never reach the catalog, and a gate that fails takes its provider out
// while the rest serve on. Reachable answers a provider whose row reads suspended or out too, for the work already
// under way there: settling its calls, reading its balance, deleting its VMs.
//
// Each adapter gets its own section of the block's compute-providers.yml (computehost's providers file) and nothing of
// another's, and the newest verified compute policy the broker holds, the only source of hosts, receivers, targets and
// model ids (§5.4).
//
// The registrations are written only during the package's init, so read without a lock after it. A registry is safe
// for concurrent use: its adapters are built at construction and never change, and its statuses are read under
// stateLock, the database read outside it, concurrent askers sharing one read.

package computeservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
)

// The block's vault file holding every adapter's credentials (§14.2's Adapters row): computehost's
// HostProvidersFileName. A YAML mapping from each provider's slug to whatever its adapter reads.
const ComputeProvidersSecretFileName = "compute-providers.yml"

// The kind of the credentials the privacy harness scans for (§22.4's testHookSecret).
const computeProviderCredentialsSecretKind = "computeservice.provider_credentials"

// What a registry answers for a provider it will not serve: not enabled here, no adapter in this build, its
// constructor's failure, its row not gated, or its row unread. errors.Is matches it; the message says which.
var ErrComputeProviderDisabled = errors.New("compute provider disabled")

// What an adapter's constructor takes. Nothing is read at construction: the policy, the credentials and the network
// are reached at each call, so a constructor does no I/O.
type ComputeProviderArgs struct {
	// The provider being built.
	Id ComputeProviderId
	// The providers' settings, read only: the adapter's payment (Settings.Payment) and its bounds.
	Settings *ComputeProviderSettings
	// The newest verified compute policy the broker holds, nil while it holds none (§5.4). Never nil itself.
	Policy func() *sidecar.ComputePolicy
	// The adapter's own section of the block's compute-providers.yml, as YAML, read at each call: an error where the
	// block holds no such file or the file no section for this provider. Never nil itself.
	Credentials func() ([]byte, error)
	// What reaches the provider's API: the deployment's, or a test's pointed at a fake provider.
	HttpClient *http.Client
	Clock      sidecar.Clock
	Log        sidecar.Logger
}

// Builds one provider's adapter for one registry.
type ComputeProviderConstructor func(args *ComputeProviderArgs) (ComputeProvider, error)

// One provider's registration.
type computeProviderRegistration struct {
	id        ComputeProviderId
	construct ComputeProviderConstructor
}

// Every adapter's registration, in the order the files' init functions made them.
var computeProviderRegistrations = []*computeProviderRegistration{}

// Registers id's adapter, from an init function in its own file. A slug this build does not know, a search provider,
// which no adapter reaches, a nil constructor and a second registration of one slug are build errors, which panic.
func registerComputeProvider(id ComputeProviderId, construct ComputeProviderConstructor) {
	kind, known := ComputeProviderKindOf(id)
	registered := slices.ContainsFunc(computeProviderRegistrations, func(registration *computeProviderRegistration) bool {
		return registration.id == id
	})
	if !known || kind == ComputeProviderKindSearch || construct == nil || registered {
		panic(fmt.Errorf("compute provider %q registered twice, without a constructor, or as no provider an adapter reaches", id))
	}
	computeProviderRegistrations = append(computeProviderRegistrations, &computeProviderRegistration{id: id, construct: construct})
}

// Where a registry reads each provider's status: the store over the process's Postgres, or a test's.
type computeProviderStatusSource interface {
	Statuses(ctx context.Context) (map[ComputeProviderId]ComputeProviderStatus, error)
}

// What a registry is built from.
type ComputeProviderRegistryArgs struct {
	// The providers' settings, validated here. nil: DefaultComputeProviderSettings.
	Settings *ComputeProviderSettings
	// The database compute_provider is read from, asked at each read: the process's Env's. nil refuses every
	// provider.
	Db func() (operator.Db, error)
	// The newest verified compute policy the broker holds. nil gives every adapter none.
	Policy func() *sidecar.ComputePolicy
	// One of the block's vault files by name (ComputeEngineDeps.SecretFile). nil gives every adapter no credentials.
	SecretFile func(name string) ([]byte, error)
	// What adapters reach their providers with. nil: a client of the standard transport, each call bounded by its
	// context alone.
	HttpClient *http.Client
	// nil: the wall clock.
	Clock sidecar.Clock
	// nil discards.
	Log sidecar.Logger

	// A test's registrations, in place of the registered ones.
	testRegistrations []*computeProviderRegistration
	// A test's status source, in place of the store over Db.
	testStatuses computeProviderStatusSource
}

// The adapters a deployment enables and their gating. See the file header.
type ComputeProviderRegistry struct {
	settings *ComputeProviderSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	statuses computeProviderStatusSource
	// each enabled provider's adapter, and why an enabled provider has none
	adapters    map[ComputeProviderId]ComputeProvider
	adapterErrs map[ComputeProviderId]error

	stateLock sync.Mutex
	// the statuses last read, and when; nil before the first read and after a failed one
	readStatuses map[ComputeProviderId]ComputeProviderStatus
	readTime     time.Time
	// the read in flight, which every asker waits on; nil for none
	statusRead *computeProviderStatusRead
}

// One read of the statuses, shared by the askers that came while it ran.
type computeProviderStatusRead struct {
	done     chan struct{}
	statuses map[ComputeProviderId]ComputeProviderStatus
	err      error
}

// A registry over args: settings that do not validate refuse it, as an engine refuses to start on them, and each
// provider the settings enable in the env gets its adapter built. A constructor's failure leaves its provider refusing
// for this registry's life, the others built regardless.
func NewComputeProviderRegistry(args *ComputeProviderRegistryArgs) (*ComputeProviderRegistry, error) {
	if args == nil {
		args = &ComputeProviderRegistryArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultComputeProviderSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	httpClient := args.HttpClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	policy := args.Policy
	if policy == nil {
		policy = func() *sidecar.ComputePolicy { return nil }
	}
	statuses := args.testStatuses
	if statuses == nil {
		statuses = &computeProviderDbStatuses{db: args.Db, settings: settings}
	}
	registrations := computeProviderRegistrations
	if args.testRegistrations != nil {
		registrations = args.testRegistrations
	}
	self := &ComputeProviderRegistry{
		settings:    settings,
		clock:       clock,
		log:         log,
		statuses:    statuses,
		adapters:    map[ComputeProviderId]ComputeProvider{},
		adapterErrs: map[ComputeProviderId]error{},
	}
	for _, registration := range registrations {
		id := registration.id
		if !settings.Enabled(id) {
			continue
		}
		adapter, err := registration.construct(&ComputeProviderArgs{
			Id:       id,
			Settings: settings,
			Policy:   policy,
			Credentials: func() ([]byte, error) {
				return computeProviderCredentials(args.SecretFile, settings, id)
			},
			HttpClient: httpClient,
			Clock:      clock,
			Log:        log,
		})
		switch {
		case err != nil:
			self.adapterErrs[id] = err
			log.Infof("[compute] the %s adapter did not build, so it serves nothing here: %v", id, err)
		case adapter == nil || adapter.Id() != id:
			self.adapterErrs[id] = fmt.Errorf("its constructor built no %s adapter", id)
		default:
			self.adapters[id] = adapter
		}
	}
	return self, nil
}

// The settings the registry runs under, read only.
func (self *ComputeProviderRegistry) Settings() *ComputeProviderSettings {
	return self.settings
}

// id's adapter for new work: enabled here, built, and its row gated now. Otherwise an error wrapping
// ErrComputeProviderDisabled that says why.
func (self *ComputeProviderRegistry) Enabled(ctx context.Context, id ComputeProviderId) (ComputeProvider, error) {
	return self.serving(ctx, id, []ComputeProviderStatus{ComputeProviderStatusGated})
}

// id's adapter for work already under way there, its calls' settlement, its balance and its VMs: enabled here, built,
// and its row gated, suspended or out. A provider never gated, whose row reads listed or is absent, has none.
func (self *ComputeProviderRegistry) Reachable(ctx context.Context, id ComputeProviderId) (ComputeProvider, error) {
	return self.serving(ctx, id, []ComputeProviderStatus{ComputeProviderStatusGated, ComputeProviderStatusSuspended, ComputeProviderStatusOut})
}

// Every adapter Enabled answers now, in code order. An error where the statuses cannot be read, which refuses every
// provider: no adapter is answered then.
func (self *ComputeProviderRegistry) EnabledProviders(ctx context.Context) ([]ComputeProvider, error) {
	statuses, err := self.currentStatuses(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: compute_provider does not read: %w", ErrComputeProviderDisabled, err)
	}
	adapters := []ComputeProvider{}
	for _, id := range ComputeProviderIds() {
		if adapter, ok := self.adapters[id]; ok && statuses[id] == ComputeProviderStatusGated {
			adapters = append(adapters, adapter)
		}
	}
	return adapters, nil
}

// id's adapter where it is enabled, built and its row's status one of allowed.
func (self *ComputeProviderRegistry) serving(ctx context.Context, id ComputeProviderId, allowed []ComputeProviderStatus) (ComputeProvider, error) {
	if _, known := ComputeProviderKindOf(id); !known {
		return nil, fmt.Errorf("%w: %q is no provider this build knows", ErrComputeProviderDisabled, id)
	}
	if !self.settings.Enabled(id) {
		return nil, fmt.Errorf("%w: %s is not enabled in this env", ErrComputeProviderDisabled, id)
	}
	adapter, built := self.adapters[id]
	if !built {
		if err, failed := self.adapterErrs[id]; failed {
			return nil, fmt.Errorf("%w: %s's adapter did not build: %w", ErrComputeProviderDisabled, id, err)
		}
		return nil, fmt.Errorf("%w: this build has no %s adapter", ErrComputeProviderDisabled, id)
	}
	statuses, err := self.currentStatuses(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s's row does not read: %w", ErrComputeProviderDisabled, id, err)
	}
	status, found := statuses[id]
	if !found {
		return nil, fmt.Errorf("%w: compute_provider holds no readable row for %s", ErrComputeProviderDisabled, id)
	}
	if !slices.Contains(allowed, status) {
		return nil, fmt.Errorf("%w: %s's row reads %s", ErrComputeProviderDisabled, id, status)
	}
	return adapter, nil
}

// The statuses as read within StatusMaxAge, or read now, one read shared by every asker that comes while it runs. A
// failed read answers its error to every one of them and keeps nothing, so no status outlives its age.
func (self *ComputeProviderRegistry) currentStatuses(ctx context.Context) (map[ComputeProviderId]ComputeProviderStatus, error) {
	var cached map[ComputeProviderId]ComputeProviderStatus
	var read *computeProviderStatusRead
	lead := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		now := self.clock.Now()
		if self.readStatuses != nil && 0 < self.settings.StatusMaxAge && !now.Before(self.readTime) &&
			now.Sub(self.readTime) < self.settings.StatusMaxAge {
			cached = self.readStatuses
			return
		}
		if self.statusRead == nil {
			self.statusRead = &computeProviderStatusRead{done: make(chan struct{})}
			lead = true
		}
		read = self.statusRead
	}()
	if cached != nil {
		return cached, nil
	}
	if lead {
		readTime := self.clock.Now()
		statuses, err := self.statuses.Statuses(ctx)
		if err == nil && statuses == nil {
			err = errors.New("the read answered no statuses")
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.statusRead = nil
			if err != nil {
				self.readStatuses = nil
				return
			}
			self.readStatuses = statuses
			self.readTime = readTime
		}()
		read.statuses, read.err = statuses, err
		close(read.done)
	}
	select {
	case <-read.done:
		return read.statuses, read.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// The store's statuses over a database asked for at each read.
type computeProviderDbStatuses struct {
	db       func() (operator.Db, error)
	settings *ComputeProviderSettings
}

// The statuses of the store over the database asked for now.
func (self *computeProviderDbStatuses) Statuses(ctx context.Context) (map[ComputeProviderId]ComputeProviderStatus, error) {
	if self.db == nil {
		return nil, errors.New("no database is given")
	}
	db, err := self.db()
	if err != nil {
		return nil, err
	}
	return NewComputeProviderStore(db, self.settings).Statuses(ctx)
}

// id's section of compute-providers.yml, as YAML: an error where there is no reader, no file, a file past the
// settings' bound or not a mapping, or no section for id.
func computeProviderCredentials(secretFile func(name string) ([]byte, error), settings *ComputeProviderSettings, id ComputeProviderId) ([]byte, error) {
	if secretFile == nil {
		return nil, fmt.Errorf("%s: this block holds no credentials", id)
	}
	data, err := secretFile(ComputeProvidersSecretFileName)
	if err != nil {
		return nil, fmt.Errorf("%s: %s does not read: %w", id, ComputeProvidersSecretFileName, err)
	}
	if settings.CredentialsFileMaxByteCount < len(data) {
		return nil, fmt.Errorf("%s: %s is longer than %d bytes", id, ComputeProvidersSecretFileName, settings.CredentialsFileMaxByteCount)
	}
	sections := map[string]yaml.Node{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&sections); err != nil {
		// never the error's text, which may quote the file
		return nil, fmt.Errorf("%s: %s is not a mapping of providers", id, ComputeProvidersSecretFileName)
	}
	section, found := sections[string(id)]
	if !found {
		return nil, fmt.Errorf("%s: %s holds no section for it", id, ComputeProvidersSecretFileName)
	}
	credentials, err := yaml.Marshal(&section)
	if err != nil {
		return nil, fmt.Errorf("%s: its section of %s does not encode", id, ComputeProvidersSecretFileName)
	}
	testHookSecret(computeProviderCredentialsSecretKind, credentials)
	return credentials, nil
}

// The engine's registry, over its settings' Providers, its Env's database, its policy, its secret files and its clock.
func newComputeEngineProviderRegistry(engine *ComputeEngine) (*ComputeProviderRegistry, error) {
	return NewComputeProviderRegistry(&ComputeProviderRegistryArgs{
		Settings: engine.settings.Providers,
		Db: func() (operator.Db, error) {
			return engine.Env().Db()
		},
		Policy:     engine.deps.Policy,
		SecretFile: engine.deps.SecretFile,
		HttpClient: engine.deps.ProviderHttpClient,
		Clock:      engine.clock,
		Log:        engine.log,
	})
}

// The provider adapters this engine's deployment enables, which a handler asks for the adapter it calls.
func (self *ComputeEngine) Providers() *ComputeProviderRegistry {
	return self.providers
}
