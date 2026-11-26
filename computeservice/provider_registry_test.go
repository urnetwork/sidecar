package computeservice

// The registry and its gating (PROV-M12-01; DESIGN-COMPUTE §4.7, D-ENC-2, CO-21): an adapter serves only where the
// settings enable it in the env and its row reads gated; a row that does not read refuses; the reference provider runs
// in development, CI and staging alone, an engine that would run it in production refusing to start; each adapter
// gets its own credentials and no other's.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A status source a test sets. Safe for concurrent use.
type fakeComputeProviderStatuses struct {
	stateLock sync.Mutex
	statuses  map[ComputeProviderId]ComputeProviderStatus
	err       error
	readCount int
	// closed to let a read answer; nil answers at once
	release chan struct{}
}

func (self *fakeComputeProviderStatuses) set(statuses map[ComputeProviderId]ComputeProviderStatus, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.statuses = statuses
	self.err = err
}

func (self *fakeComputeProviderStatuses) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

func (self *fakeComputeProviderStatuses) Statuses(ctx context.Context) (map[ComputeProviderId]ComputeProviderStatus, error) {
	var release chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.readCount += 1
		release = self.release
	}()
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	statuses := map[ComputeProviderId]ComputeProviderStatus{}
	for id, status := range self.statuses {
		statuses[id] = status
	}
	return statuses, nil
}

// A test adapter: the base, its credentials reader kept.
type testComputeProvider struct {
	ComputeProviderBase
	args *ComputeProviderArgs
}

// A registration of a test adapter for id.
func testComputeProviderRegistration(id ComputeProviderId) *computeProviderRegistration {
	return &computeProviderRegistration{
		id: id,
		construct: func(args *ComputeProviderArgs) (ComputeProvider, error) {
			return &testComputeProvider{ComputeProviderBase: ComputeProviderBase{ProviderId: id}, args: args}, nil
		},
	}
}

// Settings for env, of kind, with the providers named enabled there.
func testComputeProviderSettings(env string, kind ComputeDeploymentKind, ids ...ComputeProviderId) *ComputeProviderSettings {
	settings := DefaultComputeProviderSettings()
	settings.Environment = env
	settings.EnvironmentKinds = map[string]ComputeDeploymentKind{env: kind}
	settings.ProviderEnvironments = map[ComputeProviderId][]string{}
	for _, id := range ids {
		settings.ProviderEnvironments[id] = []string{env}
	}
	return settings
}

// A registry on a fake clock over statuses, with test adapters for engy, saygm and hippius and the real reference
// constructor.
func newTestComputeProviderRegistry(t testing.TB, settings *ComputeProviderSettings, statuses computeProviderStatusSource, clock sidecar.Clock) *ComputeProviderRegistry {
	t.Helper()
	registry, err := NewComputeProviderRegistry(&ComputeProviderRegistryArgs{
		Settings: settings,
		Clock:    clock,
		testRegistrations: []*computeProviderRegistration{
			testComputeProviderRegistration(ComputeProviderIdEngy),
			testComputeProviderRegistration(ComputeProviderIdSaygm),
			testComputeProviderRegistration(ComputeProviderIdHippius),
			{id: ComputeProviderIdReference, construct: constructReferenceProvider},
		},
		testStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// Of each status, enabled in the env or not, only gated and enabled serves new work; gated, suspended and out reach
// the work under way where enabled; listed, an absent row and a provider not enabled reach nothing; EnabledProviders
// lists exactly the serving ones, in code order.
func TestComputeProviderRegistryServesOnlyGatedEnabledAdapters(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	cases := []struct {
		status    ComputeProviderStatus
		enabled   bool
		serves    bool
		reachable bool
	}{
		{status: ComputeProviderStatusListed, enabled: true, serves: false, reachable: false},
		{status: ComputeProviderStatusGated, enabled: true, serves: true, reachable: true},
		{status: ComputeProviderStatusSuspended, enabled: true, serves: false, reachable: true},
		{status: ComputeProviderStatusOut, enabled: true, serves: false, reachable: true},
		{status: ComputeProviderStatusListed, enabled: false, serves: false, reachable: false},
		{status: ComputeProviderStatusGated, enabled: false, serves: false, reachable: false},
		{status: ComputeProviderStatusSuspended, enabled: false, serves: false, reachable: false},
		{status: ComputeProviderStatusOut, enabled: false, serves: false, reachable: false},
	}
	for _, c := range cases {
		enabled := []ComputeProviderId{ComputeProviderIdSaygm}
		if c.enabled {
			enabled = append(enabled, ComputeProviderIdEngy)
		}
		statuses := &fakeComputeProviderStatuses{}
		statuses.set(map[ComputeProviderId]ComputeProviderStatus{
			ComputeProviderIdEngy:  c.status,
			ComputeProviderIdSaygm: ComputeProviderStatusGated,
		}, nil)
		registry := newTestComputeProviderRegistry(t, testComputeProviderSettings("main", ComputeDeploymentProduction, enabled...), statuses, clock)
		adapter, err := registry.Enabled(ctx, ComputeProviderIdEngy)
		if c.serves != (err == nil) || (adapter != nil) != c.serves {
			t.Errorf("%s, enabled %v: Enabled answered %v, %v", c.status, c.enabled, adapter, err)
		}
		if err != nil && !errors.Is(err, ErrComputeProviderDisabled) {
			t.Errorf("%s, enabled %v: refused with %v", c.status, c.enabled, err)
		}
		if adapter, err := registry.Reachable(ctx, ComputeProviderIdEngy); c.reachable != (err == nil) || (adapter != nil) != c.reachable {
			t.Errorf("%s, enabled %v: Reachable answered %v, %v", c.status, c.enabled, adapter, err)
		}
		adapters, err := registry.EnabledProviders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		listed := []ComputeProviderId{}
		for _, adapter := range adapters {
			listed = append(listed, adapter.Id())
		}
		want := []ComputeProviderId{ComputeProviderIdSaygm}
		if c.serves {
			want = []ComputeProviderId{ComputeProviderIdEngy, ComputeProviderIdSaygm}
		}
		if fmt.Sprint(listed) != fmt.Sprint(want) {
			t.Errorf("%s, enabled %v: EnabledProviders lists %v, want %v", c.status, c.enabled, listed, want)
		}
	}

	// an absent row, a provider this build has no adapter for, and a slug no table names each serve nothing
	statuses := &fakeComputeProviderStatuses{}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdChutes: ComputeProviderStatusGated}, nil)
	registry := newTestComputeProviderRegistry(t, testComputeProviderSettings("main", ComputeDeploymentProduction,
		ComputeProviderIdEngy, ComputeProviderIdChutes), statuses, clock)
	for _, id := range []ComputeProviderId{ComputeProviderIdEngy, ComputeProviderIdChutes, "bittensor-sn64"} {
		if adapter, err := registry.Enabled(ctx, id); err == nil || adapter != nil || !errors.Is(err, ErrComputeProviderDisabled) {
			t.Errorf("%s: Enabled answered %v, %v", id, adapter, err)
		}
	}
}

// A read that fails refuses every provider, and keeps nothing: a status read within the age serves without reading,
// past it the registry reads again, and a failure then refuses rather than serve the old answer; the next good read
// serves again.
func TestComputeProviderRegistryRefusesWhenStatusesDoNotRead(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	statuses := &fakeComputeProviderStatuses{}
	settings := testComputeProviderSettings("main", ComputeDeploymentProduction, ComputeProviderIdEngy)
	registry := newTestComputeProviderRegistry(t, settings, statuses, clock)

	statuses.set(nil, errors.New("compute_provider does not exist in this database"))
	if adapter, err := registry.Enabled(ctx, ComputeProviderIdEngy); err == nil || adapter != nil {
		t.Fatalf("an unread row served: %v, %v", adapter, err)
	}
	if adapters, err := registry.EnabledProviders(ctx); err == nil || adapters != nil {
		t.Fatalf("an unread table listed %v, %v", adapters, err)
	}

	statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdEngy: ComputeProviderStatusGated}, nil)
	if _, err := registry.Enabled(ctx, ComputeProviderIdEngy); err != nil {
		t.Fatal(err)
	}
	reads := statuses.reads()
	clock.Advance(settings.StatusMaxAge - time.Second)
	statuses.set(nil, errors.New("the database is gone"))
	if _, err := registry.Enabled(ctx, ComputeProviderIdEngy); err != nil || statuses.reads() != reads {
		t.Fatalf("within the age: %v after %d reads, want the read of %d", err, statuses.reads(), reads)
	}
	clock.Advance(time.Second)
	if adapter, err := registry.Enabled(ctx, ComputeProviderIdEngy); err == nil || adapter != nil || statuses.reads() != reads+1 {
		t.Fatalf("past the age with the read failing: %v, %v after %d reads", adapter, err, statuses.reads())
	}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdEngy: ComputeProviderStatusSuspended}, nil)
	if _, err := registry.Enabled(ctx, ComputeProviderIdEngy); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("a suspension read after a failure: %v", err)
	}
}

// Askers that come while a read runs, or within the age after it, share it: one read for all of them.
func TestComputeProviderRegistryStatusReadIsShared(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	statuses := &fakeComputeProviderStatuses{release: make(chan struct{})}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdEngy: ComputeProviderStatusGated}, nil)
	registry := newTestComputeProviderRegistry(t, testComputeProviderSettings("main", ComputeDeploymentProduction, ComputeProviderIdEngy), statuses, clock)
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := registry.Enabled(ctx, ComputeProviderIdEngy)
			errs <- err
		}()
	}
	close(statuses.release)
	for range 8 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("an asker never answered")
		}
	}
	if reads := statuses.reads(); reads != 1 {
		t.Fatalf("8 askers read %d times", reads)
	}
}

// The reference provider never runs in production: settings that enable it in a production env do not validate, so
// neither a registry nor an engine starts on them; a production registry whose settings enable it elsewhere builds it
// not and serves it not, a gated row whatever; and its constructor refuses a production env whatever the settings.
func TestComputeProviderReferenceRefusedInProduction(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	statuses := &fakeComputeProviderStatuses{}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdReference: ComputeProviderStatusGated}, nil)

	inProduction := testComputeProviderSettings("main", ComputeDeploymentProduction, ComputeProviderIdReference)
	if err := inProduction.Validate(); err == nil || !strings.Contains(err.Error(), "D-ENC-2") {
		t.Fatalf("settings with the reference provider in production validated: %v", err)
	}
	if _, err := NewComputeProviderRegistry(&ComputeProviderRegistryArgs{Settings: inProduction, testStatuses: statuses}); err == nil {
		t.Fatal("a registry started with the reference provider in production")
	}
	// an env the kinds do not name is production
	unnamed := DefaultComputeProviderSettings()
	unnamed.Environment = "main"
	unnamed.ProviderEnvironments[ComputeProviderIdReference] = []string{"local", "main"}
	if err := unnamed.Validate(); err == nil {
		t.Fatal("the reference provider validated in an env the kinds do not name")
	}
	engineSettings := DefaultComputeEngineSettings()
	engineSettings.Providers = inProduction
	if err := engineSettings.Validate(); err == nil {
		t.Fatal("an engine's settings validated with the reference provider in production")
	}
	fixture := newComputeFixture(t, nil)
	if engine, err := NewComputeEngine(context.Background(), fixture.host, engineSettings, &ComputeEngineDeps{}); err == nil || engine != nil {
		t.Fatal("an engine started with the reference provider in production")
	}

	elsewhere := DefaultComputeProviderSettings()
	elsewhere.Environment = "main"
	registry := newTestComputeProviderRegistry(t, elsewhere, statuses, clock)
	if adapter, err := registry.Enabled(ctx, ComputeProviderIdReference); err == nil || adapter != nil {
		t.Fatalf("a production registry served the reference provider: %v, %v", adapter, err)
	}
	if _, built := registry.adapters[ComputeProviderIdReference]; built {
		t.Fatal("a production registry built the reference provider")
	}

	if adapter, err := constructReferenceProviderWith(&ComputeProviderArgs{Settings: elsewhere}, nil); err == nil || adapter != nil {
		t.Fatalf("the reference provider's constructor built in production: %v, %v", adapter, err)
	}
}

// In each of development, CI and staging, a registry whose settings enable the reference provider there builds it and
// serves it once its row reads gated.
func TestComputeProviderReferenceAllowedInDevelopmentCiAndStaging(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	for _, c := range []struct {
		env  string
		kind ComputeDeploymentKind
	}{
		{env: "local", kind: ComputeDeploymentDevelopment},
		{env: "ci-runner", kind: ComputeDeploymentCi},
		{env: "canary", kind: ComputeDeploymentStaging},
	} {
		statuses := &fakeComputeProviderStatuses{}
		statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdReference: ComputeProviderStatusListed}, nil)
		registry := newTestComputeProviderRegistry(t, testComputeProviderSettings(c.env, c.kind, ComputeProviderIdReference), statuses, clock)
		if adapter, err := registry.Enabled(ctx, ComputeProviderIdReference); err == nil || adapter != nil {
			t.Errorf("%s: a listed reference provider served: %v", c.env, adapter)
		}
		clock.Advance(registry.Settings().StatusMaxAge)
		statuses.set(map[ComputeProviderId]ComputeProviderStatus{ComputeProviderIdReference: ComputeProviderStatusGated}, nil)
		adapter, err := registry.Enabled(ctx, ComputeProviderIdReference)
		if err != nil || adapter.Id() != ComputeProviderIdReference {
			t.Errorf("%s (%s): the reference provider did not serve: %v", c.env, c.kind, err)
		}
	}
	// the defaults enable it in local, development, alone
	defaults := DefaultComputeProviderSettings()
	defaults.Environment = "local"
	if !defaults.Enabled(ComputeProviderIdReference) || defaults.Enabled(ComputeProviderIdEngy) {
		t.Fatal("the defaults do not enable the reference provider alone in local")
	}
	defaults.Environment = "canary"
	if defaults.Enabled(ComputeProviderIdReference) {
		t.Fatal("the defaults enable the reference provider beyond local")
	}
}

// Each adapter reads its own section of compute-providers.yml and no other's; with no file, no section, a file past
// the bound or one that is not a mapping, it reads an error that quotes nothing of the file.
func TestComputeProviderCredentialsAreTheProvidersOwnSection(t *testing.T) {
	ctx := context.Background()
	file := "engy:\n  api_key_hotkey_seed: engy-secret-canary\nsaygm:\n  api_key_hotkey_seed: saygm-secret-canary\n"
	secretFile := func(name string) ([]byte, error) {
		if name != ComputeProvidersSecretFileName {
			return nil, fmt.Errorf("no %s", name)
		}
		return []byte(file), nil
	}
	settings := testComputeProviderSettings("main", ComputeDeploymentProduction, ComputeProviderIdEngy, ComputeProviderIdSaygm, ComputeProviderIdHippius)
	statuses := &fakeComputeProviderStatuses{}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{
		ComputeProviderIdEngy: ComputeProviderStatusGated, ComputeProviderIdSaygm: ComputeProviderStatusGated, ComputeProviderIdHippius: ComputeProviderStatusGated,
	}, nil)
	registry, err := NewComputeProviderRegistry(&ComputeProviderRegistryArgs{
		Settings:   settings,
		SecretFile: secretFile,
		testRegistrations: []*computeProviderRegistration{
			testComputeProviderRegistration(ComputeProviderIdEngy),
			testComputeProviderRegistration(ComputeProviderIdSaygm),
			testComputeProviderRegistration(ComputeProviderIdHippius),
		},
		testStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := func(id ComputeProviderId) (string, error) {
		adapter, err := registry.Enabled(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		data, err := adapter.(*testComputeProvider).args.Credentials()
		return string(data), err
	}
	engy, err := credentials(ComputeProviderIdEngy)
	if err != nil || !strings.Contains(engy, "engy-secret-canary") || strings.Contains(engy, "saygm") {
		t.Fatalf("engy read %q, %v", engy, err)
	}
	if hippius, err := credentials(ComputeProviderIdHippius); err == nil || hippius != "" {
		t.Fatalf("a provider with no section read %q", hippius)
	}

	for label, read := range map[string]func(name string) ([]byte, error){
		"no file": func(name string) ([]byte, error) { return nil, errors.New("not mounted") },
		"past the bound": func(name string) ([]byte, error) {
			return []byte("engy: " + strings.Repeat("x", settings.CredentialsFileMaxByteCount)), nil
		},
		"not a mapping": func(name string) ([]byte, error) { return []byte("- engy-secret-canary\n"), nil },
	} {
		data, err := computeProviderCredentials(read, settings, ComputeProviderIdEngy)
		if err == nil || data != nil || strings.Contains(err.Error(), "canary") {
			t.Errorf("%s: read %q, %v", label, data, err)
		}
	}
	if data, err := computeProviderCredentials(nil, settings, ComputeProviderIdEngy); err == nil || data != nil {
		t.Errorf("no reader: read %q", data)
	}
}

// A constructor's failure refuses its own provider for the registry's life, and the others serve.
func TestComputeProviderConstructorFailureRefusesOnlyItsProvider(t *testing.T) {
	ctx := context.Background()
	statuses := &fakeComputeProviderStatuses{}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{
		ComputeProviderIdEngy: ComputeProviderStatusGated, ComputeProviderIdSaygm: ComputeProviderStatusGated,
	}, nil)
	registry, err := NewComputeProviderRegistry(&ComputeProviderRegistryArgs{
		Settings: testComputeProviderSettings("main", ComputeDeploymentProduction, ComputeProviderIdEngy, ComputeProviderIdSaygm),
		testRegistrations: []*computeProviderRegistration{
			{id: ComputeProviderIdEngy, construct: func(args *ComputeProviderArgs) (ComputeProvider, error) {
				return nil, errors.New("no hotkey for this env")
			}},
			{id: ComputeProviderIdSaygm, construct: func(args *ComputeProviderArgs) (ComputeProvider, error) {
				// an adapter that answers another provider's id builds nothing
				return &ComputeProviderBase{ProviderId: ComputeProviderIdEngy}, nil
			}},
		},
		testStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []ComputeProviderId{ComputeProviderIdEngy, ComputeProviderIdSaygm} {
		if adapter, err := registry.Enabled(ctx, id); err == nil || adapter != nil || !strings.Contains(err.Error(), "did not build") {
			t.Errorf("%s: %v, %v", id, adapter, err)
		}
	}
}

// registerComputeProvider refuses a slug no table names, web search's, a nil constructor and a second registration,
// and registers nothing for any of them.
func TestComputeProviderRegistrationRefusals(t *testing.T) {
	saved := computeProviderRegistrations
	t.Cleanup(func() { computeProviderRegistrations = saved })
	computeProviderRegistrations = []*computeProviderRegistration{}
	construct := func(args *ComputeProviderArgs) (ComputeProvider, error) { return nil, nil }
	registerComputeProvider(ComputeProviderIdEngy, construct)
	for label, register := range map[string]func(){
		"no table's slug": func() { registerComputeProvider("bittensor-sn64", construct) },
		"web search":      func() { registerComputeProvider(ComputeProviderIdParallel, construct) },
		"no constructor":  func() { registerComputeProvider(ComputeProviderIdSaygm, nil) },
		"twice":           func() { registerComputeProvider(ComputeProviderIdEngy, construct) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
	if len(computeProviderRegistrations) != 1 {
		t.Fatalf("%d registrations", len(computeProviderRegistrations))
	}
	// the build's own: the reference provider registers from its file
	if !func() bool {
		for _, registration := range saved {
			if registration.id == ComputeProviderIdReference {
				return true
			}
		}
		return false
	}() {
		t.Fatal("the reference provider is not registered")
	}
}

// Settings that do not validate: an unknown kind or slug, an adapter for web search, a payment of no method or for no
// provider, a bound that is not positive.
func TestComputeProviderSettingsRefuseWhatNoRegistryRuns(t *testing.T) {
	for label, change := range map[string]func(settings *ComputeProviderSettings){
		"an unknown kind": func(settings *ComputeProviderSettings) {
			settings.EnvironmentKinds["local"] = "preview"
		},
		"an unknown slug": func(settings *ComputeProviderSettings) {
			settings.ProviderEnvironments["targon"] = []string{"local"}
		},
		"web search's adapter": func(settings *ComputeProviderSettings) {
			settings.ProviderEnvironments[ComputeProviderIdParallel] = []string{"local"}
		},
		"a payment of no method": func(settings *ComputeProviderSettings) {
			settings.Payments[ComputeProviderIdEngy] = &ComputeProviderPayment{Method: 9}
		},
		"a payment for no provider": func(settings *ComputeProviderSettings) {
			settings.Payments["targon"] = &ComputeProviderPayment{Method: ComputeProviderPaymentGamma}
		},
		"no catalog timeout": func(settings *ComputeProviderSettings) {
			settings.CatalogReadTimeout = 0
		},
		"no history bound": func(settings *ComputeProviderSettings) {
			settings.HistoryMaxCount = 0
		},
	} {
		settings := DefaultComputeProviderSettings()
		change(settings)
		if err := settings.Validate(); err == nil {
			t.Errorf("%s validated", label)
		}
	}
	if err := DefaultComputeProviderSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	// a deployment's payment, a copy
	settings := DefaultComputeProviderSettings()
	settings.Payments[ComputeProviderIdEngy] = &ComputeProviderPayment{Method: ComputeProviderPaymentGamma, Netuid: 53, ServiceHotkey: "5ServiceHotkey", ApiKeyHotkey: "5ApiKeyHotkey"}
	payment := settings.Payment(ComputeProviderIdEngy)
	payment.Netuid = 1
	if settings.Payment(ComputeProviderIdEngy).Netuid != 53 || settings.Payment(ComputeProviderIdSaygm).Method != ComputeProviderPaymentNone {
		t.Fatal("payments do not read as set")
	}
}

// The engine builds its registry from its settings and its Env: a test engine, whose global Env grants no database,
// serves no provider, and says why.
func TestComputeEngineProvidersFailClosedWithoutTheirTable(t *testing.T) {
	settings := DefaultComputeEngineSettings()
	settings.Providers = testComputeProviderSettings("local", ComputeDeploymentDevelopment, ComputeProviderIdReference)
	fixture := newComputeFixture(t, &computeFixtureOptions{settings: settings})
	providers := fixture.engine.Providers()
	if providers == nil {
		t.Fatal("the engine has no registry")
	}
	if adapter, err := providers.Enabled(fixture.ctx, ComputeProviderIdReference); err == nil || adapter != nil || !strings.Contains(err.Error(), "does not read") {
		t.Fatalf("an engine with no database served %v, %v", adapter, err)
	}
}
