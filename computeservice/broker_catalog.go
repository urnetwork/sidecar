// The remote catalog at the broker (DESIGN-COMPUTE §6.3's sources and version rows, §4.5, §9.6, §14.3, §14.5; R-INFER-1,
// R-INFER-8, D-INFER-1, D-INFER-5; INFER-M12-01):
//
//	compute_provider_prices   hourly, on taskworker: each enabled provider's catalog read through its adapter and
//	                          stored (PROV's computeProviderReadPrices); then a full rebuild where the current version
//	                          is CatalogRebuildInterval old or none stands, else a prune that takes out at once a model
//	                          whose cost passed its price or whose provider stopped offering it (§4.5), published as a
//	                          new version where anything changed; and each direct provider's costliest worst case
//	                          recomputed and published (ComputeDirectExposure)
//	GET compute/v1/catalog    the current version, as stored, with the broker's clock
//	computeCatalogAt          what the authorize and infer routes take a request's version from: the current one, or
//	                          the one before it for CatalogPreviousGrace after a newer one is published, else
//	                          catalog_stale, so a modified client cannot keep an old price (§6.3)
//
// A build: each enabled, gated inference provider's models, named <provider>-<model>-<effort> by §6.3's normalization
// over the provider's whole id list (sidecar.InferNormalizeModelId); two ids that still give one name keep the one the
// broker's newest verified policy names (§5.4), else neither; a model labeled none is direct, AP or A1 TEE; the efforts,
// limits, tools, modalities and license as the adapter read them; the three prices per million tokens BAL's price
// function makes of the provider's gamma price at the read's gamma value (the 1.20 markup, rounded up to $0.001); a
// price that varies by request listed at the most it charges, as the adapter reads it (§6.3); "serving code measured:
// no" where §4.5 says so; and a direct model's host, receiver and target as its adapter would sign for them, which a
// device holds equal to its own policy's. The result holds to the device's own rules (sidecar.InferCatalogAnswerEntries):
// an entry that is not whole is left out, and a build in which two entries share a name publishes nothing. ENC's shapes
// and SRCH's search ids join as sections, each built by its area's own builder (computeCatalogRegisterSection).
//
// Each version is a compute_catalog_version row (MG-C2, INFER's part; compute-plan-catalog-versions, QD-1237): public
// prices and no user data, under compute-7, so every broker instance answers alike, and the version a request was
// admitted under prices its charge (§9.6). The catalog is unsigned and decides nothing about who reads a prompt (R1-14):
// the policy does, on the device and at the broker's authorize. The route writes no requester content into a log
// (IC-13): its line is its route, status and latency.
//
// The cache, the store and the job are safe for concurrent use; the build is a function.

package computeservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/bits"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// One gamma's units (§10.2): a price in nano-gamma at a gamma worth GammaNanoUsd is that price × GammaNanoUsd / 10^9
// nano-USD.
const computeNanoGammaPerGamma = 1_000_000_000

// The versions an engine holds: the current one and the one before it, which §6.3's rule takes for a day after a newer
// one. The rule's, not a tunable.
const computeCatalogVersionsHeld = 2

// The gauge the monitor's compute-direct-worst-case-rise reads (server/monitor's SIGNALS.md §32.2), by provider slug.
const computeDirectWorstCaseMetric = "urnetwork_compute_direct_worst_case_nano_usd"

// The efforts in §6.3's order, which a model's default is the nearest to medium of.
var computeCatalogEffortOrder = []sidecar.InferEffort{
	sidecar.InferEffortOff, sidecar.InferEffortMinimal, sidecar.InferEffortLow, sidecar.InferEffortMedium,
	sidecar.InferEffortHigh, sidecar.InferEffortXhigh, sidecar.InferEffortMax,
}

var (
	// Another broker or job published the version this one was about to.
	ErrComputeCatalogRace = errors.New("another publish took the catalog version")
	// A build the catalog's rules refuse: entries whose names collide, more models than the format takes, a version
	// past its bound.
	errComputeCatalogBuild = errors.New("catalog build refused")
)

// One published version of the catalog (§6.3).
type ComputeCatalogVersion struct {
	Version       uint64
	PublishedTime time.Time
	// The answer as published, its broker_time_ms zero: the route answers it with the broker's clock set.
	Answer *protocol.InferCatalogAnswer
	// Each direct provider's costliest worst case as of ExposureTime, which BAL's exposure rule reads (§9.7).
	Exposures    []*ComputeDirectExposure
	ExposureTime time.Time
}

// A direct provider's costliest worst case (§6.6, §9.7): over the provider's whole model list as its hourly read gave
// it, the largest context window times the input price plus maximum output times the output price, at the network's
// prices, so the exposure rule holds every open direct call of a network to it.
type ComputeDirectExposure struct {
	Provider ComputeProviderId `json:"provider"`
	// The provider's own id of the model that costs it, and the worst case in nano-USD.
	ModelId          string `json:"model_id"`
	WorstCaseNanoUsd int64  `json:"worst_case_nano_usd"`
}

// The newest direct exposures of version, by provider; nil for a provider it names none of.
func (self *ComputeCatalogVersion) Exposure(provider ComputeProviderId) *ComputeDirectExposure {
	for _, exposure := range self.Exposures {
		if exposure.Provider == provider {
			return exposure
		}
	}
	return nil
}

// Where versions are kept: compute_catalog_version, or a test's. Safe for concurrent use.
type computeCatalogVersionStore interface {
	// The newest count versions, newest first; none where none was published.
	Newest(ctx context.Context, count int) ([]*ComputeCatalogVersion, error)
	// Publishes version, whose number must be one past the newest: ErrComputeCatalogRace where another took it.
	Publish(ctx context.Context, version *ComputeCatalogVersion) error
	// Sets version's exposures as of at.
	SetExposure(ctx context.Context, version uint64, exposures []*ComputeDirectExposure, at time.Time) error
}

// compute_catalog_version over a database, which must link MG-C2: on one without its table every call fails, never
// answers. The job and the engine's cache read and write through it; server's private-stack test runs its SQL.
type ComputeCatalogStore struct {
	db       operator.Db
	settings *ComputeBrokerSettings
}

// A store over db, its bounds from settings (nil: DefaultComputeBrokerSettings).
func NewComputeCatalogStore(db operator.Db, settings *ComputeBrokerSettings) *ComputeCatalogStore {
	if settings == nil {
		settings = DefaultComputeBrokerSettings()
	}
	return &ComputeCatalogStore{db: db, settings: settings}
}

// See computeCatalogVersionStore.
func (self *ComputeCatalogStore) Newest(ctx context.Context, count int) ([]*ComputeCatalogVersion, error) {
	if self.db == nil {
		return nil, errors.New("compute catalog: no database")
	}
	versions := []*ComputeCatalogVersion{}
	err := self.db.Db(ctx, func(conn operator.DbConn) error {
		versions = versions[:0]
		rows, err := conn.Query(ctx, `
			SELECT version, published_time, answer, answer_sha256, exposure, exposure_time
			FROM compute_catalog_version
			ORDER BY version DESC
			LIMIT $1
		`, count)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var version int64
			var publishedTime, exposureTime time.Time
			var answerBytes, answerSha256, exposureJson []byte
			if err := rows.Scan(&version, &publishedTime, &answerBytes, &answerSha256, &exposureJson, &exposureTime); err != nil {
				return err
			}
			parsed, err := computeCatalogParseRow(uint64(version), publishedTime, answerBytes, answerSha256, exposureJson, exposureTime, self.settings)
			if err != nil {
				return err
			}
			versions = append(versions, parsed)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

// One stored row as a version: its answer whole, of its own number and hash, and its exposures.
func computeCatalogParseRow(version uint64, publishedTime time.Time, answerBytes []byte, answerSha256 []byte, exposureJson []byte, exposureTime time.Time, settings *ComputeBrokerSettings) (*ComputeCatalogVersion, error) {
	if settings.CatalogAnswerMaxByteCount < len(answerBytes) {
		return nil, fmt.Errorf("compute catalog: version %d is past %d bytes", version, settings.CatalogAnswerMaxByteCount)
	}
	sum := sha256.Sum256(answerBytes)
	if !slices.Equal(sum[:], answerSha256) {
		return nil, fmt.Errorf("compute catalog: version %d does not hash to its row", version)
	}
	answer := &protocol.InferCatalogAnswer{}
	if err := proto.Unmarshal(answerBytes, answer); err != nil || answer.GetVersion() != version {
		return nil, fmt.Errorf("compute catalog: version %d does not read as itself", version)
	}
	exposures := []*ComputeDirectExposure{}
	if err := json.Unmarshal(exposureJson, &exposures); err != nil {
		return nil, fmt.Errorf("compute catalog: version %d's exposures do not read", version)
	}
	return &ComputeCatalogVersion{
		Version:       version,
		PublishedTime: publishedTime.UTC(),
		Answer:        answer,
		Exposures:     exposures,
		ExposureTime:  exposureTime.UTC(),
	}, nil
}

// The answer's stored bytes, deterministic, its broker_time_ms zero.
func computeCatalogAnswerBytes(answer *protocol.InferCatalogAnswer) ([]byte, error) {
	stored := proto.Clone(answer).(*protocol.InferCatalogAnswer)
	stored.BrokerTimeMs = 0
	return proto.MarshalOptions{Deterministic: true}.Marshal(stored)
}

// See computeCatalogVersionStore: one insert, which the version's primary key holds to one publisher.
func (self *ComputeCatalogStore) Publish(ctx context.Context, version *ComputeCatalogVersion) error {
	if self.db == nil {
		return errors.New("compute catalog: no database")
	}
	answerBytes, err := computeCatalogAnswerBytes(version.Answer)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(answerBytes)
	exposureJson, err := json.Marshal(version.Exposures)
	if err != nil {
		return err
	}
	if math.MaxInt64 < version.Version {
		return fmt.Errorf("compute catalog: version %d past a bigint", version.Version)
	}
	return self.db.Tx(ctx, func(tx operator.DbTx) error {
		result, err := tx.Exec(ctx, `
			INSERT INTO compute_catalog_version (version, published_time, answer, answer_sha256, exposure, exposure_time)
			SELECT $1::bigint, $2::timestamp, $3::bytea, $4::bytea, $5::jsonb, $6::timestamp
			WHERE COALESCE((SELECT MAX(version) FROM compute_catalog_version), 0) = $1::bigint - 1
			ON CONFLICT (version) DO NOTHING
		`, int64(version.Version), version.PublishedTime.UTC(), answerBytes, sum[:], exposureJson, version.ExposureTime.UTC())
		if err != nil {
			return err
		}
		if result.RowsAffected != 1 {
			return ErrComputeCatalogRace
		}
		return nil
	})
}

// See computeCatalogVersionStore.
func (self *ComputeCatalogStore) SetExposure(ctx context.Context, version uint64, exposures []*ComputeDirectExposure, at time.Time) error {
	if self.db == nil {
		return errors.New("compute catalog: no database")
	}
	exposureJson, err := json.Marshal(exposures)
	if err != nil {
		return err
	}
	return self.db.Tx(ctx, func(tx operator.DbTx) error {
		_, err := tx.Exec(ctx, `
			UPDATE compute_catalog_version SET exposure = $2::jsonb, exposure_time = $3::timestamp
			WHERE version = $1::bigint AND exposure_time <= $3::timestamp
		`, int64(version), exposureJson, at.UTC())
		return err
	})
}

// What a section builder reads: the hour's catalogs and the price rule.
type ComputeCatalogSectionArgs struct {
	// Each enabled provider's catalog as the hour's read checked it, nil for one whose read failed.
	Catalogs []*ComputeProviderCatalog
	// The ledger's price rule (§9.6).
	Ledger *model.ComputeLedgerSettings
	Now    time.Time
}

// Builds one area's section of a version, its own message's bytes, from that area's file: ENC's shapes, SRCH's search
// ids. An error leaves the section out of the version, the models published regardless.
type ComputeCatalogSectionBuilder func(ctx context.Context, args *ComputeCatalogSectionArgs) ([]byte, error)

// One section's registration.
type computeCatalogSection struct {
	name  string
	build ComputeCatalogSectionBuilder
}

// The registered sections, in name order once built. Written only during the package's init.
var computeCatalogSections = []*computeCatalogSection{}

// Registers the catalog section name, from an init function in its area's own file. An empty name, a nil builder or a
// name registered twice is a build error, which panics.
func computeCatalogRegisterSection(name string, build ComputeCatalogSectionBuilder) {
	registered := slices.ContainsFunc(computeCatalogSections, func(section *computeCatalogSection) bool {
		return section.name == name
	})
	if name == "" || build == nil || registered {
		panic(fmt.Errorf("compute catalog section %q registered twice or without a builder", name))
	}
	computeCatalogSections = append(computeCatalogSections, &computeCatalogSection{name: name, build: build})
}

// What a build reads.
type computeCatalogBuildArgs struct {
	// The hour's reads, the failed ones among them.
	Reads []*computeProviderCatalogRead
	// The broker's newest verified compute policy, which names one of two colliding ids; nil names none.
	Policy *sidecar.ComputePolicy
	// A direct model's target as its adapter would sign for it, nil where it has none; nil for no adapter.
	DirectTarget func(provider ComputeProviderId, model string) *ComputeDirectTarget
	// The sections, nil for the registered ones.
	Sections      []*computeCatalogSection
	Settings      *ComputeBrokerSettings
	InferSettings *sidecar.InferSettings
	Log           sidecar.Logger
	Now           time.Time
}

// A price in nano-gamma per unit at a gamma worth gammaNanoUsd, in nano-USD, rounded up: what URnetwork pays for the
// unit at the read.
func computeNanoGammaToNanoUsd(nanoGamma int64, gammaNanoUsd int64) (int64, error) {
	if nanoGamma < 0 || gammaNanoUsd < 0 {
		return 0, fmt.Errorf("%w: a negative price or gamma", model.ErrComputePrice)
	}
	hi, lo := bits.Mul64(uint64(nanoGamma), uint64(gammaNanoUsd))
	if computeNanoGammaPerGamma <= hi {
		return 0, fmt.Errorf("%w: past int64", model.ErrComputePrice)
	}
	quotient, remainder := bits.Div64(hi, lo, computeNanoGammaPerGamma)
	if remainder != 0 {
		quotient += 1
	}
	if math.MaxInt64 < quotient {
		return 0, fmt.Errorf("%w: past int64", model.ErrComputePrice)
	}
	return int64(quotient), nil
}

// A model's three network prices per million tokens (§9.6): the provider's price at the read's gamma value, times the
// markup, rounded up to the token step.
func computeCatalogRetailPrices(providerModel *ComputeProviderModel, gammaNanoUsd int64, ledger *model.ComputeLedgerSettings) (input int64, output int64, cached int64, err error) {
	retail := func(nanoGamma int64) (int64, error) {
		cost, err := computeNanoGammaToNanoUsd(nanoGamma, gammaNanoUsd)
		if err != nil {
			return 0, err
		}
		return model.ComputeRetailPrice(ledger, model.ComputePriceClassTokens, cost)
	}
	if input, err = retail(providerModel.InputNanoGammaPerMillion); err != nil {
		return
	}
	if output, err = retail(providerModel.OutputNanoGammaPerMillion); err != nil {
		return
	}
	cached, err = retail(providerModel.CachedInputNanoGammaPerMillion)
	return
}

// A model's three costs per million tokens at the read, in nano-USD, before the markup.
func computeCatalogCosts(providerModel *ComputeProviderModel, gammaNanoUsd int64) (input int64, output int64, cached int64, err error) {
	if input, err = computeNanoGammaToNanoUsd(providerModel.InputNanoGammaPerMillion, gammaNanoUsd); err != nil {
		return
	}
	if output, err = computeNanoGammaToNanoUsd(providerModel.OutputNanoGammaPerMillion, gammaNanoUsd); err != nil {
		return
	}
	cached, err = computeNanoGammaToNanoUsd(providerModel.CachedInputNanoGammaPerMillion, gammaNanoUsd)
	return
}

// The effort an alias asking none runs at: medium where the model takes it, else the nearest to it it takes, the lower
// of two as near (Q-INFER-5's model default, which no adapter names).
func computeCatalogDefaultEffort(efforts []sidecar.InferEffort) sidecar.InferEffort {
	medium := slices.Index(computeCatalogEffortOrder, sidecar.InferEffortMedium)
	best := sidecar.InferEffort("")
	bestDistance := len(computeCatalogEffortOrder)
	for _, effort := range efforts {
		index := slices.Index(computeCatalogEffortOrder, effort)
		if index < 0 {
			continue
		}
		distance := index - medium
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance || (distance == bestDistance && index < slices.Index(computeCatalogEffortOrder, best)) {
			best = effort
			bestDistance = distance
		}
	}
	return best
}

// The ids of one provider's models the build names, by the model part each makes: §6.3's normalization over the
// provider's whole list, and of two ids that make one part, the one the policy names, else neither.
func computeCatalogModelParts(provider ComputeProviderId, catalog *ComputeProviderCatalog, policy *sidecar.ComputePolicy, settings *sidecar.InferSettings) (map[string]*ComputeProviderModel, []string, error) {
	ids := make([]*sidecar.InferProviderModel, 0, len(catalog.Models))
	for _, providerModel := range catalog.Models {
		ids = append(ids, &sidecar.InferProviderModel{Id: providerModel.ModelId, Label: providerModel.Label})
	}
	normalized, err := sidecar.InferNormalizeModelId(string(provider), ids, settings)
	if err != nil {
		return nil, nil, err
	}
	// the id the policy names for a model part, empty for none
	policyId := func(part string) string {
		if policy == nil {
			return ""
		}
		if teeProvider := policy.Provider(string(provider)); teeProvider != nil {
			return teeProvider.ProviderModelId(part)
		}
		if direct := policy.DirectProvider(string(provider)); direct != nil {
			if directModel := direct.Model(part); directModel != nil {
				return directModel.ProviderModelId
			}
		}
		return ""
	}
	parts := map[string]*ComputeProviderModel{}
	faults := []string{}
	for i, result := range normalized {
		providerModel := catalog.Models[i]
		switch {
		case result.Refused != "":
			faults = append(faults, fmt.Sprintf("%s's id %q: %s", provider, providerModel.ModelId, result.Refused))
		case result.Collides && policyId(result.Model) != providerModel.ModelId:
			faults = append(faults, fmt.Sprintf("%s's id %q collides as %s, and the policy names another", provider, providerModel.ModelId, result.Model))
		default:
			parts[result.Model] = providerModel
		}
	}
	return parts, faults, nil
}

// The models one provider's read gives the catalog, each as the build writes it.
func computeCatalogProviderModels(read *computeProviderCatalogRead, args *computeCatalogBuildArgs) ([]*protocol.InferCatalogModel, []string) {
	catalog := read.Catalog
	parts, faults, err := computeCatalogModelParts(read.Provider, catalog, args.Policy, args.InferSettings)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s's ids do not normalize: %s", read.Provider, err)}
	}
	ledger := args.Settings.ledger()
	models := []*protocol.InferCatalogModel{}
	for _, part := range slices.Sorted(maps.Keys(parts)) {
		providerModel := parts[part]
		input, output, cached, err := computeCatalogRetailPrices(providerModel, catalog.GammaNanoUsd, ledger)
		if err != nil {
			faults = append(faults, fmt.Sprintf("%s's %s does not price: %s", read.Provider, part, err))
			continue
		}
		kind := protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_TEE
		if providerModel.Label == sidecar.ComputeLabelNone {
			kind = protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT
		}
		efforts := make([]string, len(providerModel.Efforts))
		for i, effort := range providerModel.Efforts {
			efforts[i] = string(effort)
		}
		modalities := make([]string, len(providerModel.Modalities))
		for i, modality := range providerModel.Modalities {
			modalities[i] = string(modality)
		}
		entry := &protocol.InferCatalogModel{
			Provider:                     string(read.Provider),
			Model:                        part,
			Kind:                         kind,
			Label:                        string(providerModel.Label),
			Efforts:                      efforts,
			DefaultEffort:                string(computeCatalogDefaultEffort(providerModel.Efforts)),
			ContextWindow:                providerModel.ContextWindow,
			MaxOutput:                    providerModel.MaxOutput,
			Tools:                        providerModel.Tools,
			StructuredOutput:             providerModel.StructuredOutput,
			Modalities:                   modalities,
			License:                      providerModel.License,
			ProviderModelId:              providerModel.ModelId,
			InputNanoUsdPerMillion:       input,
			OutputNanoUsdPerMillion:      output,
			CachedInputNanoUsdPerMillion: cached,
			PriceVaries:                  providerModel.PriceVaries,
			ServingCodeUnmeasured:        providerModel.Label.Tee() && providerModel.ServingCodeUnmeasured,
		}
		if kind == protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT && args.DirectTarget != nil {
			if target := args.DirectTarget(read.Provider, part); target != nil {
				entry.Host = target.Host
				entry.ReceiverHotkey = target.ReceiverHotkey
				entry.Targets = []*protocol.InferCatalogTarget{{Method: target.Method, Path: target.Path}}
			}
		}
		models = append(models, entry)
	}
	return models, faults
}

// A full build (§6.3): every enabled provider's models, held to the device's rules, and the sections. Answers the
// answer, its version unset, and the faults of what it left out.
func computeCatalogBuild(ctx context.Context, args *computeCatalogBuildArgs) (*protocol.InferCatalogAnswer, []string, error) {
	answer := &protocol.InferCatalogAnswer{
		PublishedMs: args.Now.UnixMilli(),
		Models:      []*protocol.InferCatalogModel{},
		Sections:    []*protocol.InferCatalogSection{},
	}
	faults := []string{}
	catalogs := []*ComputeProviderCatalog{}
	for _, read := range args.Reads {
		if read == nil || read.Catalog == nil {
			continue
		}
		catalogs = append(catalogs, read.Catalog)
		if kind, _ := ComputeProviderKindOf(read.Provider); kind != ComputeProviderKindInference {
			continue
		}
		models, modelFaults := computeCatalogProviderModels(read, args)
		answer.Models = append(answer.Models, models...)
		faults = append(faults, modelFaults...)
	}
	sections := args.Sections
	if sections == nil {
		sections = computeCatalogSections
	}
	sorted := slices.Clone(sections)
	sort.Slice(sorted, func(i int, j int) bool { return sorted[i].name < sorted[j].name })
	for _, section := range sorted {
		body, err := section.build(ctx, &ComputeCatalogSectionArgs{Catalogs: catalogs, Ledger: args.Settings.ledger(), Now: args.Now})
		if err != nil {
			faults = append(faults, fmt.Sprintf("the %s section did not build: %s", section.name, err))
			continue
		}
		answer.Sections = append(answer.Sections, &protocol.InferCatalogSection{Name: section.name, Body: body})
	}
	kept, keptFaults, err := computeCatalogHold(answer, args.Settings, args.InferSettings)
	return kept, append(faults, keptFaults...), err
}

// answer held to the device's rules: each entry the device would leave out taken out, and refused whole where two
// share a name, it lists more models than CatalogModelMaxCount, or its bytes pass CatalogAnswerMaxByteCount.
func computeCatalogHold(answer *protocol.InferCatalogAnswer, settings *ComputeBrokerSettings, inferSettings *sidecar.InferSettings) (*protocol.InferCatalogAnswer, []string, error) {
	if settings.CatalogModelMaxCount < len(answer.Models) {
		return nil, nil, fmt.Errorf("%w: %d models, past %d", errComputeCatalogBuild, len(answer.Models), settings.CatalogModelMaxCount)
	}
	entries, faults, err := sidecar.InferCatalogAnswerEntries(answer, inferSettings)
	if err != nil {
		return nil, faults, fmt.Errorf("%w: %w", errComputeCatalogBuild, err)
	}
	kept := proto.Clone(answer).(*protocol.InferCatalogAnswer)
	kept.Models = make([]*protocol.InferCatalogModel, 0, len(entries))
	for _, entry := range entries {
		kept.Models = append(kept.Models, entry.Model)
	}
	answerBytes, err := computeCatalogAnswerBytes(kept)
	if err != nil {
		return nil, faults, err
	}
	if settings.CatalogAnswerMaxByteCount < len(answerBytes) {
		return nil, faults, fmt.Errorf("%w: %d bytes, past %d", errComputeCatalogBuild, len(answerBytes), settings.CatalogAnswerMaxByteCount)
	}
	return kept, faults, nil
}

// The current version pruned by the hour's reads (§4.5): a model whose provider's read succeeded and no longer offers
// it, whose provider is no longer enabled and gated, or whose cost at the read passed any of its three prices, taken out
// at once; a provider whose read failed keeps its models, its last read standing. Whether anything was taken out.
func computeCatalogPrune(current *protocol.InferCatalogAnswer, reads []*computeProviderCatalogRead, args *computeCatalogBuildArgs) (*protocol.InferCatalogAnswer, []string, bool) {
	readsByProvider := map[ComputeProviderId]*computeProviderCatalogRead{}
	for _, read := range reads {
		if read != nil {
			readsByProvider[read.Provider] = read
		}
	}
	pruned := proto.Clone(current).(*protocol.InferCatalogAnswer)
	pruned.Models = []*protocol.InferCatalogModel{}
	reasons := []string{}
	for _, catalogModel := range current.GetModels() {
		provider := ComputeProviderId(catalogModel.GetProvider())
		read, enabled := readsByProvider[provider]
		if !enabled {
			reasons = append(reasons, fmt.Sprintf("%s-%s: its provider is no longer enabled and gated", provider, catalogModel.GetModel()))
			continue
		}
		if read.Catalog == nil {
			pruned.Models = append(pruned.Models, catalogModel)
			continue
		}
		index := slices.IndexFunc(read.Catalog.Models, func(providerModel *ComputeProviderModel) bool {
			return providerModel.ModelId == catalogModel.GetProviderModelId()
		})
		if index < 0 {
			reasons = append(reasons, fmt.Sprintf("%s-%s: its provider no longer offers it", provider, catalogModel.GetModel()))
			continue
		}
		input, output, cached, err := computeCatalogCosts(read.Catalog.Models[index], read.Catalog.GammaNanoUsd)
		if err != nil || catalogModel.GetInputNanoUsdPerMillion() < input || catalogModel.GetOutputNanoUsdPerMillion() < output ||
			catalogModel.GetCachedInputNanoUsdPerMillion() < cached {
			reasons = append(reasons, fmt.Sprintf("%s-%s: its cost passed its price", provider, catalogModel.GetModel()))
			continue
		}
		pruned.Models = append(pruned.Models, catalogModel)
	}
	return pruned, reasons, 0 < len(reasons)
}

// Each direct provider's costliest worst case over its whole list as the hour's reads gave it (§6.6, §9.7), at the
// network's prices, by provider slug order; a provider whose read failed has none.
func computeDirectExposures(reads []*computeProviderCatalogRead, ledger *model.ComputeLedgerSettings) []*ComputeDirectExposure {
	exposures := []*ComputeDirectExposure{}
	for _, read := range reads {
		if read == nil || read.Catalog == nil {
			continue
		}
		var costliest *ComputeDirectExposure
		for _, providerModel := range read.Catalog.Models {
			if providerModel.Label != sidecar.ComputeLabelNone {
				continue
			}
			input, output, _, err := computeCatalogRetailPrices(providerModel, read.Catalog.GammaNanoUsd, ledger)
			if err != nil {
				continue
			}
			worstCase, err := model.ComputeWorstCase(providerModel.ContextWindow, providerModel.MaxOutput, input, output)
			if err != nil {
				// a worst case past int64 is the most any exposure can be
				worstCase = math.MaxInt64
			}
			if costliest == nil || costliest.WorstCaseNanoUsd < worstCase {
				costliest = &ComputeDirectExposure{Provider: read.Provider, ModelId: providerModel.ModelId, WorstCaseNanoUsd: worstCase}
			}
		}
		if costliest != nil {
			exposures = append(exposures, costliest)
		}
	}
	sort.Slice(exposures, func(i int, j int) bool { return exposures[i].Provider < exposures[j].Provider })
	return exposures
}

// The newest versions an engine read, kept CatalogCacheMaxAge. Safe for concurrent use: readLock makes one read of the
// store at a time across its I/O, and stateLock guards what it kept.
type computeCatalogCache struct {
	engine *ComputeEngine

	readLock sync.Mutex

	stateLock sync.Mutex
	// the newest two, newest first
	versions []*ComputeCatalogVersion
	readTime time.Time
	read     bool
}

// The engine's cache.
func newComputeCatalogCache(engine *ComputeEngine) *computeCatalogCache {
	return &computeCatalogCache{engine: engine}
}

// The store versions are read from: the deps' test store, else compute_catalog_version over the engine's Env.
func (self *computeCatalogCache) store() (computeCatalogVersionStore, error) {
	if self.engine.deps.testCatalogStore != nil {
		return self.engine.deps.testCatalogStore, nil
	}
	db, err := self.engine.Env().Db()
	if err != nil {
		return nil, err
	}
	return NewComputeCatalogStore(db, self.engine.brokerSettings()), nil
}

// The newest two versions, read again past CatalogCacheMaxAge, or where the newest held is older than atLeast.
func (self *computeCatalogCache) newest(ctx context.Context, atLeast uint64) ([]*ComputeCatalogVersion, error) {
	fresh := func() ([]*ComputeCatalogVersion, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		maxAge := self.engine.brokerSettings().CatalogCacheMaxAge
		if !self.read || maxAge <= 0 || maxAge <= self.engine.clock.Now().Sub(self.readTime) {
			return nil, false
		}
		if 0 < len(self.versions) && self.versions[0].Version < atLeast {
			return nil, false
		}
		return self.versions, true
	}
	if versions, ok := fresh(); ok {
		return versions, nil
	}
	self.readLock.Lock()
	defer self.readLock.Unlock()
	if versions, ok := fresh(); ok {
		return versions, nil
	}
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	readTime := self.engine.clock.Now()
	versions, err := store.Newest(ctx, computeCatalogVersionsHeld)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.versions = versions
	self.readTime = readTime
	self.read = true
	return versions, nil
}

// The broker's settings, the defaults where the engine's name none.
func (self *ComputeEngine) brokerSettings() *ComputeBrokerSettings {
	if self.settings.Broker == nil {
		return DefaultComputeBrokerSettings()
	}
	return self.settings.Broker
}

// The version a request names, for the authorize and infer routes (§6.3, §9.6): the current one, or the one before it
// until CatalogPreviousGrace after the current was published; catalog_stale for any other; unavailable where none
// can be read or none was published.
func (self *ComputeEngine) computeCatalogAt(ctx context.Context, version uint64) (*ComputeCatalogVersion, *ComputeRefusal) {
	versions, err := self.catalog.newest(ctx, version)
	if err != nil {
		return nil, NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if len(versions) == 0 {
		return nil, NewComputeRefusal(ComputeRefusalUnavailable)
	}
	current := versions[0]
	if version == current.Version {
		return current, nil
	}
	grace := self.brokerSettings().CatalogPreviousGrace
	if 1 < len(versions) && version == versions[1].Version && 0 < grace &&
		self.clock.Now().Before(current.PublishedTime.Add(grace)) {
		return versions[1], nil
	}
	return nil, NewComputeRefusal(ComputeRefusalCatalogStale)
}

// GET /v1/catalog: the current version with the broker's clock; unavailable before the first is published.
func serveComputeCatalog(request *ComputeRequest) {
	versions, err := request.Engine().catalog.newest(request.Ctx, 0)
	if err != nil || len(versions) == 0 {
		request.Unavailable()
		return
	}
	answer := proto.Clone(versions[0].Answer).(*protocol.InferCatalogAnswer)
	answer.BrokerTimeMs = request.Now().UnixMilli()
	request.Reply(answer)
}

// Registers the catalog route.
func init() {
	registerComputeRoutes(map[string]ComputeHandler{
		ComputeRouteCatalog: serveComputeCatalog,
	})
}

// What compute_provider_prices' job is built over: what server's taskworker gives it.
type ComputeProviderPricesJobArgs struct {
	// The providers this deployment enables, with their gating (provider_registry.go).
	Registry *ComputeProviderRegistry
	// compute_provider, compute_provider_price and compute_catalog_version's database, which links MG-C2.
	Db operator.Db
	// The newest verified compute policy taskworker holds (§5.4). nil names no collision's winner.
	Policy func() *sidecar.ComputePolicy
	// nil: DefaultComputeBrokerSettings.
	Settings *ComputeBrokerSettings
	// The name grammar's bounds, which the device reads at the same defaults. nil: sidecar.DefaultInferSettings.
	InferSettings *sidecar.InferSettings
	// The direct worst case's gauge. nil publishes none.
	Metrics sidecar.Metrics
	// nil: the wall clock.
	Clock sidecar.Clock
	// nil discards.
	Log sidecar.Logger

	// A test's reads and store, in place of the registry's and the database's.
	testReadPrices func(ctx context.Context, now time.Time) ([]*computeProviderCatalogRead, error)
	testStore      computeCatalogVersionStore
	testSections   []*computeCatalogSection
}

// compute_provider_prices' run. See the file header. Safe for concurrent use, though its schedule runs one at a time.
type ComputeProviderPricesJob struct {
	args          *ComputeProviderPricesJobArgs
	settings      *ComputeBrokerSettings
	inferSettings *sidecar.InferSettings
	clock         sidecar.Clock
	log           sidecar.Logger
	worstCase     sidecar.MetricsGauge
	readPrices    func(ctx context.Context, now time.Time) ([]*computeProviderCatalogRead, error)
	store         computeCatalogVersionStore
}

// A job over args: settings that do not validate refuse it.
func NewComputeProviderPricesJob(args *ComputeProviderPricesJobArgs) (*ComputeProviderPricesJob, error) {
	if args == nil {
		return nil, errors.New("compute_provider_prices: no args")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultComputeBrokerSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	inferSettings := args.InferSettings
	if inferSettings == nil {
		inferSettings = sidecar.DefaultInferSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	self := &ComputeProviderPricesJob{
		args:          args,
		settings:      settings,
		inferSettings: inferSettings,
		clock:         clock,
		log:           log,
		readPrices:    args.testReadPrices,
		store:         args.testStore,
	}
	if args.Metrics != nil {
		self.worstCase = args.Metrics.Gauge(computeDirectWorstCaseMetric, "a direct compute provider's costliest worst case, in nano-USD", "provider")
	}
	if self.readPrices == nil {
		if args.Registry == nil || args.Db == nil {
			return nil, errors.New("compute_provider_prices: a registry and a database")
		}
		providerStore := NewComputeProviderStore(args.Db, args.Registry.Settings())
		self.readPrices = func(ctx context.Context, now time.Time) ([]*computeProviderCatalogRead, error) {
			return computeProviderReadPrices(ctx, args.Registry, providerStore, now)
		}
	}
	if self.store == nil {
		if args.Db == nil {
			return nil, errors.New("compute_provider_prices: a database")
		}
		self.store = NewComputeCatalogStore(args.Db, settings)
	}
	return self, nil
}

// One hourly run: the reads stored, the catalog rebuilt or pruned and published where it changed, and the direct
// exposures recomputed, published and gauged. A run that cannot store the hour's reads publishes nothing, since a charge
// prices from the read a version was admitted under.
func (self *ComputeProviderPricesJob) Run(ctx context.Context) error {
	now := self.clock.Now()
	reads, err := self.readPrices(ctx, now)
	if err != nil {
		return err
	}
	for _, read := range reads {
		if read.Err != nil {
			// its last read stands, and its models stay where the current version holds them
			self.log.Warningf("[compute] compute_provider_prices: %s's catalog did not read: %s", read.Provider, read.Err)
		}
	}
	newest, err := self.store.Newest(ctx, 1)
	if err != nil {
		return err
	}
	var current *ComputeCatalogVersion
	if 0 < len(newest) {
		current = newest[0]
	}
	exposures := computeDirectExposures(reads, self.settings.ledger())
	buildArgs := &computeCatalogBuildArgs{
		Reads:         reads,
		Settings:      self.settings,
		InferSettings: self.inferSettings,
		Sections:      self.args.testSections,
		Log:           self.log,
		Now:           now,
	}
	if self.args.Policy != nil {
		buildArgs.Policy = self.args.Policy()
	}
	if self.args.Registry != nil {
		registry := self.args.Registry
		buildArgs.DirectTarget = func(provider ComputeProviderId, model string) *ComputeDirectTarget {
			adapter, err := registry.Enabled(ctx, provider)
			if err != nil {
				return nil
			}
			target, err := adapter.DirectTarget(model)
			if err != nil {
				return nil
			}
			return target
		}
	}
	var answer *protocol.InferCatalogAnswer
	switch {
	case current == nil || self.settings.CatalogRebuildInterval <= 0 || self.settings.CatalogRebuildInterval <= now.Sub(current.PublishedTime):
		built, faults, err := computeCatalogBuild(ctx, buildArgs)
		for _, fault := range faults {
			self.log.Warningf("[compute] compute_provider_prices left out %s", fault)
		}
		if err != nil {
			self.log.Errorf("[compute] compute_provider_prices: the catalog did not build, so the version that stands keeps standing: %s", err)
		} else {
			answer = built
		}
	default:
		pruned, reasons, changed := computeCatalogPrune(current.Answer, reads, buildArgs)
		for _, reason := range reasons {
			self.log.Infof("[compute] compute_provider_prices took out %s", reason)
		}
		if changed {
			answer = pruned
		}
	}
	if answer != nil {
		version := uint64(1)
		if current != nil {
			version = current.Version + 1
		}
		answer.Version = version
		answer.PublishedMs = now.UnixMilli()
		answer.BrokerTimeMs = 0
		versionKey := strconv.FormatUint(version, 10)
		testHookBarrier(BarrierComputeCatalogPublishBefore, versionKey)
		err := self.store.Publish(ctx, &ComputeCatalogVersion{
			Version:       version,
			PublishedTime: now,
			Answer:        answer,
			Exposures:     exposures,
			ExposureTime:  now,
		})
		testHookBarrier(BarrierComputeCatalogPublishAfter, versionKey)
		if err != nil {
			return fmt.Errorf("compute_provider_prices: version %d was not published: %w", version, err)
		}
	} else if current != nil {
		if err := self.store.SetExposure(ctx, current.Version, exposures, now); err != nil {
			return fmt.Errorf("compute_provider_prices: the exposures were not published: %w", err)
		}
	}
	self.publishExposures(current, exposures)
	return nil
}

// Gauges each direct provider's costliest worst case, which the monitor pages a rise of, and logs one above what the
// version that stood held for it (§6.6).
func (self *ComputeProviderPricesJob) publishExposures(previous *ComputeCatalogVersion, exposures []*ComputeDirectExposure) {
	for _, exposure := range exposures {
		if self.worstCase != nil {
			self.worstCase.Set(float64(exposure.WorstCaseNanoUsd), string(exposure.Provider))
		}
		if previous == nil {
			continue
		}
		if before := previous.Exposure(exposure.Provider); before != nil && before.WorstCaseNanoUsd < exposure.WorstCaseNanoUsd {
			self.log.Errorf("[compute] direct provider %s's costliest worst case rose from %d to %d nano-USD, narrowing every network's room under the exposure rule",
				exposure.Provider, before.WorstCaseNanoUsd, exposure.WorstCaseNanoUsd)
		}
	}
}
