//go:build !ios_extension && !sidecar_http

// Fetching the compute policy and its freshness tickets (DESIGN-COMPUTE §5.4's Distribution, IC-9): each `ur` release
// carries the policy current at its build, and a device fetches newer ones, and the newest released ticket, from any
// ComputePolicySource: ur.io's serving path and its mirrors, which this file builds, or another device of the network.
// The signature, never the host, is what a device trusts, so the path through Cloudflare changes nothing, and a server
// that withholds a newer policy or ticket can only stop remote work, never widen the policy.
//
// The paths, by compute-plan-ticket-distribution's answer (QD-1379), under a base that is a setting, by default
// https://ur.io/compute/policy/v1 (the answer's <version> read as the serving path's own version, v1, beside the
// policy files, so one day's file names the newest batch's ticket whatever policy it requires):
//
//	<base>/<version>.json      the policy of that version
//	<base>/<version>.json.sig  its detached SSHSIG
//	<base>/tickets/<day>.bin   the ticket the ticket host released for that UTC day, a ComputePolicyTicketFile
//
// One Fetch takes the newest released ticket (today's, else the days before it a ticket's window still covers), then
// the policy the newest ticket names where it is newer than the one held, else the next version where one exists, up
// to FetchMaxPolicySteps versions. A newer policy or ticket is taken through the store and the gate, which verify and
// persist it. The device relay §5.4 allows, a device passing its newest current ticket to the network's others over
// EVS in the vault (QD-1379), is another ComputePolicySource, unregistered until a vault reader lands in the root.
//
// Safe for concurrent use: a fetcher holds no state of its own.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// What a source answers for a file it does not hold.
var ErrComputePolicySourceAbsent = errors.New("the source holds no such file")

// Where policies and tickets come from. A source is untrusted: everything it answers is verified.
type ComputePolicySource interface {
	// The policy of version and its detached signature; ErrComputePolicySourceAbsent where it holds none.
	Policy(ctx context.Context, version uint64) (document []byte, signature []byte, err error)
	// The ticket file it holds for the UTC day starting at day; ErrComputePolicySourceAbsent where it holds none.
	Ticket(ctx context.Context, day time.Time) ([]byte, error)
}

// The ticket path's day: the UTC date.
const computePolicyTicketDayLayout = "2006-01-02"

// A UTC day, the unit tickets are dated in: the format's, not a limit.
const computePolicyDay = 24 * time.Hour

// ur.io's serving path, or a mirror of it, over HTTPS.
type computePolicyHttpSource struct {
	base     *url.URL
	client   *http.Client
	settings *AttestSettings
}

// A source at base, an https URL with no query or fragment, through client; nil client is one of the source's own,
// with no proxy and no redirect followed, since a source that redirects is not answering.
func NewComputePolicyHttpSource(base string, client *http.Client, settings *AttestSettings) (ComputePolicySource, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, errors.New("compute policy source: not an https base url")
	}
	if settings == nil {
		return nil, errors.New("compute policy source: no settings")
	}
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true},
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return &computePolicyHttpSource{base: parsed, client: client, settings: settings}, nil
}

// See ComputePolicySource.
func (self *computePolicyHttpSource) Policy(ctx context.Context, version uint64) ([]byte, []byte, error) {
	document, err := self.get(ctx, ComputePolicyFileName(version), self.settings.PolicyMaxByteCount)
	if err != nil {
		return nil, nil, err
	}
	signature, err := self.get(ctx, ComputePolicySignatureFileName(version), self.settings.SignatureMaxByteCount)
	if err != nil {
		return nil, nil, err
	}
	return document, signature, nil
}

// See ComputePolicySource. The names are the pipeline's one layout (attest_policy_build.go), which publish and the
// ticket host's release write.
func (self *computePolicyHttpSource) Ticket(ctx context.Context, day time.Time) ([]byte, error) {
	return self.get(ctx, ComputePolicyTicketFileName(day), self.settings.TicketMaxByteCount)
}

// The body at name under the base, at most maxByteCount bytes, within FetchTimeout: 404 and 410 are
// ErrComputePolicySourceAbsent, any other status but 200 an error.
func (self *computePolicyHttpSource) get(ctx context.Context, name string, maxByteCount int) ([]byte, error) {
	if 0 < self.settings.FetchTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, self.settings.FetchTimeout)
		defer cancel()
	}
	target := *self.base
	target.Path += "/" + name
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := self.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("compute policy source: %w", err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return nil, ErrComputePolicySourceAbsent
	default:
		return nil, fmt.Errorf("compute policy source: %s answered %d", name, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxByteCount)+1))
	if err != nil {
		return nil, fmt.Errorf("compute policy source: %w", err)
	}
	if maxByteCount < len(body) {
		return nil, fmt.Errorf("compute policy source: %s is larger than %d bytes", name, maxByteCount)
	}
	return body, nil
}

// What NewComputePolicyFetcher builds on.
type ComputePolicyFetcherArgs struct {
	// Required: takes policies.
	Store *ComputePolicyStore
	// Required: takes tickets, and gives the time.
	Gate *ComputePolicyGate
	// The sources, tried in order for each file; none fetches nothing.
	Sources []ComputePolicySource
	// Required.
	Settings *AttestSettings
	// Nil logs nothing.
	Log Logger
}

// Fetches policies and tickets into the store and the gate.
type ComputePolicyFetcher struct {
	store    *ComputePolicyStore
	gate     *ComputePolicyGate
	sources  []ComputePolicySource
	settings *AttestSettings
	log      Logger
}

// A fetcher over args.
func NewComputePolicyFetcher(args *ComputePolicyFetcherArgs) (*ComputePolicyFetcher, error) {
	if args == nil || args.Store == nil || args.Gate == nil || args.Settings == nil {
		return nil, errors.New("compute policy fetcher: a store, a gate and settings")
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &ComputePolicyFetcher{
		store:    args.Store,
		gate:     args.Gate,
		sources:  append([]ComputePolicySource{}, args.Sources...),
		settings: args.Settings,
		log:      log,
	}, nil
}

// One pass: the newest released ticket, then every newer policy it or anything verified names, then the next version
// where a source has one. What could not be fetched or was refused is joined into the error; what was taken stays
// taken.
func (self *ComputePolicyFetcher) Fetch(ctx context.Context) error {
	errs := []error{}
	if err := self.fetchTicket(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := self.fetchPolicies(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Today's ticket, else the newest of the days before it a window still covers, from the first source whose file the
// gate takes.
func (self *ComputePolicyFetcher) fetchTicket(ctx context.Context) error {
	now := self.gate.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	// a ticket's window covers its day and the ones after it, so a fetch looks back as far
	dayCount := int((self.settings.TicketMaxWindow + computePolicyDay - 1) / computePolicyDay)
	errs := []error{}
	for back := 0; back < max(dayCount, 1); back += 1 {
		day := today.AddDate(0, 0, -back)
		for _, source := range self.sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			file, err := source.Ticket(ctx, day)
			if errors.Is(err, ErrComputePolicySourceAbsent) {
				continue
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := self.gate.OfferTicket(file); err != nil {
				errs = append(errs, fmt.Errorf("the ticket of %s: %w", day.Format(computePolicyTicketDayLayout), err))
				continue
			}
			return nil
		}
	}
	return errors.Join(errs...)
}

// The policy the highest version seen names where it is above the newest held, else the next version, until no
// source has the one asked or FetchMaxPolicySteps versions were taken.
func (self *ComputePolicyFetcher) fetchPolicies(ctx context.Context) error {
	errs := []error{}
	for step := 0; step < self.settings.FetchMaxPolicySteps; step += 1 {
		held := uint64(0)
		if newest := self.store.Newest(); newest != nil {
			held = newest.Version
		}
		version := held + 1
		if highest := self.store.HighestSeen(); held < highest {
			version = highest
		}
		taken := false
		for _, source := range self.sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			document, signature, err := source.Policy(ctx, version)
			if errors.Is(err, ErrComputePolicySourceAbsent) {
				continue
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			policy, err := self.store.Offer(document, signature)
			if err != nil {
				errs = append(errs, fmt.Errorf("policy %d: %w", version, err))
				continue
			}
			// a source that answers with what is already held makes no progress, so the next is asked
			if policy.Version < version {
				errs = append(errs, fmt.Errorf("policy %d: the source answered version %d", version, policy.Version))
				continue
			}
			taken = true
			break
		}
		if !taken {
			break
		}
	}
	return errors.Join(errs...)
}

// The fetcher's own schedule, once remote work has been asked for: a pass at once, then one each FetchInterval, until
// ctx ends. A device that never asks for remote work fetches nothing. Non-positive FetchInterval runs no schedule,
// leaving fetches to the gate's refreshes.
func (self *ComputePolicyFetcher) run(ctx context.Context, clock Clock) {
	if self.settings.FetchInterval <= 0 {
		return
	}
	select {
	case <-self.gate.Wanted():
	case <-ctx.Done():
		return
	}
	for {
		if err := self.Fetch(ctx); err != nil && ctx.Err() == nil {
			self.log.Warningf("[attest]fetching the compute policy: %s", err)
		}
		select {
		case <-clock.After(self.settings.FetchInterval):
		case <-ctx.Done():
			return
		}
	}
}
