// The intake's network mail key (plan-SMTP-report-seal-key, decided as its option 1, QD-075; §14.8, §15.8,
// D-KEYS-17): what api's gate read surface checks before it answers a network's report seal key, the format of its
// answer, and the block's SmtpReportKeySource over that answer.
//
//	repo      §15.8's mail repo as the network's verified rows name it (AclState.NetworkMailKeyRepo): a Team's admin
//	          inbox, a personal network's Owner's mailbox
//	read      api reads the repo's GenRotates from gkm's drop-key route (GET /gkm/repos/<id>/drop-key?since=<g>,
//	          §10.14) under a 15-minute repo:<id>:deposit token, aud gkm, that it issues itself (§7.8), a scope that
//	          reaches that public-key read alone and that evs refuses
//	checks    CheckSmtpReportSealKey: the newest generation gkm serves (the answer's last, generations rising)
//	          verifies under its signer's admitted identity key; §10.9's rotation checks pass at its own pin, so it
//	          names the repo, its signer writes it, its holders are the state's and its drop key's life is in
//	          bounds, its parent being the answer's entry before it; it publishes a drop key; and at api's newest
//	          state it covers the repo's holders_shrunk_at and every holder expiry up to now (§10.6's gate), with now
//	          before its drop_not_after_ms
//	cache     api keeps what it read at most 5 minutes, running SmtpReportSealKey.Check again at each answer, so a
//	          removal stops the seal at once and a rotation reaches it within that bound
//	answer    GET /internal/gate/report-key/<network_id> on the platform listener's gate bearer: the key, its
//	          generation and drop_not_after_ms, or no field when the network has no key to seal to; 503 when api
//	          cannot tell now
//
// A key is never sealed to past a removal its generation does not cover, so a removed reader opens no later copy.
// What a depositor does and api does not: a pin of its own, since api holds none, so gkm's newest is the newest; and
// the wait for a newer rotation, which here is a report whose raw bytes are dropped unread and whose fields are kept.
//
// The intake already sees the raw bytes (mx-4), so the checks are for whom the copies are sealed to: the network's
// readers at the newest state, never a generation a removed reader holds, and never a key a server made up, since
// every GenRotate verifies under an identity key the network's own log admits.
//
// Nothing here creates, derives or unwraps a key, so nothing passes through testHookSecret.

package smtpedgeservice

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// api's internal route the block's key source reads, followed by the network's id (§8.9's gate read surface).
const SmtpReportKeyGatePath = "/internal/gate/report-key/"

var (
	// The network has no key to seal to: its rows name no mail key's repo, gkm serves no generation with a drop key,
	// or the newest fails a check. Its reports' raw bytes are dropped unread.
	ErrSmtpReportKeyNone = errors.New("smtp report key: none to seal to")
	// The key cannot be told now: the verified state is behind the newest generation, or gkm or api did not answer.
	// The report is taken again later.
	ErrSmtpReportKeyUnavailable = errors.New("smtp report key: unavailable")
)

// A network mail key api's gate read surface verified: the newest generation's drop key of §15.8's repo.
type SmtpReportSealKey struct {
	RepoId     sidecar.Id
	Generation uint64
	// X-Wing's public key.
	PublicKey []byte
	// drop_not_after_ms.
	NotAfter time.Time
	// The GenRotate's auth pin and time, which coverage is judged by again at each answer.
	Auth *bridge.AuthPin
	Time time.Time
}

// Whether the key still seals at the verifier's newest state view and now: before its drop_not_after_ms, and covering
// the repo's holders_shrunk_at and every holder expiry up to now (§10.6's gate). nil when it seals;
// ErrSmtpReportKeyUnavailable while the state is below the generation's pin; ErrSmtpReportKeyNone otherwise.
func (self *SmtpReportSealKey) Check(view sidecar.GkmAuthView, now time.Time) error {
	if view == nil {
		return fmt.Errorf("%w: no verified state", ErrSmtpReportKeyUnavailable)
	}
	if !now.Before(self.NotAfter) {
		return fmt.Errorf("%w: generation %d's drop key has lapsed", ErrSmtpReportKeyNone, self.Generation)
	}
	err := sidecar.GkmGateCheck(view, self.RepoId, self.Auth, self.Time, now)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sidecar.ErrGkmAuthAhead):
		return fmt.Errorf("%w: %w", ErrSmtpReportKeyUnavailable, err)
	}
	return fmt.Errorf("%w: generation %d: %w", ErrSmtpReportKeyNone, self.Generation, err)
}

// §14.8's checks of gkm's drop-key answer for repoId, at the verifier's newest state view and now, a drop key living
// at most dropKeyLifetime past its generation's time (GkmSettings.DropKeyLifetime). See the file header. The error is
// ErrSmtpReportKeyNone or ErrSmtpReportKeyUnavailable, its text naming ids and positions only.
func CheckSmtpReportSealKey(view sidecar.GkmAuthView, repoId sidecar.Id, reply *protocol.GkmGenerationsReply, now time.Time, dropKeyLifetime time.Duration) (*SmtpReportSealKey, error) {
	if view == nil {
		return nil, fmt.Errorf("%w: no verified state", ErrSmtpReportKeyUnavailable)
	}
	none := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrSmtpReportKeyNone, fmt.Sprintf(format, args...))
	}
	signeds := reply.GetGenerations()
	if len(signeds) == 0 {
		return nil, none("gkm serves no generation of the repo")
	}
	// each statement as written, unverified, for its group, generation and pin
	rotates := make([]*protocol.GenRotate, 0, len(signeds))
	for _, signed := range signeds {
		rotate := &protocol.GenRotate{}
		if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
			return nil, none("a GenRotate that does not parse")
		}
		if 0 < len(rotates) && rotate.GetGeneration() <= rotates[len(rotates)-1].GetGeneration() {
			return nil, none("generations that do not rise")
		}
		rotates = append(rotates, rotate)
	}
	newestIndex := len(signeds) - 1
	if view.Pin().GetVersion() < rotates[newestIndex].GetAuth().GetVersion() {
		// a generation of a state the verifier has not reached, whose signer it may not know as admitted yet
		return nil, fmt.Errorf("%w: generation %d's pin %d is above the state's %d", ErrSmtpReportKeyUnavailable,
			rotates[newestIndex].GetGeneration(), rotates[newestIndex].GetAuth().GetVersion(), view.Pin().GetVersion())
	}
	parse := func(index int) (*sidecar.GkmGeneration, error) {
		groupId, err := sidecar.IdFromBytes(rotates[index].GetGroupId())
		if err != nil {
			return nil, err
		}
		signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signeds[index])
		if err != nil {
			return nil, err
		}
		return sidecar.ParseGenRotate(signedBytes, groupId, rotates[index].GetGeneration(), sidecar.GkmIdentityKeys(view))
	}
	newest, err := parse(newestIndex)
	if err != nil {
		return nil, none("generation %d does not verify: %v", rotates[newestIndex].GetGeneration(), err)
	}
	generation := newest.Rotate.GetGeneration()
	var parent *sidecar.GkmGeneration
	if 1 < generation && 0 < newestIndex && rotates[newestIndex-1].GetGeneration()+1 == generation {
		if parent, err = parse(newestIndex - 1); err != nil {
			return nil, none("generation %d does not verify: %v", generation-1, err)
		}
	}
	verdict, err := sidecar.CheckRotation(view, &sidecar.GkmRotationCheckArgs{
		RepoId:          repoId,
		Generation:      newest,
		Parent:          parent,
		DropKeyLifetime: dropKeyLifetime,
		Now:             now,
	})
	switch {
	case errors.Is(err, sidecar.ErrGkmAuthAhead) || errors.Is(err, sidecar.ErrGkmTimeAhead):
		return nil, fmt.Errorf("%w: generation %d: %w", ErrSmtpReportKeyUnavailable, generation, err)
	case err != nil:
		// no parent to chain on, or a state that cannot name the repo's holders
		return nil, none("generation %d cannot be judged: %v", generation, err)
	case verdict.Refused:
		return nil, none("generation %d is refused: %s %s", generation, verdict.Reason, verdict.Detail)
	}
	rotate := newest.Rotate
	if len(rotate.GetDropPublicKey()) == 0 {
		return nil, none("generation %d publishes no drop key", generation)
	}
	key := &SmtpReportSealKey{
		RepoId:     repoId,
		Generation: generation,
		PublicKey:  bytes.Clone(rotate.GetDropPublicKey()),
		NotAfter:   time.UnixMilli(rotate.GetDropNotAfterMs()),
		Auth:       proto.Clone(rotate.GetAuth()).(*bridge.AuthPin),
		Time:       time.UnixMilli(rotate.GetTimeMs()),
	}
	if err := key.Check(view, now); err != nil {
		return nil, err
	}
	return key, nil
}

// GET /internal/gate/report-key/<network_id>'s answer, JSON: the network's key to seal to, or no field for none.
type SmtpReportKeyReply struct {
	// X-Wing's public key, in base64.
	PublicKey  []byte `json:"public_key,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	// drop_not_after_ms.
	NotAfterMs int64 `json:"not_after_ms,omitempty"`
}

// The answer for key, the one for none when key is nil.
func NewSmtpReportKeyReply(key *SmtpReportSealKey) *SmtpReportKeyReply {
	if key == nil {
		return &SmtpReportKeyReply{}
	}
	return &SmtpReportKeyReply{
		PublicKey:  bytes.Clone(key.PublicKey),
		Generation: key.Generation,
		NotAfterMs: key.NotAfter.UnixMilli(),
	}
}

// The key the answer holds at now, nil for none or for one that lapsed since api answered, or why the answer is no
// answer of the route's.
func (self *SmtpReportKeyReply) publicKey(now time.Time) ([]byte, error) {
	if len(self.PublicKey) == 0 {
		if self.Generation != 0 || self.NotAfterMs != 0 {
			return nil, errors.New("smtp report key: an answer of none naming a generation")
		}
		return nil, nil
	}
	if self.Generation == 0 || self.NotAfterMs <= 0 {
		return nil, errors.New("smtp report key: a key with no generation or expiry")
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(self.PublicKey); err != nil {
		return nil, errors.New("smtp report key: a key that is no X-Wing public key")
	}
	if !now.Before(time.UnixMilli(self.NotAfterMs)) {
		return nil, nil
	}
	return bytes.Clone(self.PublicKey), nil
}

// The block's source's tunables, each with its default here and nowhere else.
type SmtpReportKeyGateSettings struct {
	// The most bytes one answer may hold before the read fails: 8 KiB, an X-Wing public key in base64 (1,624 B) and
	// two numbers, with room. Must be positive.
	ReplyMaxByteCount int64
}

func DefaultSmtpReportKeyGateSettings() *SmtpReportKeyGateSettings {
	return &SmtpReportKeyGateSettings{
		ReplyMaxByteCount: 8 * 1024,
	}
}

// What NewSmtpReportKeyGateSource takes.
type SmtpReportKeyGateSourceArgs struct {
	// api's base url: http or https, with no trailing slash.
	ApiUrl string
	// The block's own gate bearer (the platform listener's), which goes nowhere but this route's Authorization
	// header.
	Bearer string
	// nil: a client of its own that follows no redirect.
	HttpClient *http.Client
	// nil is real time.
	Clock sidecar.Clock
	// nil takes the defaults.
	Settings *SmtpReportKeyGateSettings
}

// SmtpReportKeySource over api's gate read surface: GET <api>/internal/gate/report-key/<network_id> on the block's
// gate bearer, each call bounded by the caller's context, which the intake bounds by its StoreTimeout. A 200 in the
// route's format is a key or none; every other outcome, a refusal, a redirect, a transport error or an answer past
// its bound, is the source not telling now (ErrSmtpReportKeyUnavailable), which the listener answers 451. Its errors
// name a status or a part, never the bearer or a key. Safe for concurrent use.
type SmtpReportKeyGateSource struct {
	routeUrl   string
	bearer     string
	httpClient *http.Client
	clock      sidecar.Clock
	settings   *SmtpReportKeyGateSettings
}

var _ SmtpReportKeySource = (*SmtpReportKeyGateSource)(nil)

// A source of args. An error names the part that cannot be used, never the bearer.
func NewSmtpReportKeyGateSource(args *SmtpReportKeyGateSourceArgs) (*SmtpReportKeyGateSource, error) {
	if args == nil {
		return nil, errors.New("smtp report key source: no args")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSmtpReportKeyGateSettings()
	}
	if settings.ReplyMaxByteCount <= 0 {
		return nil, errors.New("smtp report key source: no answer bound")
	}
	if args.Bearer == "" {
		return nil, errors.New("smtp report key source: no bearer")
	}
	apiUrl, err := url.Parse(args.ApiUrl)
	if err != nil || (apiUrl.Scheme != "http" && apiUrl.Scheme != "https") || apiUrl.Host == "" || strings.HasSuffix(args.ApiUrl, "/") {
		return nil, errors.New("smtp report key source: api url")
	}
	httpClient := args.HttpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{},
			// a redirect is answered as the refusal it is, so the bearer goes to api's own url alone
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &SmtpReportKeyGateSource{
		routeUrl:   args.ApiUrl + SmtpReportKeyGatePath,
		bearer:     args.Bearer,
		httpClient: httpClient,
		clock:      clock,
		settings:   settings,
	}, nil
}

// See SmtpReportKeySource.
func (self *SmtpReportKeyGateSource) ReportSealKey(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, self.routeUrl+networkId.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: a request that does not build", ErrSmtpReportKeyUnavailable)
	}
	request.Header.Set("Authorization", "Bearer "+self.bearer)
	request.Header.Set("Accept", "application/json")
	response, err := self.httpClient.Do(request)
	if err != nil {
		// the transport's own error may name the url, which holds an id, and never the bearer; it is not passed on
		return nil, fmt.Errorf("%w: api did not answer", ErrSmtpReportKeyUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: api answered %d", ErrSmtpReportKeyUnavailable, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ReplyMaxByteCount+1))
	if err != nil {
		return nil, fmt.Errorf("%w: the answer was cut short", ErrSmtpReportKeyUnavailable)
	}
	if self.settings.ReplyMaxByteCount < int64(len(body)) {
		return nil, fmt.Errorf("%w: an answer past its bound", ErrSmtpReportKeyUnavailable)
	}
	reply := &SmtpReportKeyReply{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(reply); err != nil {
		return nil, fmt.Errorf("%w: an answer that is not the route's format", ErrSmtpReportKeyUnavailable)
	}
	if err := decoder.Decode(&json.RawMessage{}); err != io.EOF {
		return nil, fmt.Errorf("%w: a second value after the answer", ErrSmtpReportKeyUnavailable)
	}
	publicKey, err := reply.publicKey(self.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSmtpReportKeyUnavailable, err)
	}
	return publicKey, nil
}
