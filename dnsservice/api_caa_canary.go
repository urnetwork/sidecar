// POST /dns/internal/caa-canary (§12.8's CAA probe, dns side; D-DNS-9, D-DNS-8, FS-32, FI-11; DNS-M6-05):
// certs, the only DNS-01 and canary writer, publishes a strong-mode custom host's canary at the host owner
// the host maps to, <host>.<net>.<root>, and takes it out again. Only the certs bearer reaches it, and it is a
// write, which the dns gate's writes: false refuses.
//
// A publish writes, in one write at serial s, the CAA RRset of the walk's effective set (the customer's pin)
// plus 0 urcanary "<128-bit nonce>", TTL ttl.canary (60), kind canary, so it expires an hour after the write
// as a challenge does and taskworker's chain removes it then; §12.6's write path plans a copy of *'s records
// at the owner where it holds nothing else, so the host's addresses keep answering from * while the probe
// runs (copy_rows.go). The block draws the nonce from crypto/rand and answers it with s, and certs looks for
// it in every answer of its walk: CAs ignore an unknown non-critical tag (RFC 8659 §3, §4.1), so the canary
// admits only the customer's pin, even flattened or cached. A delete takes out the canary and its copy in one
// write, whatever the verdict.
//
// What the model refuses (DnsCaaCanaryWriter):
//   - an owner no strong-mode custom host of its network maps to, so never a network's, alias's or scope's
//     @, and a CAA set no canary may hold: 400;
//   - a second probe at one owner, while another's canary stands (one probe per target at a time), unless the
//     request replaces that canary by its nonce, as certs does after /dns/ready answers stale: 409 busy;
//   - a CNAME at the owner, which the zone lint refuses (RFC 2181 §10.1): 409 lint_refused, which is itself the
//     probe's failing verdict (§12.8), so certs reads it as one;
//   - a restore: 503 with Retry-After, which certs retries with backoff.
//
// CAA stays refused to users (DNS-M5-02); only this route writes it below a network's zone.

package dnsservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// The canary route (plan-DNS-internal-route-credential's prefix over §12.8's /dns/caa-canary).
const DnsCaaCanaryPath = DnsInternalPathPrefix + "caa-canary"

// The CAA property tag of a canary (§12.8): one no CA knows, sent non-critical.
const DnsCaaCanaryTag = "urcanary"

// The bytes of a canary's nonce: §12.8's 128 bits.
const dnsCaaCanaryNonceByteCount = 16

// The codes of the route's 409 answers.
const (
	// another probe's canary stands at the owner
	DnsCaaCanaryCodeBusy = "busy"
	// the zone lint refused the canary: a CNAME at the owner, the probe's failing verdict
	DnsCaaCanaryCodeLintRefused = "lint_refused"
)

var (
	// An owner no strong-mode custom host maps to, or a CAA set no canary may hold: 400.
	ErrDnsCaaCanaryRefused = errors.New("dns caa canary refused")
	// Another probe's canary stands at the owner: 409 busy.
	ErrDnsCaaCanaryBusy = errors.New("dns caa canary busy")
	// The zone lint refused the canary, a CNAME at the owner: 409 lint_refused, the probe's failing verdict.
	ErrDnsCaaCanaryLint = errors.New("dns caa canary refused by the zone lint")
)

// One publish as the route hands it to the model.
type DnsCaaCanaryPut struct {
	// <host>.<label>.<root>, canonical.
	Owner string
	// The canary's RRset: the walk's effective set, then the urcanary property (DnsCaaCanaryRdata).
	Rdata []string
	// This publish's nonce, which Rdata's last record carries.
	Nonce string
	// The nonce of the canary this one replaces, or "" for a first publish.
	Replaces string
	// Seconds: ttl.canary.
	Ttl uint32
}

// The model's half of the route: each one write through §12.6's path. PutCaaCanary returns ErrDnsRestoring
// while restoring and ErrDnsCaaCanaryRefused, ErrDnsCaaCanaryBusy or ErrDnsCaaCanaryLint for what it refuses.
// DeleteCaaCanary returns ErrDnsWriteEmpty for a canary already gone, ErrDnsRestoring while restoring, and
// ErrDnsCaaCanaryRefused for an owner it cannot name. Safe for concurrent use.
type DnsCaaCanaryWriter interface {
	PutCaaCanary(ctx context.Context, root string, put *DnsCaaCanaryPut) (serial uint64, err error)
	DeleteCaaCanary(ctx context.Context, root string, owner string) (serial uint64, err error)
}

// The body of POST caa-canary.
type DnsCaaCanaryRequest struct {
	// May be left out with one root.
	Root string `json:"root,omitempty"`
	// The host owner a strong-mode custom host maps to, <host>.<label>.<root>, with or without its final dot.
	Owner string `json:"owner"`
	// The walk's effective set, each a CAA RDATA as presentation form writes it: 0 issue "ca.example;
	// accounturi=...". A publish names at least one.
	Caa []string `json:"caa,omitempty"`
	// The nonce of the canary this publish replaces, after /dns/ready answered stale (§13.8). Empty for a
	// first publish.
	Replaces string `json:"replaces,omitempty"`
	// Takes the canary and its copy out, whatever the verdict. Caa and Replaces are then left out.
	Delete bool `json:"delete,omitempty"`
}

// The answer of POST caa-canary: the serial the write took, zero for a delete of nothing, and a publish's
// nonce.
type DnsCaaCanaryAnswer struct {
	Serial uint64 `json:"serial"`
	Nonce  string `json:"nonce,omitempty"`
}

// The body of a 409.
type DnsCaaCanaryRefusal struct {
	Code  string `json:"code"`
	Error string `json:"error,omitempty"`
}

// A fresh nonce: 128 bits from crypto/rand in lowercase hex.
func NewDnsCaaCanaryNonce() (string, error) {
	nonceBytes := make([]byte, dnsCaaCanaryNonceByteCount)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonceBytes), nil
}

// Whether nonce is one a canary carries: 128 bits in lowercase hex.
func isDnsCaaCanaryNonce(nonce string) bool {
	if len(nonce) != 2*dnsCaaCanaryNonceByteCount {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil && strings.ToLower(nonce) == nonce
}

// The canary's RRset (§12.8): each record of caa, the walk's effective set, as one CAA RDATA, then 0 urcanary
// "<nonce>". Refuses, wrapping ErrDnsCaaCanaryRefused, an empty set or one past settings' caa_canary
// record_max_count, a record that is no CAA RDATA or names the urcanary tag itself, a record twice, and a
// nonce that is not 128 bits in lowercase hex.
func DnsCaaCanaryRdata(caa []string, nonce string, settings *DnsCaaCanarySettings) ([]string, error) {
	if !isDnsCaaCanaryNonce(nonce) {
		return nil, fmt.Errorf("%w: a nonce that is not 128 bits in hex", ErrDnsCaaCanaryRefused)
	}
	if len(caa) == 0 || settings.RecordMaxCount < len(caa) {
		return nil, fmt.Errorf("%w: %d records in the effective set", ErrDnsCaaCanaryRefused, len(caa))
	}
	rdata := []string{}
	for _, text := range caa {
		if strings.ContainsAny(text, "\n\r\x00") {
			return nil, fmt.Errorf("%w: a record holds a line break", ErrDnsCaaCanaryRefused)
		}
		record, err := dns.NewRR(". IN CAA " + text)
		caaRecord, ok := record.(*dns.CAA)
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: %q is no CAA record", ErrDnsCaaCanaryRefused, text)
		}
		if strings.EqualFold(caaRecord.Tag, DnsCaaCanaryTag) {
			return nil, fmt.Errorf("%w: the effective set names %s", ErrDnsCaaCanaryRefused, DnsCaaCanaryTag)
		}
		normal := strings.TrimPrefix(caaRecord.String(), caaRecord.Header().String())
		for _, earlier := range rdata {
			if earlier == normal {
				return nil, fmt.Errorf("%w: a record twice", ErrDnsCaaCanaryRefused)
			}
		}
		rdata = append(rdata, normal)
	}
	return append(rdata, fmt.Sprintf(`0 %s "%s"`, DnsCaaCanaryTag, nonce)), nil
}

// The nonce a canary's RRset carries, "" for an RRset with no urcanary record.
func DnsCaaCanaryNonce(rdata []string) string {
	for _, text := range rdata {
		record, err := dns.NewRR(". IN CAA " + text)
		if caaRecord, ok := record.(*dns.CAA); err == nil && ok && strings.EqualFold(caaRecord.Tag, DnsCaaCanaryTag) {
			return caaRecord.Value
		}
	}
	return ""
}

// The canary route.
func (self *DnsApi) caaCanaryRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodPost, path: DnsCaaCanaryPath, class: DnsCallerCerts, write: true, serve: self.serveCaaCanary},
	}
}

// The labels of the CAA canary counter.
const (
	dnsCaaCanaryResultWritten   = "written"
	dnsCaaCanaryResultDeleted   = "deleted"
	dnsCaaCanaryResultRefused   = "refused"
	dnsCaaCanaryResultBusy      = "busy"
	dnsCaaCanaryResultLint      = "lint_refused"
	dnsCaaCanaryResultRestoring = "restoring"
	dnsCaaCanaryResultFailed    = "failed"
)

func (self *DnsApi) serveCaaCanary(writer http.ResponseWriter, request *http.Request) {
	unavailable := func() {
		retryAfter := int(math.Ceil(self.host.GatesOrClosed().RetryAfter().Seconds()))
		writer.Header().Set("Retry-After", strconv.Itoa(max(retryAfter, 1)))
		http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
	}
	conflict := func(code string, err error) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusConflict)
		body, _ := json.Marshal(&DnsCaaCanaryRefusal{Code: code, Error: err.Error()})
		writer.Write(body)
	}
	if self.deps.CaaCanaries == nil {
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultFailed)
		unavailable()
		return
	}
	settings := &self.settings.CaaCanary
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(settings.RequestMaxByteCount)+1))
	if err != nil || settings.RequestMaxByteCount < len(body) {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	canary := &DnsCaaCanaryRequest{}
	if err := json.Unmarshal(body, canary); err != nil || canary.Owner == "" {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	root, ok := self.challengeRoot(canary.Root)
	owner := dns.CanonicalName(canary.Owner)
	if _, valid := dns.IsDomainName(owner); !ok || !valid || owner == root || !dns.IsSubDomain(root, owner) {
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultRefused)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	var answer *DnsCaaCanaryAnswer
	if canary.Delete {
		if len(canary.Caa) != 0 || canary.Replaces != "" {
			http.Error(writer, "a delete names no record", http.StatusBadRequest)
			return
		}
		serial, err := self.deps.CaaCanaries.DeleteCaaCanary(request.Context(), root, owner)
		if errors.Is(err, ErrDnsWriteEmpty) {
			err = nil
		}
		answer = &DnsCaaCanaryAnswer{Serial: serial}
		if err == nil {
			self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultDeleted)
		}
		if err != nil && !self.answerCaaCanaryError(writer, err, unavailable, conflict) {
			return
		}
	} else {
		if canary.Replaces != "" && !isDnsCaaCanaryNonce(canary.Replaces) {
			self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultRefused)
			http.Error(writer, "replaces is no nonce", http.StatusBadRequest)
			return
		}
		nonce, err := NewDnsCaaCanaryNonce()
		if err != nil {
			self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultFailed)
			unavailable()
			return
		}
		testHookSecret("dns_caa_canary_nonce", []byte(nonce))
		rdata, err := DnsCaaCanaryRdata(canary.Caa, nonce, settings)
		if err != nil {
			self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultRefused)
			http.Error(writer, "canary refused", http.StatusBadRequest)
			return
		}
		serial, err := self.deps.CaaCanaries.PutCaaCanary(request.Context(), root, &DnsCaaCanaryPut{
			Owner:    owner,
			Rdata:    rdata,
			Nonce:    nonce,
			Replaces: canary.Replaces,
			Ttl:      self.settings.Ttl.Canary,
		})
		if err != nil {
			self.answerCaaCanaryError(writer, err, unavailable, conflict)
			return
		}
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultWritten)
		answer = &DnsCaaCanaryAnswer{Serial: serial, Nonce: nonce}
	}
	dnsWriteJson(writer, answer)
}

// Answers a writer's refusal as the route maps it, counting it. Always false: the request is answered.
func (self *DnsApi) answerCaaCanaryError(writer http.ResponseWriter, err error, unavailable func(), conflict func(code string, err error)) bool {
	switch {
	case errors.Is(err, ErrDnsRestoring):
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultRestoring)
		unavailable()
	case errors.Is(err, ErrDnsCaaCanaryLint):
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultLint)
		conflict(DnsCaaCanaryCodeLintRefused, err)
	case errors.Is(err, ErrDnsCaaCanaryBusy):
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultBusy)
		conflict(DnsCaaCanaryCodeBusy, err)
	case errors.Is(err, ErrDnsCaaCanaryRefused):
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultRefused)
		http.Error(writer, "canary refused", http.StatusBadRequest)
	default:
		self.metrics.caaCanaries.Add(1, dnsCaaCanaryResultFailed)
		self.log.Errorf("[dns]caa canary write failed: %v", err)
		unavailable()
	}
	return false
}
