//go:build !sidecar_http && !ios_extension

// §15.5's MTA-STS on the receiver (M8; D-MAIL-4, I-11; owner decision 96; RFC 8461; MAIL-M8-08): the policy a network's
// receivers serve at https://mta-sts.<zone>/.well-known/mta-sts.txt, and the receiver's half of serving it as §13.9's
// system publish.
//
//	policy    MailMtaStsHandler answers GET and HEAD of RFC 8461 §3.3's path with sidecar.MtaStsPolicy's text for the
//	          zone the request names, mode enforce and mx: mx.<zone>, as text/plain, so the label's policy is the very
//	          text whose id §12.7's _mta-sts carries (DNS-M8-01). The zones are the network's own, <label>.<root> and
//	          its live alias's <alias>.<root>; an alias's TXT is its label's (dnsservice's alias view copies TXT as
//	          it stands), and that id stays a version of both, since one setting changes both texts together. Any
//	          other host gets 404: a burner's <blabel>, which relies on DANE and publishes no policy, since senders
//	          never take a parent zone's (RFC 8461 §3.4), a Team scope's and another network's
//	serve     the mail component serves it through Sidecar.ServeTlsSystemPublish (tls/443/mta-sts, audience public,
//	          no tls_endpoints unit or expiry) once mail is on, this device's receiver holds its smtp/25/mx listen
//	          and the device holds a §13 certificate answering mta-sts.<label>.<root>, never on its self-signed leaf;
//	          the sockets service admits it only for a verified network with a mail_network row (§13.9's
//	          ValidateListen). The receiver's end, the listen grant's above all, ends it, as does mail turning off.
//	          A Team scope's receiver serves none: §13.9 names no scope publish
//
// Nothing here logs a host or a zone (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RFC 8461 §3.3's well-known path and the host its policy sits at below a zone: identifiers of the protocol.
const (
	mailMtaStsPath      = "/.well-known/mta-sts.txt"
	mailMtaStsHostLabel = "mta-sts"
)

// What the receiver's MTA-STS publish is tuned by.
type MailMtaStsSettings struct {
	// The policy the receivers serve, whose id §12.7's _mta-sts carries: one object both sides read, so its
	// defaults stay sidecar.DefaultMtaStsSettings'.
	Policy *MtaStsSettings
	// After a publish the sockets service refused, an unverified network's above all, the wait before the next try,
	// so a refusal costs one registration an interval. Must be positive.
	RetryInterval time.Duration
}

// The receiver's defaults: §15.5's policy, and a try every 5 min after a refusal.
func DefaultMailMtaStsSettings() *MailMtaStsSettings {
	return &MailMtaStsSettings{
		Policy:        DefaultMtaStsSettings(),
		RetryInterval: 5 * time.Minute,
	}
}

// §15.5's policy as a receiver answers it: see the file header's policy row.
type MailMtaStsHandler struct {
	// The zones answered, <label>.<root> and the live alias's <alias>.<root>, read at each request.
	zones    func() []string
	settings *MtaStsSettings
}

var _ http.Handler = (*MailMtaStsHandler)(nil)

// A handler for the zones zones answers, each a name like <label>.<root>. settings nil takes the defaults.
func NewMailMtaStsHandler(zones func() []string, settings *MtaStsSettings) *MailMtaStsHandler {
	if settings == nil {
		settings = DefaultMtaStsSettings()
	}
	return &MailMtaStsHandler{zones: zones, settings: settings}
}

// The zone host names under, lowercase with no final dot, and whether it is one of this handler's: mta-sts.<zone>.
func (self *MailMtaStsHandler) zoneOf(host string) (string, bool) {
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	host = strings.TrimSuffix(dnsAsciiLower(host), ".")
	zone, found := strings.CutPrefix(host, mailMtaStsHostLabel+".")
	if !found || zone == "" || self.zones == nil {
		return "", false
	}
	return zone, slices.ContainsFunc(self.zones(), func(own string) bool {
		return strings.TrimSuffix(dnsAsciiLower(own), ".") == zone
	})
}

// See http.Handler: RFC 8461 §3.3's fetch.
func (self *MailMtaStsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Path != mailMtaStsPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	host := r.Host
	if host == "" && r.TLS != nil {
		host = r.TLS.ServerName
	}
	zone, ok := self.zoneOf(host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	policy := MtaStsPolicy("mx."+zone, self.settings)
	// RFC 8461 §3.3: text/plain, and nothing for a cache between to keep past the policy's own max_age
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(policy)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		io.WriteString(w, policy)
	}
}

// How the component serves the system publish: the Sidecar's tls component, or a test's.
type mailMtaStsPublisher interface {
	// Whether this device holds a §13 certificate answering serverName: an issued one, never the self-signed leaf.
	Certified(serverName string) bool
	// Serves handler as the receiver's system publish until the closer is closed (Sidecar.ServeTlsSystemPublish).
	Serve(ctx context.Context, handler http.Handler) (io.Closer, error)
}

// The system publish over a Sidecar.
type mailSidecarMtaStsPublisher struct {
	sidecar *Sidecar
}

// See mailMtaStsPublisher: an issued certificate the tls component holds for serverName.
func (self *mailSidecarMtaStsPublisher) Certified(serverName string) bool {
	component := self.sidecar.tlsComponent()
	if component == nil || component.manager == nil {
		return false
	}
	_, err := component.manager.PublishCertificate([]string{serverName})
	return err == nil
}

// See mailMtaStsPublisher.
func (self *mailSidecarMtaStsPublisher) Serve(ctx context.Context, handler http.Handler) (io.Closer, error) {
	return self.sidecar.ServeTlsSystemPublish(ctx, handler, nil)
}

// The publisher the component serves through: a test's, else one over the client's Sidecar, else none.
func (self *MailClient) mtaStsPublisher() mailMtaStsPublisher {
	if seams := self.seams(); seams != nil && seams.mtaSts != nil {
		return seams.mtaSts
	}
	if self.sidecar != nil {
		return &mailSidecarMtaStsPublisher{sidecar: self.sidecar}
	}
	return nil
}

// The zones the policy answers for under row: the label's and the live alias's.
func mailMtaStsZones(row NetworkLabelRow) []string {
	if row.Root == "" || row.Label == "" {
		return []string{}
	}
	zones := []string{row.Label + "." + row.Root}
	if row.Alias != "" {
		zones = append(zones, row.Alias+"."+row.Root)
	}
	return zones
}

// The network's row as binding reads it, else as the component last read it.
func (self *MailClient) mtaStsNetwork(binding *MailBinding) NetworkLabelRow {
	if binding != nil && binding.Network != nil {
		return binding.Network()
	}
	return self.networkRow()
}

// Starts the receiver's system publish where its conditions hold, and ends it where one stops (the file header's
// serve row). Called after passReceive, with run's receiver as that pass left it.
func (self *MailClient) passMtaSts(run *mailComponentRun, binding *MailBinding) {
	settings := (*MailMtaStsSettings)(nil)
	if self.settings.Receive != nil {
		settings = self.settings.Receive.MtaSts
	}
	receiver, serving, retryTime := func() (*MailReceiver, bool, time.Time) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return run.receiver, run.mtaSts != nil, run.mtaStsRetryTime
	}()
	row := self.mtaStsNetwork(binding)
	publisher := self.mtaStsPublisher()
	hold := settings != nil && publisher != nil && receiver != nil && self.Enabled() && row.Label != "" && row.Root != "" &&
		receiver.Status().Listening && publisher.Certified(mailMtaStsHostLabel+"."+row.Label+"."+row.Root)
	if !hold {
		if serving {
			self.stopMtaSts(run)
		}
		return
	}
	if serving || self.clock.Now().Before(retryTime) {
		return
	}
	zones := func() []string {
		return mailMtaStsZones(self.mtaStsNetwork(binding))
	}
	closer, err := publisher.Serve(run.ctx, NewMailMtaStsHandler(zones, settings.Policy))
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			run.mtaStsRetryTime = self.clock.Now().Add(settings.RetryInterval)
		}()
		if self.log.V(1).Enabled() {
			self.log.Infof("[mail]the MTA-STS publish did not register; it tries again: %T", err)
		}
		return
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if run.receiver != receiver || run.ctx.Err() != nil {
			return false
		}
		run.mtaSts = closer
		return true
	}()
	if !kept {
		// the receiver ended while the publish registered
		closer.Close()
	}
}

// Ends run's system publish, if it serves one.
func (self *MailClient) stopMtaSts(run *mailComponentRun) {
	closer := func() io.Closer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		closer := run.mtaSts
		run.mtaSts = nil
		return closer
	}()
	if closer != nil {
		closer.Close()
	}
}

// Whether run serves the system publish now.
func (self *MailClient) mtaStsServing(run *mailComponentRun) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return run.mtaSts != nil
}
