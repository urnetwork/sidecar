// SearchSignerClient: the broker's half of searchsigner's API (DESIGN-COMPUTE §21.5, §14.2, D-SRCH-12; SRCH-M13-07), the
// one link between the two systems §21.5 keeps apart, over mTLS, which only the broker reaches and only in this
// direction (compute-plan-signer-report-path, QD-1377: the broker pulls the reports):
//
//	POST /v1/sign             SearchSignRequest, one admitted ticket with its amount, minute and sealed payee, relayed
//	                          unread; SearchSignResponse, the sealed authorization or the signer's refusal
//	POST /v1/reports          an empty body; SearchSignerReports, the final authorizations not yet answered, by ticket
//	POST /v1/reports/answers  SearchSignerAnswers, the broker's answer to each by ticket; an empty answer
//	POST /v1/day              SearchSignerDayRequest; SearchSignerDay, a UTC day's totals with no network, for the
//	                          day's reconciliation (SRCH-M13-09)
//
// The paths are this plan's (proposed): SRCH-M13-03 and SRCH-M13-04 serve them on the signer. Every body is
// deterministic protobuf (QD-1246). A status but 200, a body past SignerAnswerMaxByteCount or one that does not parse
// is ErrSearchSignerCall naming the path and status alone, never a byte of the body, and the admission answers capacity.
//
// The client's credentials are the block's vault file compute-searchsigner-client.yml (server/computehost's
// HostSearchSignerClientFileName), read through ComputeEngineDeps.SecretFile: a YAML mapping of url (the signer's https
// base url), certificate and key (the broker's client certificate and its private key, PEM) and ca (the certificates
// the signer's own chains to, PEM), the connection TLS 1.3 alone. No hostname is written here: the url is the vault's.
// A block whose file does not read holds no client, and every search answers capacity. Until SRCH-M13-03 lands the
// signer, a test's fake stands in (computeservice's search fixture).
//
// Safe for concurrent use.

package computeservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/protocol"
)

// The signer's routes, from its base url: identifiers of the format.
const (
	SearchSignerSignPath    = "/v1/sign"
	SearchSignerReportsPath = "/v1/reports"
	SearchSignerAnswersPath = "/v1/reports/answers"
	SearchSignerDayPath     = "/v1/day"
)

// The block's vault file the client reads (server/computehost's HostSearchSignerClientFileName), and the kind its
// private key is handed to the privacy harness under.
const (
	ComputeSearchSignerClientFileName  = "compute-searchsigner-client.yml"
	computeSearchSignerClientSecretKey = "searchsigner_client_key"
)

// A call the signer did not answer as its API does: unreachable, another status, a body that does not read.
var ErrSearchSignerCall = errors.New("searchsigner did not answer")

// searchsigner's API, which the broker alone calls. Safe for concurrent use.
type SearchSignerClient interface {
	// One admitted ticket: the sealed authorization, or the signer's refusal in the answer.
	Sign(ctx context.Context, request *protocol.SearchSignRequest) (*protocol.SearchSignResponse, error)
	// The final authorizations the signer holds unanswered.
	Reports(ctx context.Context) (*protocol.SearchSignerReports, error)
	// The broker's answers to reports, by ticket.
	Answer(ctx context.Context, answers *protocol.SearchSignerAnswers) error
	// A UTC day's totals, with no network.
	Day(ctx context.Context, request *protocol.SearchSignerDayRequest) (*protocol.SearchSignerDay, error)
}

// The client's vault file.
type searchSignerClientFile struct {
	Url         string `yaml:"url"`
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
	Ca          string `yaml:"ca"`
}

// The client over HTTPS.
type httpSearchSignerClient struct {
	baseUrl  *url.URL
	client   *http.Client
	settings *ComputeSearchSettings
}

// A client of the signer at baseUrl, an https url, through client, whose transport holds the broker's mTLS
// credentials.
func NewSearchSignerHttpClient(baseUrl string, client *http.Client, settings *ComputeSearchSettings) (SearchSignerClient, error) {
	if settings == nil {
		settings = DefaultComputeSearchSettings()
	}
	parsed, err := url.Parse(baseUrl)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("searchsigner's url is no https base url")
	}
	if client == nil {
		return nil, errors.New("searchsigner's client holds no transport")
	}
	return &httpSearchSignerClient{baseUrl: parsed, client: client, settings: settings}, nil
}

// The client the block's vault file describes, through secretFile. An error naming the file alone where it does not
// read, past its bound, or holds no url, key pair or ca.
func newSearchSignerClientFromSecretFile(secretFile func(name string) ([]byte, error), settings *ComputeSearchSettings) (SearchSignerClient, error) {
	if secretFile == nil {
		return nil, errors.New("this compute block reads no secret files")
	}
	data, err := secretFile(ComputeSearchSignerClientFileName)
	if err != nil {
		return nil, fmt.Errorf("%s does not read", ComputeSearchSignerClientFileName)
	}
	if settings.SignerClientFileMaxByteCount < len(data) {
		return nil, fmt.Errorf("%s is longer than %d bytes", ComputeSearchSignerClientFileName, settings.SignerClientFileMaxByteCount)
	}
	file := &searchSignerClientFile{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(file); err != nil {
		// never the error's text, which may quote the file
		return nil, fmt.Errorf("%s is not the client's mapping", ComputeSearchSignerClientFileName)
	}
	testHookSecret(computeSearchSignerClientSecretKey, []byte(file.Key))
	certificate, err := tls.X509KeyPair([]byte(file.Certificate), []byte(file.Key))
	if err != nil {
		return nil, fmt.Errorf("%s holds no client certificate and key", ComputeSearchSignerClientFileName)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(file.Ca)) {
		return nil, fmt.Errorf("%s holds no ca", ComputeSearchSignerClientFileName)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS13,
		},
		ForceAttemptHTTP2: true,
	}
	return NewSearchSignerHttpClient(file.Url, &http.Client{Transport: transport}, settings)
}

// POSTs body to path and answers the reply's body, within the settings' bounds.
func (self *httpSearchSignerClient) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, self.settings.SignerTimeout)
	defer cancel()
	target := self.baseUrl.JoinPath(path)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSearchSignerCall, path)
	}
	request.Header.Set("Content-Type", computeContentTypeProtobuf)
	response, err := self.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s unreachable", ErrSearchSignerCall, path)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s answered %s", ErrSearchSignerCall, path, strconv.Itoa(response.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, self.settings.SignerAnswerMaxByteCount+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s's answer did not arrive", ErrSearchSignerCall, path)
	}
	if self.settings.SignerAnswerMaxByteCount < int64(len(data)) {
		return nil, fmt.Errorf("%w: %s's answer passes its bound", ErrSearchSignerCall, path)
	}
	return data, nil
}

// POSTs message to path and reads the reply into reply, nil for an empty one.
func (self *httpSearchSignerClient) call(ctx context.Context, path string, message proto.Message, reply proto.Message) error {
	body := []byte{}
	if message != nil {
		var err error
		if body, err = (proto.MarshalOptions{Deterministic: true}).Marshal(message); err != nil {
			return fmt.Errorf("%w: %s's request does not encode", ErrSearchSignerCall, path)
		}
	}
	data, err := self.post(ctx, path, body)
	if err != nil {
		return err
	}
	if reply == nil {
		return nil
	}
	if err := proto.Unmarshal(data, reply); err != nil {
		return fmt.Errorf("%w: %s's answer does not parse", ErrSearchSignerCall, path)
	}
	return nil
}

// See SearchSignerClient.
func (self *httpSearchSignerClient) Sign(ctx context.Context, request *protocol.SearchSignRequest) (*protocol.SearchSignResponse, error) {
	response := &protocol.SearchSignResponse{}
	if err := self.call(ctx, SearchSignerSignPath, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

// See SearchSignerClient.
func (self *httpSearchSignerClient) Reports(ctx context.Context) (*protocol.SearchSignerReports, error) {
	reports := &protocol.SearchSignerReports{}
	if err := self.call(ctx, SearchSignerReportsPath, nil, reports); err != nil {
		return nil, err
	}
	return reports, nil
}

// See SearchSignerClient.
func (self *httpSearchSignerClient) Answer(ctx context.Context, answers *protocol.SearchSignerAnswers) error {
	return self.call(ctx, SearchSignerAnswersPath, answers, nil)
}

// See SearchSignerClient.
func (self *httpSearchSignerClient) Day(ctx context.Context, request *protocol.SearchSignerDayRequest) (*protocol.SearchSignerDay, error) {
	day := &protocol.SearchSignerDay{}
	if err := self.call(ctx, SearchSignerDayPath, request, day); err != nil {
		return nil, err
	}
	return day, nil
}
