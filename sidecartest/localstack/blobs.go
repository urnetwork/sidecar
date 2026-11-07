// sidecar.BlobStore on the local stack's MinIO, keeping host_blobs.go's promises against a real store:
// every write is conditional, a PUT or DELETE that does not end in a definite answer reports
// BlobUnknownError, and every request but PutStream carries x-ur-deadline-ms and is cancelled here at
// that deadline. Each cluster is a bucket of one process, since §22.4 runs one locally; what is
// per-cluster in production is only the bucket's name here.
//
// A stock MinIO ignores x-ur-deadline-ms and keeps none of D-OPS-20's settle rules, so SettlePassed
// stays false until BlobSettings names a build that has passed FS-114. Safe for concurrent use.

package localstack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	s3MetadataHeaderPrefix = "X-Amz-Meta-"
	s3ChecksumHeader       = "X-Amz-Checksum-Sha256"
	// §19.6's deadline header (D-OPS-20).
	blobDeadlineHeader = "X-Ur-Deadline-Ms"
	// §19.6: objects carry this and no other content type.
	blobContentType = "application/octet-stream"
)

// A store's answers that mean a body did not match the checksum it named. Nothing was written.
var s3ChecksumErrorCodes = []string{"BadDigest", "XAmzContentChecksumMismatch", "XAmzContentSHA256Mismatch"}

type BlobClusterSettings struct {
	// Its id in BlobStore.
	ClusterId string
	// Its bucket, made unversioned on first use.
	Bucket string
}

type BlobSettings struct {
	// MinIO's S3 endpoint, as http://host:port. Its host and port must pass CheckStackAddress.
	Endpoint string
	// The root user local/docker-compose.yml starts it with: synthetic, on loopback only.
	AccessKeyId     string
	SecretAccessKey string
	// MinIO's default, which a signature names.
	Region string
	// Every metadata cluster, the first first.
	MetadataClusters []*BlobClusterSettings
	// Where seg/, pack/ and dropscan/ live.
	SegmentCluster *BlobClusterSettings
	// §19.6's store request deadline, 10 s on both clusters.
	RequestTimeout time.Duration
	// How long a dial may take. 5 s: loopback answers at once, so this only bounds a dead store.
	DialTimeout time.Duration
	// Whether the build behind Endpoint passed §22.9's settle cases. False until one has (FS-114).
	SettlePassed bool
	// Where a request reads its deadline's time and waits it out, so a test moves it. nil is real time,
	// which a real store's signature check needs.
	Clock sidecartest.Clock
}

// What local/docker-compose.yml binds, with one bucket per cluster fake_blobs.go names.
func DefaultBlobSettings() *BlobSettings {
	return &BlobSettings{
		Endpoint:         "http://127.0.0.1:59000",
		AccessKeyId:      "sidecar-local-test",
		SecretAccessKey:  "sidecar-local-test-only",
		Region:           "us-east-1",
		MetadataClusters: []*BlobClusterSettings{{ClusterId: "meta-1", Bucket: "sidecar-test-meta-1"}},
		SegmentCluster:   &BlobClusterSettings{ClusterId: "seg-1", Bucket: "sidecar-test-seg-1"},
		RequestTimeout:   10 * time.Second,
		DialTimeout:      5 * time.Second,
		SettlePassed:     false,
	}
}

// Real time, as sidecartest.Clock.
type realClock struct{}

func (self realClock) Now() time.Time {
	return time.Now()
}

func (self realClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

func (self realClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return time.AfterFunc(timeout, function).Stop
}

type BlobStore struct {
	settings    *BlobSettings
	clock       sidecartest.Clock
	endpoint    *url.URL
	credentials *s3Credentials
	client      *http.Client
	clusters    map[string]*blobCluster
}

// Makes each cluster's bucket when it is missing, and fails when the store does not answer. settings
// may be nil for the defaults. The caller closes it.
func NewBlobStore(ctx context.Context, settings *BlobSettings) (*BlobStore, error) {
	if settings == nil {
		settings = DefaultBlobSettings()
	}
	endpoint, err := url.Parse(settings.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := CheckStackAddress(endpoint.Host); err != nil {
		return nil, err
	}
	clock := settings.Clock
	if clock == nil {
		clock = realClock{}
	}
	dialer := net.Dialer{Timeout: settings.DialTimeout}
	self := &BlobStore{
		settings: settings,
		clock:    clock,
		endpoint: endpoint,
		credentials: &s3Credentials{
			accessKeyId:     settings.AccessKeyId,
			secretAccessKey: settings.SecretAccessKey,
			region:          settings.Region,
		},
		client: &http.Client{
			Transport: &http.Transport{
				DialContext:        dialer.DialContext,
				DisableCompression: true,
				// host_blobs.go's PutStream bound: this long after its last byte, with no response
				ResponseHeaderTimeout: settings.RequestTimeout,
			},
			// a redirect goes wherever it says, and CheckStackAddress passed only Endpoint
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		clusters: map[string]*blobCluster{},
	}
	for _, clusterSettings := range append(slices.Clone(settings.MetadataClusters), settings.SegmentCluster) {
		cluster := &blobCluster{store: self, clusterId: clusterSettings.ClusterId, bucket: clusterSettings.Bucket}
		if err := cluster.ensureBucket(ctx); err != nil {
			self.Close()
			return nil, fmt.Errorf("bucket %s: %w", clusterSettings.Bucket, err)
		}
		self.clusters[clusterSettings.ClusterId] = cluster
	}
	return self, nil
}

func (self *BlobStore) Close() {
	self.client.CloseIdleConnections()
}

func (self *BlobStore) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, ok := self.clusters[clusterId]
	if !ok {
		return nil, fmt.Errorf("%w: %s", sidecar.ErrBlobClusterUnknown, clusterId)
	}
	return cluster, nil
}

func (self *BlobStore) FirstCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.settings.MetadataClusters[0].ClusterId)
}

func (self *BlobStore) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.settings.SegmentCluster.ClusterId)
}

func (self *BlobStore) MetadataClusterIds() []string {
	clusterIds := make([]string, 0, len(self.settings.MetadataClusters))
	for _, cluster := range self.settings.MetadataClusters {
		clusterIds = append(clusterIds, cluster.ClusterId)
	}
	return clusterIds
}

func (self *BlobStore) NewRepoClusterId() string {
	return self.settings.MetadataClusters[0].ClusterId
}

// An answer the store gave, with what its error document said.
type s3Failure struct {
	status  int
	code    string
	message string
}

func (self *s3Failure) Error() string {
	return fmt.Sprintf("store answered %d %s: %s", self.status, self.code, self.message)
}

// Reads a failed response's error document. HEAD has none, so there the status is all of it.
func newS3Failure(response *http.Response) *s3Failure {
	failure := &s3Failure{status: response.StatusCode}
	document := struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}{}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err == nil && xml.Unmarshal(body, &document) == nil {
		failure.code = document.Code
		failure.message = document.Message
	}
	return failure
}

type blobCluster struct {
	store     *BlobStore
	clusterId string
	bucket    string
}

func (self *blobCluster) ClusterId() string {
	return self.clusterId
}

func (self *blobCluster) RequestTimeout() time.Duration {
	return self.store.settings.RequestTimeout
}

func (self *blobCluster) SettlePassed() bool {
	return self.store.settings.SettlePassed
}

// One request to the store, as send takes it.
type blobRequest struct {
	method string
	// Empty for the bucket itself.
	key     string
	query   url.Values
	headers map[string]string
	// The whole body, or nil for none. A stream sets stream instead.
	body []byte
	// A body the store reads as it comes, of exactly streamByteCount bytes, with no deadline.
	stream          io.Reader
	streamByteCount int64
}

// An open response. close ends its request, so a body is read only until then.
type blobResponse struct {
	response *http.Response
	close    func()
}

// Signs and sends request. Under ctx alone once its response has started, so a body streams past
// the deadline (host_blobs.go), and the caller closes what comes back on every success.
func (self *blobCluster) send(ctx context.Context, request *blobRequest) (*blobResponse, error) {
	endpoint := *self.store.endpoint
	endpoint.Path = "/" + self.bucket
	endpoint.RawPath = "/" + s3Escape(self.bucket, false)
	if request.key != "" {
		endpoint.Path += "/" + request.key
		endpoint.RawPath += "/" + s3Escape(request.key, true)
	}
	if request.query != nil {
		endpoint.RawQuery = s3CanonicalQuery(request.query)
	}

	issued := self.store.clock.Now()
	requestCtx, cancel := context.WithCancel(ctx)
	var body io.Reader
	payloadSha256 := s3EmptyPayloadSha256
	switch {
	case request.stream != nil:
		body = request.stream
		payloadSha256 = s3UnsignedPayload
	case 0 < len(request.body):
		body = bytes.NewReader(request.body)
		sum := sha256.Sum256(request.body)
		payloadSha256 = hex.EncodeToString(sum[:])
	}
	httpRequest, err := http.NewRequestWithContext(requestCtx, request.method, endpoint.String(), body)
	if err != nil {
		cancel()
		return nil, err
	}
	for name, value := range request.headers {
		httpRequest.Header.Set(name, value)
	}
	stopDeadline := func() bool { return true }
	if request.stream != nil {
		httpRequest.ContentLength = request.streamByteCount
	} else {
		deadline := sidecar.BlobRequestDeadline(ctx, issued, self.RequestTimeout())
		httpRequest.Header.Set(blobDeadlineHeader, strconv.FormatInt(deadline.UnixMilli(), 10))
		stopDeadline = self.store.clock.AfterFunc(deadline.Sub(issued), cancel)
	}
	signS3Request(httpRequest, self.store.credentials, issued, payloadSha256)
	response, err := self.store.client.Do(httpRequest)
	stopDeadline()
	if err != nil {
		cancel()
		return nil, err
	}
	return &blobResponse{
		response: response,
		close: func() {
			response.Body.Close()
			cancel()
		},
	}, nil
}

// One signed call to MinIO's admin api, which a test reads the stack's shape from. path names the
// whole route, since no bucket is in it.
func (self *blobCluster) sendAdmin(ctx context.Context, method string, path string) (*blobResponse, error) {
	endpoint := *self.store.endpoint
	endpoint.Path = path
	requestCtx, cancel := context.WithTimeout(ctx, self.RequestTimeout())
	httpRequest, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	signS3Request(httpRequest, self.store.credentials, time.Now(), s3EmptyPayloadSha256)
	response, err := self.store.client.Do(httpRequest)
	if err != nil {
		cancel()
		return nil, err
	}
	return &blobResponse{
		response: response,
		close: func() {
			response.Body.Close()
			cancel()
		},
	}, nil
}

// PUT /bucket. An owner asking again is no failure.
func (self *blobCluster) ensureBucket(ctx context.Context) error {
	answer, err := self.send(ctx, &blobRequest{method: http.MethodPut})
	if err != nil {
		return err
	}
	defer answer.close()
	if answer.response.StatusCode == http.StatusOK {
		return nil
	}
	failure := newS3Failure(answer.response)
	if failure.code == "BucketAlreadyOwnedByYou" {
		return nil
	}
	return failure
}

// What a PUT's failed answer means. Precondition and checksum are definite, nothing was written, and
// everything else leaves the outcome unknown however it reads (host_blobs.go). MinIO answers an If-Match
// on a missing key NoSuchKey, not 412, and host_blobs.go calls both a failed condition.
func putFailure(failure *s3Failure) error {
	switch {
	case failure.status == http.StatusPreconditionFailed, failure.code == "NoSuchKey":
		return sidecar.ErrBlobPrecondition
	case slices.Contains(s3ChecksumErrorCodes, failure.code):
		return sidecar.ErrBlobChecksum
	}
	return &sidecar.BlobUnknownError{Err: failure}
}

func putHeaders(condition string, conditionValue string, options *sidecar.BlobPutOptions) map[string]string {
	headers := map[string]string{"Content-Type": blobContentType, condition: conditionValue}
	if options == nil {
		return headers
	}
	if 0 < len(options.Sha256) {
		headers[s3ChecksumHeader] = base64.StdEncoding.EncodeToString(options.Sha256)
	}
	for name, value := range options.Metadata {
		headers[s3MetadataHeaderPrefix+name] = value
	}
	return headers
}

func unquoteEtag(etag string) string {
	return strings.Trim(etag, `"`)
}

func (self *blobCluster) put(ctx context.Context, request *blobRequest) (string, error) {
	answer, err := self.send(ctx, request)
	if err != nil {
		return "", &sidecar.BlobUnknownError{Err: err}
	}
	defer answer.close()
	if answer.response.StatusCode != http.StatusOK {
		return "", putFailure(newS3Failure(answer.response))
	}
	return unquoteEtag(answer.response.Header.Get("Etag")), nil
}

func (self *blobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}
	return self.put(ctx, &blobRequest{
		method:  http.MethodPut,
		key:     key,
		headers: putHeaders("If-None-Match", "*", options),
		body:    body,
	})
}

func (self *blobCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}
	if etag == "" {
		return "", fmt.Errorf("%w: an If-Match with no etag", sidecar.ErrBlobPutOptions)
	}
	return self.put(ctx, &blobRequest{
		method:  http.MethodPut,
		key:     key,
		headers: putHeaders("If-Match", `"`+etag+`"`, options),
		body:    body,
	})
}

// Ends a read with an error at the first byte past byteCount, so a body longer than declared fails
// rather than go out cut short. io.EOF comes only after it has seen the source's own.
type exactLengthReader struct {
	source    io.Reader
	remaining int64
}

func (self *exactLengthReader) Read(buffer []byte) (int, error) {
	if self.remaining == 0 {
		var extra [1]byte
		count, err := self.source.Read(extra[:])
		if 0 < count {
			return 0, errors.New("a body longer than declared")
		}
		return 0, err
	}
	count, err := self.source.Read(buffer[:min(int64(len(buffer)), self.remaining)])
	self.remaining -= int64(count)
	return count, err
}

func (self *blobCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	if len(checksumSha256) != 32 {
		return "", fmt.Errorf("%w: a segment names its 32 byte checksum", sidecar.ErrBlobPutOptions)
	}
	return self.put(ctx, &blobRequest{
		method:          http.MethodPut,
		key:             key,
		headers:         putHeaders("If-None-Match", "*", &sidecar.BlobPutOptions{Sha256: checksumSha256}),
		stream:          &exactLengthReader{source: body, remaining: byteCount},
		streamByteCount: byteCount,
	})
}

// The object a response's headers describe. byteCount is the whole object's.
func blobInfoOf(key string, response *http.Response, byteCount int64) (*sidecar.BlobInfo, error) {
	lastModified, err := http.ParseTime(response.Header.Get("Last-Modified"))
	if err != nil {
		return nil, err
	}
	info := &sidecar.BlobInfo{
		Key:          key,
		ByteCount:    byteCount,
		Etag:         unquoteEtag(response.Header.Get("Etag")),
		LastModified: lastModified,
	}
	for name, values := range response.Header {
		if field, ok := strings.CutPrefix(name, s3MetadataHeaderPrefix); ok && 0 < len(values) {
			if info.Metadata == nil {
				info.Metadata = map[string]string{}
			}
			info.Metadata[strings.ToLower(field)] = values[0]
		}
	}
	return info, nil
}

// What a read's failed answer means. Nothing about a read is unknown: it failed.
func readFailure(failure *s3Failure) error {
	switch failure.status {
	case http.StatusNotFound:
		return sidecar.ErrBlobNotFound
	case http.StatusRequestedRangeNotSatisfiable:
		return sidecar.ErrBlobRange
	}
	return failure
}

// Hands the body to the caller, whose Close ends the request.
type blobBody struct {
	io.Reader
	close func()
}

func (self *blobBody) Close() error {
	self.close()
	return nil
}

func (self *blobCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	answer, err := self.send(ctx, &blobRequest{method: http.MethodGet, key: key})
	if err != nil {
		return nil, err
	}
	if answer.response.StatusCode != http.StatusOK {
		defer answer.close()
		return nil, readFailure(newS3Failure(answer.response))
	}
	info, err := blobInfoOf(key, answer.response, answer.response.ContentLength)
	if err != nil {
		answer.close()
		return nil, err
	}
	return &sidecar.BlobObject{
		BlobInfo: *info,
		Body:     &blobBody{Reader: answer.response.Body, close: answer.close},
	}, nil
}

func (self *blobCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	if offset < 0 || byteCount <= 0 {
		return nil, fmt.Errorf("a range of %d bytes at %d", byteCount, offset)
	}
	answer, err := self.send(ctx, &blobRequest{
		method:  http.MethodGet,
		key:     key,
		headers: map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", offset, offset+byteCount-1)},
	})
	if err != nil {
		return nil, err
	}
	if answer.response.StatusCode != http.StatusPartialContent {
		defer answer.close()
		return nil, readFailure(newS3Failure(answer.response))
	}
	// Content-Range: bytes first-last/whole, the only place the whole object's size is
	_, wholeText, found := strings.Cut(answer.response.Header.Get("Content-Range"), "/")
	whole, err := strconv.ParseInt(wholeText, 10, 64)
	if !found || err != nil {
		answer.close()
		return nil, fmt.Errorf("a Content-Range of %q", answer.response.Header.Get("Content-Range"))
	}
	info, err := blobInfoOf(key, answer.response, whole)
	if err != nil {
		answer.close()
		return nil, err
	}
	return &sidecar.BlobObject{
		BlobInfo: *info,
		Body:     &blobBody{Reader: answer.response.Body, close: answer.close},
	}, nil
}

func (self *blobCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	answer, err := self.send(ctx, &blobRequest{method: http.MethodHead, key: key})
	if err != nil {
		return nil, err
	}
	defer answer.close()
	if answer.response.StatusCode != http.StatusOK {
		return nil, readFailure(newS3Failure(answer.response))
	}
	return blobInfoOf(key, answer.response, answer.response.ContentLength)
}

func (self *blobCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("a list limit of %d", limit)
	}
	query := url.Values{"list-type": {"2"}, "prefix": {keyPrefix}, "max-keys": {strconv.Itoa(limit)}}
	if startAfter != "" {
		query.Set("start-after", startAfter)
	}
	answer, err := self.send(ctx, &blobRequest{method: http.MethodGet, query: query})
	if err != nil {
		return nil, false, err
	}
	defer answer.close()
	if answer.response.StatusCode != http.StatusOK {
		return nil, false, newS3Failure(answer.response)
	}
	document := struct {
		IsTruncated bool `xml:"IsTruncated"`
		Contents    []struct {
			Key          string    `xml:"Key"`
			Size         int64     `xml:"Size"`
			ETag         string    `xml:"ETag"`
			LastModified time.Time `xml:"LastModified"`
		} `xml:"Contents"`
	}{}
	if err := xml.NewDecoder(answer.response.Body).Decode(&document); err != nil {
		return nil, false, err
	}
	objects := make([]*sidecar.BlobInfo, 0, len(document.Contents))
	for _, content := range document.Contents {
		objects = append(objects, &sidecar.BlobInfo{
			Key:          content.Key,
			ByteCount:    content.Size,
			Etag:         unquoteEtag(content.ETag),
			LastModified: content.LastModified,
		})
	}
	return objects, document.IsTruncated, nil
}

func (self *blobCluster) Delete(ctx context.Context, key string) error {
	answer, err := self.send(ctx, &blobRequest{method: http.MethodDelete, key: key})
	if err != nil {
		return &sidecar.BlobUnknownError{Err: err}
	}
	defer answer.close()
	if answer.response.StatusCode != http.StatusNoContent && answer.response.StatusCode != http.StatusOK {
		return &sidecar.BlobUnknownError{Err: newS3Failure(answer.response)}
	}
	return nil
}

var _ sidecar.BlobStore = (*BlobStore)(nil)
