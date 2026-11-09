// AWS Signature Version 4 for S3 requests: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html.

package localstack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	s3SignatureAlgorithm  = "AWS4-HMAC-SHA256"
	s3SignatureTimeFormat = "20060102T150405Z"
	s3SignatureDayFormat  = "20060102"
	// What x-amz-content-sha256 says when a body streams through unhashed.
	s3UnsignedPayload = "UNSIGNED-PAYLOAD"
	// sha256 of no bytes.
	s3EmptyPayloadSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type s3Credentials struct {
	accessKeyId     string
	secretAccessKey string
	region          string
}

func hmacSha256(key []byte, text string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(text))
	return mac.Sum(nil)
}

// S3's URI encoding: every byte but the unreserved, each path segment once, / kept in a path.
func s3Escape(text string, keepSlash bool) string {
	var escaped strings.Builder
	for index := 0; index < len(text); index += 1 {
		c := text[index]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			escaped.WriteByte(c)
		case c == '/' && keepSlash:
			escaped.WriteByte(c)
		default:
			fmt.Fprintf(&escaped, "%%%02X", c)
		}
	}
	return escaped.String()
}

// The query in the one order and encoding a signature covers.
func s3CanonicalQuery(query url.Values) string {
	pairs := []string{}
	for name, values := range query {
		for _, value := range values {
			pairs = append(pairs, s3Escape(name, false)+"="+s3Escape(value, false))
		}
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "&")
}

// Sets x-amz-date and Authorization on request, whose headers, host and x-amz-content-sha256 included,
// are all signed. payloadSha256 is that header's value.
func signS3Request(request *http.Request, credentials *s3Credentials, signedAt time.Time, payloadSha256 string) {
	signedAt = signedAt.UTC()
	stamp := signedAt.Format(s3SignatureTimeFormat)
	day := signedAt.Format(s3SignatureDayFormat)
	request.Header.Set("X-Amz-Date", stamp)
	request.Header.Set("X-Amz-Content-Sha256", payloadSha256)

	headerValues := map[string]string{"host": request.URL.Host}
	if request.Host != "" {
		headerValues["host"] = request.Host
	}
	for name, values := range request.Header {
		// a header's value is signed with its runs of spaces closed up
		headerValues[strings.ToLower(name)] = strings.Join(strings.Fields(strings.Join(values, ",")), " ")
	}
	headerNames := make([]string, 0, len(headerValues))
	for name := range headerValues {
		headerNames = append(headerNames, name)
	}
	slices.Sort(headerNames)
	var canonicalHeaders strings.Builder
	for _, name := range headerNames {
		canonicalHeaders.WriteString(name + ":" + headerValues[name] + "\n")
	}
	signedHeaders := strings.Join(headerNames, ";")

	canonicalRequest := strings.Join([]string{
		request.Method,
		request.URL.EscapedPath(),
		s3CanonicalQuery(request.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadSha256,
	}, "\n")
	canonicalSum := sha256.Sum256([]byte(canonicalRequest))
	scope := strings.Join([]string{day, credentials.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{s3SignatureAlgorithm, stamp, scope, hex.EncodeToString(canonicalSum[:])}, "\n")

	key := hmacSha256([]byte("AWS4"+credentials.secretAccessKey), day)
	key = hmacSha256(key, credentials.region)
	key = hmacSha256(key, "s3")
	key = hmacSha256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSha256(key, stringToSign))
	request.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		s3SignatureAlgorithm, credentials.accessKeyId, scope, signedHeaders, signature,
	))
}
