package localstack

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// AWS's own worked examples, from the signature documentation: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html.
// The bucket, key and credentials are the page's, and nothing of ours.
func TestSignaturesMatchAwsPublishedExamples(t *testing.T) {
	credentials := &s3Credentials{
		accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		region:          "us-east-1",
	}
	signedAt := time.Date(2013, time.May, 24, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name          string
		method        string
		url           string
		headers       map[string]string
		payloadSha256 string
		want          string
	}{
		{
			name:          "get object",
			method:        http.MethodGet,
			url:           "https://examplebucket.s3.amazonaws.com/test.txt",
			headers:       map[string]string{"Range": "bytes=0-9"},
			payloadSha256: s3EmptyPayloadSha256,
			want:          "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name:   "put object",
			method: http.MethodPut,
			url:    "https://examplebucket.s3.amazonaws.com/test%24file.text",
			headers: map[string]string{
				"Date":                "Fri, 24 May 2013 00:00:00 GMT",
				"X-Amz-Storage-Class": "REDUCED_REDUNDANCY",
			},
			payloadSha256: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			want:          "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name:          "get bucket lifecycle",
			method:        http.MethodGet,
			url:           "https://examplebucket.s3.amazonaws.com/?lifecycle",
			payloadSha256: s3EmptyPayloadSha256,
			want:          "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name:          "list objects",
			method:        http.MethodGet,
			url:           "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			payloadSha256: s3EmptyPayloadSha256,
			want:          "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	} {
		request, err := http.NewRequest(c.method, c.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range c.headers {
			request.Header.Set(name, value)
		}
		signS3Request(request, credentials, signedAt, c.payloadSha256)
		authorization := request.Header.Get("Authorization")
		if !strings.HasSuffix(authorization, "Signature="+c.want) {
			t.Errorf("%s: %s", c.name, authorization)
		}
	}
}

func TestS3EscapeKeepsOnlyTheUnreserved(t *testing.T) {
	for _, c := range []struct {
		text      string
		keepSlash bool
		want      string
	}{
		{text: "aZ09-._~", want: "aZ09-._~"},
		{text: "a/b", keepSlash: true, want: "a/b"},
		{text: "a/b", want: "a%2Fb"},
		{text: "a b+c=d", want: "a%20b%2Bc%3Dd"},
		// a percent is escaped, never taken for one already done
		{text: "a%41", want: "a%2541"},
		{text: "\xff", want: "%FF"},
	} {
		if got := s3Escape(c.text, c.keepSlash); got != c.want {
			t.Errorf("%q: %q", c.text, got)
		}
	}
}
