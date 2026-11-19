//go:build !ios_extension

// MAIL-M9-03's header rules, by testdata/mail/burner_headers.yml's fixed vectors on every leg the root's tests run on,
// the sidecar_http Worker's included, and a canary fixture: after the rules, nothing of the device, the client or its
// timezone is left in a reply.

package sidecar

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/mail/burner_headers.yml
var testMailBurnerHeadersVectors []byte

// One vector.
type testMailBurnerHeadersCase struct {
	Name      string `yaml:"name"`
	MessageId string `yaml:"message_id"`
	NowMillis int64  `yaml:"now_ms"`
	Lf        bool   `yaml:"lf"`
	Refused   bool   `yaml:"refused"`
	Input     string `yaml:"input"`
	Want      string `yaml:"want"`
}

// The vectors, byte for byte.
func TestMailBurnerHeadersVectors(t *testing.T) {
	vectors := struct {
		Cases []*testMailBurnerHeadersCase `yaml:"cases"`
	}{}
	if err := yaml.Unmarshal(testMailBurnerHeadersVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no vectors")
	}
	rules := NewMailBurnerHeaders(nil)
	for _, vector := range vectors.Cases {
		input, want := vector.Input, vector.Want
		if !vector.Lf {
			input = strings.ReplaceAll(input, "\n", "\r\n")
			want = strings.ReplaceAll(want, "\n", "\r\n")
		}
		got, err := rules.Apply([]byte(input), &MailBurnerHeadersArgs{
			MessageId: vector.MessageId,
			Now:       time.UnixMilli(vector.NowMillis),
			Boundary:  func(index int) string { return fmt.Sprintf("b%d", index) },
		})
		if vector.Refused {
			if err == nil {
				t.Errorf("%s: applied, not refused:\n%s", vector.Name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s:\n%q\nwant\n%q", vector.Name, got, want)
		}
	}
}

// A reply holding every trace a client leaves, each a canary: after the rules none is there, nor the sender's offset,
// and the drawn boundaries and the id stand in their places.
func TestMailBurnerHeadersLeaveNoDeviceClientOrTimezoneTrace(t *testing.T) {
	canaries := []string{
		"canary-laptop-7c1", "192.0.2.77", "CanaryMail", "canary-mailer-9", "canary-x-trace", "Canary-Part-0042",
		"canary-client-id", "+0530",
	}
	message := "Received: from canary-laptop-7c1 ([192.0.2.77]) by localhost\r\n" +
		"From: shop@otter-4821.acme.root.example\r\n" +
		"To: orders@store.example\r\n" +
		"Subject: Re: order\r\n" +
		"Date: Wed, 02 Dec 2026 14:00:59 +0530\r\n" +
		"Message-ID: <canary-client-id@canary-laptop-7c1>\r\n" +
		"User-Agent: CanaryMail/3.0\r\n" +
		"X-Mailer: canary-mailer-9\r\n" +
		"X-Trace: canary-x-trace\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"Canary-Part-0042\"\r\n" +
		"\r\n" +
		"--Canary-Part-0042\r\nContent-Type: text/plain\r\n\r\nYes, please.\r\n" +
		"--Canary-Part-0042--\r\n"
	got, err := NewMailBurnerHeaders(nil).Apply([]byte(message), &MailBurnerHeadersArgs{
		MessageId: "q7vcs2xw5bm3y4n6p8r2t3u4v5@otter-4821.acme.root.example",
		Now:       time.UnixMilli(testMailIngestPushMillis),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range canaries {
		if strings.Contains(string(got), canary) {
			t.Errorf("a reply carries %q:\n%s", canary, got)
		}
	}
	for _, want := range []string{
		"Date: Wed, 02 Dec 2026 08:30:00 +0000\r\n",
		"Message-ID: <q7vcs2xw5bm3y4n6p8r2t3u4v5@otter-4821.acme.root.example>\r\n",
		"Yes, please.\r\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	// two applications draw two boundaries, so no boundary links two replies
	again, err := NewMailBurnerHeaders(nil).Apply([]byte(message), &MailBurnerHeadersArgs{
		MessageId: "q7vcs2xw5bm3y4n6p8r2t3u4v5@otter-4821.acme.root.example",
		Now:       time.UnixMilli(testMailIngestPushMillis),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(again) == string(got) {
		t.Fatal("two replies share a boundary")
	}
}
