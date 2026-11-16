// What the engine's external tests share: documentation names and addresses, the tiers' limits, and
// settings for an edge in an MX world.

package smtpedgeservice_test

import (
	"bytes"
	"net/netip"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

const (
	testRoot            = "root.example"
	testHeloName        = "o1.out.root.example"
	testRecipientDomain = "dest.example"
	testMxHost          = "mx1.dest.example"
	// 26 lowercase base32 characters, a report_token's form (plan-SMTP-net-token)
	testReportToken = "abcdefghijklmnopqrstuvwxyz"
	testSelector    = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	testLabel       = "n1"
)

var (
	testSendingAddress = netip.MustParseAddr("192.0.2.10")
	testMxAddress      = netip.MustParseAddr("192.0.2.25")
	// the X-UR-Ref key the tests' edges hold, 32 synthetic octets
	testXUrRefKey = &smtpedgeservice.SmtpXUrRefKey{KeyId: 1, Key: bytes.Repeat([]byte{0x5a}, 32)}
)

// Pro's smtp_* numbers and the sidecar_abuse: ones (§20.4).
func proLimits() *sidecar.QuotaLimits {
	return &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{
		smtpedgeservice.SmtpLimitConnectionsPerDay:             200,
		smtpedgeservice.SmtpLimitBytesPerDay:                   1024 * 1024 * 1024,
		smtpedgeservice.SmtpLimitRecipientsPerMessage:          50,
		smtpedgeservice.SmtpLimitRecipientsPerDay:              1000,
		smtpedgeservice.SmtpLimitMessageBytes:                  25 * 1024 * 1024,
		smtpedgeservice.SmtpLimitBurst:                         50,
		smtpedgeservice.SmtpLimitBurstWindow:                   (10 * time.Minute).Milliseconds(),
		smtpedgeservice.SmtpLimitConcurrentConnections:         4,
		smtpedgeservice.SmtpLimitCommunityConnectionsPerHour:   500,
		smtpedgeservice.SmtpLimitCommunityMedianMultiple:       3,
		smtpedgeservice.SmtpLimitDestinationConnectionsPerHour: 200,
		smtpedgeservice.SmtpLimitDestinationConcurrency:        10,
	}}
}

// Community's: 5 a day, 5 recipients a message, 25 a day, 5 a burst of 10 min, one at a time.
func communityLimits() *sidecar.QuotaLimits {
	limits := proLimits()
	limits.Tier = "free"
	limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] = 5
	limits.Limits[smtpedgeservice.SmtpLimitBytesPerDay] = 5 * 1024 * 1024
	limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerMessage] = 5
	limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerDay] = 25
	limits.Limits[smtpedgeservice.SmtpLimitMessageBytes] = 5 * 1024 * 1024
	limits.Limits[smtpedgeservice.SmtpLimitBurst] = 5
	limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 1
	return limits
}

// Settings for an edge in the MX world: documentation names, one sending address, an X-UR-Ref key, and
// 192.0.2.0/24 and 203.0.113.0/24 dialable, while 198.51.100.0/24 stands for what the edge never dials.
func worldSettings() *smtpedgeservice.SmtpEdgeSettings {
	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	settings.Root = testRoot
	settings.ReportHostName = "rpt.root.example"
	settings.SendingAddresses = []smtpedgeservice.SmtpSendingAddress{{Address: testSendingAddress, HeloName: testHeloName}}
	settings.XUrRefKeys = []*smtpedgeservice.SmtpXUrRefKey{testXUrRefKey}
	settings.MxRefusedPrefixes = slices.DeleteFunc(settings.MxRefusedPrefixes, func(prefix netip.Prefix) bool {
		return prefix == netip.MustParsePrefix("192.0.2.0/24") || prefix == netip.MustParsePrefix("203.0.113.0/24")
	})
	return settings
}
