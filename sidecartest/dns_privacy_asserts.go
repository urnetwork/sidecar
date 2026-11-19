// The test that shows §22.7's synthesized-dmarc row, which DNS-M5-11 owns (TEST-M2-10's registry): no _dmarc record
// dns synthesizes carries ruf, fo or a rua into <root>, over every system record set with mail off and on, and a
// report host inside the root refused. The test is server's, in model's dns_system_records_model_test.go; M5's sweep
// found the row with nothing registered to it (TEST-M5-02), so the registration sits here beside the registry. It names
// the pending groups' tag, which every gate entry in server's model carries, though the test reads no table.

package sidecartest

var _ = RegisterPrivacyAssert("synthesized-dmarc", &PrivacyAssertTest{Repo: "server", Package: "github.com/urnetwork/server/model", Name: "TestDnsSystemDmarcNeverReportsIntoTheRoot", Tags: "sidecar_pending"})
