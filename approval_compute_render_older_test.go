//go:build !ios_extension && !js

package sidecar

// CACL-M12-02: version 5's render leaves versions 1 to 4 as they were. Each golden in testdata/approval_compute/render/
// whose name starts older_ was written by the render before version 5's landed, so a byte that moves fails here.
// Synthetic values only.

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Rewrites testdata/approval_compute/render/'s goldens from the render as it stands.
var testUpdateApprovalComputeRender = flag.Bool("update-approval-compute-render", false, "rewrite testdata/approval_compute/render/")

// The directory of the render's goldens.
const testApprovalComputeRenderDir = "testdata/approval_compute/render"

// Holds text to the golden name, or writes it under -update-approval-compute-render.
func testApprovalComputeRenderGolden(t *testing.T, name string, text string) {
	t.Helper()
	path := filepath.Join(testApprovalComputeRenderDir, name+".txt")
	if *testUpdateApprovalComputeRender {
		if err := os.MkdirAll(testApprovalComputeRenderDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run with -update-approval-compute-render to write it)", name, err)
	}
	if string(golden) != text {
		t.Errorf("%s's render moved:\n%s\nwant:\n%s", name, text, golden)
	}
}

// The renders of versions 1, 3 and 4, a detail opened and not, are the goldens written before version 5's render.
func TestRenderOlderVersionsUnchanged(t *testing.T) {
	for _, item := range []struct {
		name   string
		action *protocol.CanonicalAction
		detail *protocol.CanonicalActionDetail
	}{
		{name: "older_v1_dns_set", action: testRecordDnsAction()},
		{name: "older_v3_access_request_opened", action: testRecordAccessRequestAction(), detail: testRecordAccessRequestDetail()},
		{name: "older_v3_access_request_sealed", action: testRecordAccessRequestAction()},
		{name: "older_v4_forward_opened", action: testRecordSealedGrantAction(), detail: testForwardDetail()},
	} {
		request, err := ParseStoredApprovalRequest(testRecordStored(t, testRecordRequest(t, testRecordStored(t, item.action))))
		if err != nil {
			t.Fatalf("%s: %v", item.name, err)
		}
		testApprovalComputeRenderGolden(t, item.name, RenderApprovalRequestDetail(request, item.detail).Text())
	}
}
