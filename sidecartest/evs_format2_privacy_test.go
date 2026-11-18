//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Format 2's privacy capture on T2 (EVS2-M10-32; §22.7's canaries, R-EVS-5, R-EVS-12, I-2, FI-16, X2): canaries of 32
// random bytes in versionless contents, one past 16 KiB, a kind-5 upload, and one staged in its push's record; in their
// names; and in a git-lfs object put to ur/lfs, written by format-2 devices against evsservice's engine on the epoch
// world, with the kind-5 file written again and its replaced content purged. Every object of every cluster (records
// with their staged tails and purge lists, seg/, slots, and drops/ and dropscan/ where a drop wrote them), every Redis
// value ({evsd_} among them), every metric and hint, and every request a device sent evs, its path and its body, is
// scanned, and nothing is found. The scan's self-test: a canary put in the clear into a drops/ object, a dropscan/
// file and an {evsd_} value is found in each, so the scan reads format 2's families and does not pass them unread.
//
// On the desktop legs, where ur/lfs is built.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

// Content of size holding canary once, past its first kilobyte.
func format2PrivacyContent(canary []byte, size int) []byte {
	content := bytes.Repeat([]byte("format 2 privacy content; "), size/26+1)[:size]
	copy(content[1024:], canary)
	return content
}

// A world whose devices wrote format 2's constructs with canaries in them, and the capture that holds them.
func newFormat2PrivacyWorld(t *testing.T) (*epochWorld, *PrivacyCapture) {
	t.Helper()
	world := newVersionlessWorld(t)
	capture := NewPrivacyCapture()
	var requestLock sync.Mutex
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		body := []byte{}
		if request.Body != nil {
			read, err := io.ReadAll(request.Body)
			if err != nil {
				return err
			}
			request.Body.Close()
			request.Body = io.NopCloser(bytes.NewReader(read))
			body = read
		}
		requestLock.Lock()
		defer requestLock.Unlock()
		capture.Add(PrivacyClassHandler, "request "+request.Method+" "+request.URL.RequestURI(), append([]byte(request.URL.RequestURI()+"\x00"), body...))
		return nil
	})
	purger := world.startPurger()
	w := world.format2Device("w")
	directory := "notes-" + capture.CanaryText("format 2 directory name")
	big := directory + "/" + capture.CanaryText("format 2 file name") + ".bin"
	small := directory + "/staged-" + capture.CanaryText("format 2 staged name") + ".txt"
	if _, err := w.writeSetting(big, format2PrivacyContent(capture.Canary("format 2 kind-5 content"), 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the kind-5 write: %v", err)
	}
	if _, err := w.writeSetting(small, format2PrivacyContent(capture.Canary("format 2 staged content"), 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the staged write: %v", err)
	}
	if _, err := w.writeSetting(big, format2PrivacyContent(capture.Canary("format 2 replacing content"), 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the replacing write: %v", err)
	}
	if stats := world.purgeDue(purger); stats.DeletedCount != 1 {
		t.Fatalf("the purge deleted %d", stats.DeletedCount)
	}
	lfsContent := format2PrivacyContent(capture.Canary("format 2 git-lfs object"), 8*1024)
	if _, err := sidecar.NewEvsLfsStore(w.repo).Put(world.ctx, sidecar.EvsLfsOid(sha256.Sum256(lfsContent)), int64(len(lfsContent)), bytes.NewReader(lfsContent)); err != nil {
		t.Fatalf("the git-lfs object: %v", err)
	}
	world.setIntercept(nil)
	capture.AddSource(world.host.privacyItems)
	return world, capture
}

func TestEvsFormat2LeaksNothingEndToEnd(t *testing.T) {
	_, capture := newFormat2PrivacyWorld(t)
	for _, class := range []PrivacyClass{PrivacyClassHandler, PrivacyClassObject, PrivacyClassRedis} {
		if capture.ItemCount(class) == 0 {
			t.Errorf("the scan read nothing of %s", class)
		}
	}
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
}

// The scan's self-test: a canary in the clear in each of format 2's own families is found there.
func TestEvsFormat2PrivacyScanFindsALeakInEachFamily(t *testing.T) {
	world, capture := newFormat2PrivacyWorld(t)
	repoKey := sidecar.EvsKeyId(world.repoId)
	if _, err := world.cluster.PutIfNoneMatch(world.ctx, "drops/"+repoKey+"/leak", capture.Canary("format 2 drops leak"), nil); err != nil {
		t.Fatal(err)
	}
	segments, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := segments.PutIfNoneMatch(world.ctx, evsservice.DropFileKey(world.repoId, sidecar.Id{9}, evsservice.DropFileList, 0), capture.Canary("format 2 dropscan leak"), nil); err != nil {
		t.Fatal(err)
	}
	if err := world.host.Redis.Set(world.ctx, evsservice.DropHintKey(world.repoId), capture.Canary("format 2 evsd leak"), time.Hour); err != nil {
		t.Fatal(err)
	}
	findings := capture.Scan()
	for _, kind := range []string{"format 2 drops leak", "format 2 dropscan leak", "format 2 evsd leak"} {
		found := false
		for _, finding := range findings {
			found = found || strings.Contains(finding.String(), kind)
		}
		if !found {
			t.Errorf("the scan missed the %s", kind)
		}
	}
	if len(findings) != 3 {
		t.Fatalf("%d findings for three leaks: %v", len(findings), findings)
	}
}
