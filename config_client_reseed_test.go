//go:build !ios_extension

// A device's site-loss upload (config_client_reseed.go; TEAM-M3-02, FS-41): a full tail's entries and rows, a phone's
// pins, a config writer's re-seeded head, and nothing from a read_only device or a non-writer's re-seed.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An api that keeps what each upload carried.
type testConfigReseedPoster struct {
	uploads []*ConfigReseedUpload
}

func (self *testConfigReseedPoster) PostConfigReseed(ctx context.Context, upload *ConfigReseedUpload) (*ConfigReseedAnswer, error) {
	self.uploads = append(self.uploads, upload)
	return &ConfigReseedAnswer{}, nil
}

// A desktop member device uploads the genesis, every entry it keeps verbatim and the rows of its bases; a config
// writer's device adds its re-seeded head's pushes; the uploads verify as a cold gate starts, at the net's tip.
func TestConfigClientUploadsItsFullTail(t *testing.T) {
	world := newTestConfigClientWorld(t)
	world.net.admitMemberDevice("member")
	world.publish()
	settings := DefaultConfigClientSettings()
	settings.RetainFullTail = true
	client := world.client(settings)
	world.caughtUp(client)

	poster := &testConfigReseedPoster{}
	pushes := [][]byte{[]byte("a re-seeded head's push")}
	if _, err := client.UploadReseed(context.Background(), poster, world.net.owner.sidecarId, pushes); err != nil {
		t.Fatal(err)
	}
	upload := poster.uploads[0]
	if !bytes.Equal(upload.SignedGenesis, world.net.signedGenesis) || len(upload.Pins) != 0 || len(upload.ConfigPushes) != 1 {
		t.Fatalf("the upload: %d pins, %d pushes", len(upload.Pins), len(upload.ConfigPushes))
	}
	retained := &ConfigRetained{SignedGenesis: upload.SignedGenesis, Entries: upload.Entries, Rows: map[[32]byte][]byte{}}
	for _, rowsBytes := range upload.Rows {
		retained.Rows[sha256.Sum256(rowsBytes)] = rowsBytes
	}
	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, world.net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatalf("the upload as a cold gate: %v", err)
	}
	if gate.Pin().GetVersion() != world.net.n {
		t.Fatalf("the upload ends at %d, the net at %d", gate.Pin().GetVersion(), world.net.n)
	}
}

// A phone, which keeps no full tail, uploads its pins from the retention point to its tip, each the net's own.
func TestConfigClientUploadsAPhonesPins(t *testing.T) {
	world := newTestConfigClientWorld(t)
	world.net.admitMemberDevice("member")
	world.publish()
	client := world.client(nil)
	state := world.caughtUp(client)

	upload, err := client.ReseedUpload(world.net.owner.sidecarId, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(upload.Entries) != 0 || len(upload.Pins) == 0 {
		t.Fatalf("a phone's upload: %d entries, %d pins", len(upload.Entries), len(upload.Pins))
	}
	for _, pin := range upload.Pins {
		if !state.OnChain(pin) {
			t.Errorf("pin %d is not on the net's chain", pin.GetVersion())
		}
	}
	if last := upload.Pins[len(upload.Pins)-1]; last.GetVersion() != world.net.n {
		t.Errorf("the pins end at %d, the tip is %d", last.GetVersion(), world.net.n)
	}
}

// A read_only device uploads nothing, nor does one the state never admitted, and only a config writer's device carries
// a re-seeded head.
func TestConfigClientUploadRefusals(t *testing.T) {
	world := newTestConfigClientWorld(t)
	member := world.net.admitMemberDevice("member")
	readOnly := world.net.device("member page worker", member.memberId)
	world.net.admitDevice(world.net.owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)

	for name, sidecarId := range map[string]Id{
		"a read_only device": readOnly.sidecarId,
		"a stranger":         testConfigId("stranger"),
	} {
		if _, err := client.ReseedUpload(sidecarId, nil); !errors.Is(err, ErrConfigReseedNotUploader) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := client.ReseedUpload(member.sidecarId, [][]byte{[]byte("push")}); !errors.Is(err, ErrConfigReseedNotUploader) {
		t.Errorf("a member's device carrying a re-seeded head: %v", err)
	}
	if _, err := client.ReseedUpload(member.sidecarId, nil); err != nil {
		t.Errorf("a member's device: %v", err)
	}
}
