// The proofs' settings: the catalog of DESIGN-DETAILS 3.2.6 by name and capacity, the header block's cut
// (3.2.4) and a record's role by position (3.2.5).

package smtpproof

import (
	"slices"
	"testing"
)

// The eleven shapes, by the KeySet names 3.2.6 writes, in its order.
func TestProofSettingsHoldTheElevenShapes(t *testing.T) {
	settings := DefaultProofSettings()
	var names []string
	for _, shape := range settings.Shapes {
		names = append(names, shape.Name())
	}
	want := []string{
		"key-v0304-aes128gcm-c8", "key-v0304-chacha20-c2", "key-v0303-aes128gcm-c8",
		"env-aes128gcm-s40-c40", "msg-aes128gcm-s16-c4-h52", "hdr-aes128gcm-c2-r75", "body-aes128gcm-c2-b81",
		"env-chacha20-s19-c20", "msg-chacha20-s12-c2-h19", "hdr-chacha20-c1-r35", "body-chacha20-c2-b40",
	}
	if !slices.Equal(names, want) {
		t.Errorf("catalog %q", names)
	}
	// what 3.2.6 says each holds under 1.3, a record's type octet off
	for _, c := range []struct {
		kind   ShapeKind
		family ShapeFamily
		blocks func(shape *ShapeSettings) int
		holds  int
	}{
		{kind: ShapeKindMessage, family: ShapeFamilyAes128Gcm, blocks: func(shape *ShapeSettings) int { return shape.HeadBlocks }, holds: 831},
		{kind: ShapeKindHeader, family: ShapeFamilyAes128Gcm, blocks: func(shape *ShapeSettings) int { return shape.RestBlocks }, holds: 1199},
		{kind: ShapeKindBody, family: ShapeFamilyAes128Gcm, blocks: func(shape *ShapeSettings) int { return shape.BodyBlocks }, holds: 1295},
		{kind: ShapeKindMessage, family: ShapeFamilyChacha20, blocks: func(shape *ShapeSettings) int { return shape.HeadBlocks }, holds: 1215},
		{kind: ShapeKindHeader, family: ShapeFamilyChacha20, blocks: func(shape *ShapeSettings) int { return shape.RestBlocks }, holds: 2239},
		{kind: ShapeKindBody, family: ShapeFamilyChacha20, blocks: func(shape *ShapeSettings) int { return shape.BodyBlocks }, holds: 2559},
	} {
		shape := settings.shape(c.kind, c.family, 0)
		if holds := shape.recordContentBytes(c.blocks(shape), tlsVersion13); holds != c.holds {
			t.Errorf("%s holds %d octets, want %d", shape.Name(), holds, c.holds)
		}
		// 1.2 has no type octet: one more a record
		if holds := shape.recordContentBytes(c.blocks(shape), tlsVersion12); holds != c.holds+1 {
			t.Errorf("%s holds %d octets under 1.2", shape.Name(), holds)
		}
	}
	if settings.shape(ShapeKindKey, ShapeFamilyChacha20, tlsVersion12) != nil {
		t.Error("a ChaCha20 key shape for TLS 1.2, which has no such suite here")
	}
	if suiteFamily(tlsSuiteEcdheRsaAes128GcmSha256) != ShapeFamilyAes128Gcm || suiteFamily(tlsSuiteEcdheEcdsaAes128GcmSha256) != ShapeFamilyAes128Gcm ||
		suiteFamily(tlsSuiteAes128GcmSha256) != ShapeFamilyAes128Gcm || suiteFamily(tlsSuiteChacha20Poly1305Sha256) != ShapeFamilyChacha20 {
		t.Error("a suite in the wrong family")
	}
}

// 3.2.4's split, by length alone: the head, then rests, the last moved up to its minimum; every cut is one
// the edge accepts, and the record counts are 3.2.6's.
func TestHeaderSplitCutsByLengthAlone(t *testing.T) {
	settings := DefaultProofSettings()
	for _, c := range []struct {
		length  int
		family  ShapeFamily
		version uint16
		want    []int
	}{
		{length: 4, family: ShapeFamilyAes128Gcm, version: tlsVersion13, want: []int{4}},
		{length: 831, family: ShapeFamilyAes128Gcm, version: tlsVersion13, want: []int{831}},
		{length: 832, family: ShapeFamilyAes128Gcm, version: tlsVersion13, want: []int{828, 4}},
		{length: 832, family: ShapeFamilyAes128Gcm, version: tlsVersion12, want: []int{832}},
		{length: 4095, family: ShapeFamilyAes128Gcm, version: tlsVersion13, want: []int{831, 1199, 1199, 866}},
		{length: 4095, family: ShapeFamilyChacha20, version: tlsVersion13, want: []int{1215, 2239, 641}},
		{length: 2032, family: ShapeFamilyAes128Gcm, version: tlsVersion13, want: []int{831, 1197, 4}},
	} {
		sizes, err := settings.headerSplit(c.length, c.family, c.version)
		if err != nil || !slices.Equal(sizes, c.want) {
			t.Errorf("%d octets, %s, %04x: %v, %v", c.length, c.family, c.version, sizes, err)
		}
	}
	// every length a header block may have cuts to records the edge accepts, as many as 3.2.6 counts
	for _, family := range []ShapeFamily{ShapeFamilyAes128Gcm, ShapeFamilyChacha20} {
		for _, version := range []uint16{tlsVersion13, tlsVersion12} {
			if family == ShapeFamilyChacha20 && version == tlsVersion12 {
				continue
			}
			head := settings.shape(ShapeKindMessage, family, 0)
			rest := settings.shape(ShapeKindHeader, family, 0)
			headBytes := head.recordContentBytes(head.HeadBlocks, version)
			restBytes := rest.recordContentBytes(rest.RestBlocks, version)
			for length := settings.HeaderLastRecordMinByteCount; length <= settings.HeaderBlockMaxByteCount; length += 1 {
				sizes, err := settings.headerSplit(length, family, version)
				if err != nil {
					t.Fatalf("%d octets: %v", length, err)
				}
				sum := 0
				for _, size := range sizes {
					sum += size
				}
				records := 1 + (max(0, length-headBytes)+restBytes-1)/restBytes
				if sum != length || !settings.headerCutAccepted(sizes) || len(sizes) != records {
					t.Fatalf("%s %04x, %d octets: %v", family, version, length, sizes)
				}
			}
		}
	}
	for _, length := range []int{0, 3, settings.HeaderBlockMaxByteCount + 1} {
		if _, err := settings.headerSplit(length, ShapeFamilyAes128Gcm, tlsVersion13); err == nil {
			t.Errorf("%d octets cut", length)
		}
	}
}

// The edge's rule for a cut it did not make: a record of 127 octets that is not the last is refused, so
// no literal straddles two boundaries; a last record under 4 octets is too.
func TestHeaderCutsTheEdgeRefuses(t *testing.T) {
	settings := DefaultProofSettings()
	for _, c := range []struct {
		sizes    []int
		accepted bool
	}{
		{sizes: []int{128, 4}, accepted: true},
		{sizes: []int{127, 4}},
		{sizes: []int{128, 127, 4}},
		{sizes: []int{128, 3}},
		{sizes: []int{4}, accepted: true},
		{sizes: nil},
		{sizes: slices.Repeat([]int{128}, 17)},
	} {
		if accepted := settings.headerCutAccepted(c.sizes); accepted != c.accepted {
			t.Errorf("%v: accepted %t", c.sizes, accepted)
		}
	}
}

// 3.2.5's table: a record's role is its position, from f, and the header block's record count once named.
func TestRecordRoleAtFollowsPosition(t *testing.T) {
	for _, mode := range []uint32{partModeBdat, partModeData} {
		want := []recordRole{recordRoleEhlo, recordRoleMail, recordRoleRcpt, recordRoleRcpt, recordRoleBdat, recordRoleHeaderBlock, recordRoleHeaderBlock, recordRoleHeaderBlock, recordRoleBody, recordRoleBody}
		if mode == partModeData {
			want[4] = recordRoleData
		}
		for offset, role := range want {
			got, err := recordRoleAt(uint64(offset), 2, mode, 3)
			if err != nil || got != role {
				t.Errorf("mode %d offset %d: %d, %v", mode, offset, got, err)
			}
		}
		// past the envelope, nothing has a role until the count is named
		if _, err := recordRoleAt(5, 2, mode, 0); err == nil {
			t.Errorf("mode %d: a header record before its count", mode)
		}
		if role, err := recordRoleAt(4, 2, mode, 0); err != nil || (role != recordRoleBdat && role != recordRoleData) {
			t.Errorf("mode %d: the command at the envelope's end: %d, %v", mode, role, err)
		}
	}
	if _, err := recordRoleAt(4, 2, partModeNone, 3); err == nil {
		t.Error("a record at the envelope's end with no mode")
	}
	if _, err := recordRoleAt(0, 0, partModeBdat, 1); err == nil {
		t.Error("a transaction with no recipient")
	}
}
