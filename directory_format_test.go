// directory_format.go's values: a repo item's announcement_id and every path as fixed vectors, computed apart from
// this code; each path's ids in lowercase hex under the shard of their own text; a request target naming exactly one
// thing and the roles it may ask; expiry by kind and the withdrawn state's kinds; repo announce entries padding alike
// to 2,048 B; and a notice of two decisions at their widest within its 256 B.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// SHA-256("urnetwork-sidecar-v1/directory-repo" || 16 x 0x33)[:16], and each path for fixed ids, computed by a program
// that reads only the rules.
func TestDirectoryRepoAnnouncementIdVector(t *testing.T) {
	repoId := Id(bytes.Repeat([]byte{0x33}, 16))
	announcementId := DirectoryRepoAnnouncementId(repoId)
	if hex.EncodeToString(announcementId[:]) != "4618a1b4e46657fa62d7696888d22dcd" {
		t.Errorf("announcement_id %x", announcementId)
	}
	if DirectoryRepoAnnouncementId(NewId()) == announcementId {
		t.Error("another repo takes the same id")
	}
}

func TestDirectoryPathVectors(t *testing.T) {
	sidecarId := Id(bytes.Repeat([]byte{0x22}, 16))
	repoId := Id(bytes.Repeat([]byte{0x33}, 16))
	requestId := Id(bytes.Repeat([]byte{0x44}, 16))
	if path := DirectoryCardPath(sidecarId); path != "d/0d/22222222222222222222222222222222" {
		t.Errorf("card %s", path)
	}
	if path := DirectoryRepoPath(repoId); path != "r/de/33333333333333333333333333333333" {
		t.Errorf("repo file %s", path)
	}
	for _, c := range []struct {
		target *protocol.RequestTarget
		want   string
	}{
		{
			target: &protocol.RequestTarget{RepoId: repoId.Bytes()},
			want:   "q/de/33333333333333333333333333333333/44444444444444444444444444444444",
		},
		{
			target: &protocol.RequestTarget{SidecarId: sidecarId.Bytes(), TcpPorts: []uint32{22}},
			want:   "q/0d/22222222222222222222222222222222/44444444444444444444444444444444",
		},
		{
			target: &protocol.RequestTarget{SocketToken: bytes.Repeat([]byte{0x55}, 32)},
			want:   "q/d6/84126d0dd850199be29021aadbaee68c/44444444444444444444444444444444",
		},
	} {
		path, err := DirectoryNoticePath(c.target, requestId)
		if err != nil {
			t.Fatal(err)
		}
		if path != c.want {
			t.Errorf("notice %s, want %s", path, c.want)
		}
		prefix, err := DirectoryNoticePrefix(c.target)
		if err != nil || prefix+hex.EncodeToString(requestId[:]) != path {
			t.Errorf("prefix %s is not the notice's: %v", prefix, err)
		}
	}
}

// Every id in a path is 32 lowercase hex, never the dashed form, under <h>, the first byte of SHA-256 of that text.
func TestDirectoryPathsShardTheirOwnHex(t *testing.T) {
	for range 64 {
		id := NewId()
		text := hex.EncodeToString(id[:])
		sum := sha256.Sum256([]byte(text))
		shard := hex.EncodeToString(sum[:1])
		requestId := NewId()
		notice, err := DirectoryNoticePath(&protocol.RequestTarget{RepoId: id.Bytes()}, requestId)
		if err != nil {
			t.Fatal(err)
		}
		for prefix, path := range map[string]string{
			"d/": DirectoryCardPath(id), "r/": DirectoryRepoPath(id), "q/": strings.TrimSuffix(notice, "/"+hex.EncodeToString(requestId[:])),
		} {
			if path != prefix+shard+"/"+text {
				t.Fatalf("%s for %s", path, id)
			}
			if strings.Contains(path, "-") || strings.ToLower(path) != path {
				t.Fatalf("%s is not lowercase hex", path)
			}
		}
	}
}

// A request target names exactly one of a repo, a worker and a socket, each at its length, and only a worker takes
// ports; whatever does not is refused, by every path function too.
func TestDirectoryRequestTargetNamesExactlyOne(t *testing.T) {
	id := NewId().Bytes()
	accepted := map[DirectoryTargetKind]*protocol.RequestTarget{
		DirectoryTargetKindRepo:   {RepoId: id},
		DirectoryTargetKindWorker: {SidecarId: id, TcpPorts: []uint32{22, 443}},
		DirectoryTargetKindSocket: {SocketToken: bytes.Repeat([]byte{0x01}, 8*16)},
	}
	for want, target := range accepted {
		if kind, err := DirectoryRequestTargetKind(target); err != nil || kind != want {
			t.Errorf("%v: %d, %v", target, kind, err)
		}
	}
	refused := map[string]*protocol.RequestTarget{
		"nothing":                   nil,
		"an empty target":           {},
		"a repo and a worker":       {RepoId: id, SidecarId: id},
		"a worker and a socket":     {SidecarId: id, SocketToken: bytes.Repeat([]byte{0x01}, 16)},
		"a short repo id":           {RepoId: id[:15]},
		"a long worker id":          {SidecarId: append(bytes.Clone(id), 0)},
		"a token off its segments":  {SocketToken: bytes.Repeat([]byte{0x01}, 17)},
		"a token of nine segments":  {SocketToken: bytes.Repeat([]byte{0x01}, 9*16)},
		"ports on a repo":           {RepoId: id, TcpPorts: []uint32{22}},
		"ports on a socket":         {SocketToken: bytes.Repeat([]byte{0x01}, 16), TcpPorts: []uint32{22}},
		"ports alone, with no host": {TcpPorts: []uint32{22}},
	}
	for name, target := range refused {
		if _, err := DirectoryRequestTargetKind(target); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := DirectoryNoticePath(target, NewId()); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("%s: a notice path: %v", name, err)
		}
	}
}

// plan-RECORD-small-readings#4: a repo request asks RepoGrantRole's deposit, reader or writer, a worker or socket
// request AclAction's dial, and 0 is refused everywhere; a repo item offers RepoGrantRole's roles alone.
func TestDirectoryRolesTakeTheirEnums(t *testing.T) {
	id := NewId().Bytes()
	repo := &protocol.RequestTarget{RepoId: id}
	worker := &protocol.RequestTarget{SidecarId: id}
	socket := &protocol.RequestTarget{SocketToken: bytes.Repeat([]byte{0x01}, 16)}
	for _, c := range []struct {
		target *protocol.RequestTarget
		role   uint32
		want   bool
	}{
		{target: repo, role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT), want: true},
		{target: repo, role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER), want: true},
		{target: repo, role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER), want: true},
		{target: repo, role: 0, want: false},
		{target: repo, role: 4, want: false},
		{target: worker, role: uint32(protocol.AclAction_ACL_ACTION_DIAL), want: true},
		{target: worker, role: uint32(protocol.AclAction_ACL_ACTION_LISTEN), want: false},
		{target: worker, role: 0, want: false},
		{target: socket, role: uint32(protocol.AclAction_ACL_ACTION_DIAL), want: true},
		{target: socket, role: uint32(protocol.AclAction_ACL_ACTION_READ), want: false},
		{target: &protocol.RequestTarget{}, role: uint32(protocol.AclAction_ACL_ACTION_DIAL), want: false},
	} {
		kind, _ := DirectoryRequestTargetKind(c.target)
		if got := DirectoryRequestRoleAllowed(c.target, c.role); got != c.want {
			t.Errorf("target kind %d, role %d: %t", kind, c.role, got)
		}
	}
	for role := uint32(0); role < 8; role += 1 {
		if got, want := DirectoryOfferedRoleAllowed(role), 1 <= role && role <= 3; got != want {
			t.Errorf("offering role %d: %t", role, got)
		}
	}
}

// §16.11's expire row: a run's item lapses 90 min after its renewal and a worker's 26 h after, and a repo item never;
// a state's kinds as plan-RECORD-m6-carrier#1 has them, withdrawn for runs and workers alone.
func TestDirectoryAnnouncementExpiryAndStates(t *testing.T) {
	const renewedMillis = 1762387200000
	for _, c := range []struct {
		kind DirectoryAnnouncementKind
		want int64
	}{
		{kind: DirectoryAnnouncementKindRun, want: renewedMillis + 90*60*1000},
		{kind: DirectoryAnnouncementKindWorker, want: renewedMillis + 26*60*60*1000},
		{kind: DirectoryAnnouncementKindRepo, want: 0},
	} {
		if got, ok := DirectoryAnnouncementExpiresMillis(c.kind, renewedMillis); !ok || got != c.want {
			t.Errorf("kind %d expires %d", c.kind, got)
		}
	}
	for _, kind := range []DirectoryAnnouncementKind{0, 4} {
		if _, ok := DirectoryAnnouncementExpiresMillis(kind, renewedMillis); ok || kind.Known() {
			t.Errorf("kind %d has an expiry", kind)
		}
	}
	for _, c := range []struct {
		state DirectoryAnnouncementState
		kind  DirectoryAnnouncementKind
		want  bool
	}{
		{state: DirectoryAnnouncementStateActive, kind: DirectoryAnnouncementKindRepo, want: true},
		{state: DirectoryAnnouncementStateHandedOff, kind: DirectoryAnnouncementKindRun, want: true},
		{state: DirectoryAnnouncementStateWithdrawn, kind: DirectoryAnnouncementKindRun, want: true},
		{state: DirectoryAnnouncementStateWithdrawn, kind: DirectoryAnnouncementKindWorker, want: true},
		{state: DirectoryAnnouncementStateWithdrawn, kind: DirectoryAnnouncementKindRepo, want: false},
		{state: 0, kind: DirectoryAnnouncementKindRun, want: false},
		{state: 5, kind: DirectoryAnnouncementKindRun, want: false},
		{state: DirectoryAnnouncementStateEnded, kind: 0, want: false},
	} {
		if got := c.state.KnownFor(c.kind); got != c.want {
			t.Errorf("state %d for kind %d: %t", c.state, c.kind, got)
		}
	}
}

// A repo item at every cap, and a private marker holding only who, repo_id, repo_kind and requests.
func testDirectoryRepoItems() map[string]*protocol.Announcement {
	repoId := Id(bytes.Repeat([]byte{0x33}, 16))
	announcementId := DirectoryRepoAnnouncementId(repoId)
	who := &protocol.AnnounceWho{
		MemberId:    bytes.Repeat([]byte{0x66}, 16),
		SidecarId:   bytes.Repeat([]byte{0x22}, 16),
		MemberLabel: strings.Repeat("m", 64),
	}
	topics := []string{}
	for range 8 {
		topics = append(topics, strings.Repeat("t", 32))
	}
	return map[string]*protocol.Announcement{
		"a full item": {
			AnnouncementId: announcementId[:],
			Kind:           uint32(DirectoryAnnouncementKindRepo),
			Version:        math.MaxUint64,
			StartedMillis:  math.MaxInt64,
			RenewedMillis:  math.MaxInt64,
			State:          uint32(DirectoryAnnouncementStateActive),
			Who:            who,
			What: &protocol.AnnounceWhat{
				Title:       strings.Repeat("n", 128),
				Description: strings.Repeat("d", 512),
				Requests:    uint32(DirectoryRequestsOpen),
				Topics:      topics,
				RepoKind:    math.MaxUint32,
				Roles:       []uint32{1, 2, 3},
			},
			Where: &protocol.AnnounceWhere{RepoId: repoId.Bytes(), HostLabel: strings.Repeat("h", 64)},
		},
		"a private marker": {
			AnnouncementId: announcementId[:],
			Kind:           uint32(DirectoryAnnouncementKindRepo),
			Version:        1,
			State:          uint32(DirectoryAnnouncementStateActive),
			Who:            who,
			What:           &protocol.AnnounceWhat{Requests: uint32(DirectoryRequestsClosed), RepoKind: 1},
			Where:          &protocol.AnnounceWhere{RepoId: repoId.Bytes(), Private: true},
		},
	}
}

// plan-RECORD-m6-carrier#2: an announcement and a private marker both marshal to exactly 2,048 B once padded, so evs
// cannot tell them apart; the pad is zero bytes, parses back, and pads again to the same size; a body that leaves the
// pad no room goes on to the next multiple; and a run or worker item is refused.
func TestDirectoryRepoEntriesPadAlike(t *testing.T) {
	for name, item := range testDirectoryRepoItems() {
		unpadded := proto.Size(item)
		size, err := DirectoryPadRepoAnnouncement(item)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if size != DirectoryRepoEntryStepByteCount || len(encoded) != size {
			t.Errorf("%s of %d bytes padded to %d, marshaled %d", name, unpadded, size, len(encoded))
		}
		if !bytes.Equal(item.GetPad(), make([]byte, len(item.GetPad()))) {
			t.Errorf("%s's pad is not zero bytes", name)
		}
		parsed := &protocol.Announcement{}
		if err := proto.Unmarshal(encoded, parsed); err != nil || !proto.Equal(parsed, item) {
			t.Errorf("%s did not parse back: %v", name, err)
		}
		if again, err := DirectoryPadRepoAnnouncement(item); err != nil || again != size {
			t.Errorf("%s padded again to %d: %v", name, again, err)
		}
	}

	// each unpadded size around a step: the pad takes at least its tag, a length and one byte, so the size is the
	// first multiple with room for that, except where the room is exactly 130 B, which a one-byte length leaves one
	// byte short and a two-byte length one byte over, and which goes on to the multiple after
	marker := testDirectoryRepoItems()["a private marker"]
	gapCount := 0
	for extra := 1700; extra < 2100; extra += 1 {
		marker.What.Description = strings.Repeat("d", extra)
		marker.Pad = nil
		unpadded := proto.Size(marker)
		size, err := DirectoryPadRepoAnnouncement(marker)
		if err != nil {
			t.Fatal(err)
		}
		want := (unpadded + 3 + DirectoryRepoEntryStepByteCount - 1) / DirectoryRepoEntryStepByteCount * DirectoryRepoEntryStepByteCount
		if want-unpadded == 130 {
			want += DirectoryRepoEntryStepByteCount
			gapCount += 1
		}
		if size != want || proto.Size(marker) != size || len(marker.GetPad()) == 0 {
			t.Fatalf("%d bytes unpadded padded to %d, want %d", unpadded, size, want)
		}
	}
	if gapCount != 1 {
		t.Errorf("the sizes crossed the 130 B room %d times", gapCount)
	}

	for _, kind := range []DirectoryAnnouncementKind{DirectoryAnnouncementKindRun, DirectoryAnnouncementKindWorker, 0} {
		if _, err := DirectoryPadRepoAnnouncement(&protocol.Announcement{Kind: uint32(kind)}); !errors.Is(err, ErrDirectoryFormatInvalid) {
			t.Errorf("kind %d padded: %v", kind, err)
		}
	}
	if _, err := DirectoryPadRepoAnnouncement(nil); !errors.Is(err, ErrDirectoryFormatInvalid) {
		t.Errorf("nothing padded: %v", err)
	}
}

// §16.11: a notice naming its rule's two approvals, every field at its widest, stays within its 256 B.
func TestDirectoryNoticeOfTwoDecisionsFitsItsByteCount(t *testing.T) {
	decision := func(fill byte) *protocol.DecisionRef {
		return &protocol.DecisionRef{
			DeciderSidecarId: bytes.Repeat([]byte{fill}, 16),
			Seq:              math.MaxUint64,
			HeaderSha256:     bytes.Repeat([]byte{fill}, 32),
		}
	}
	notice := &protocol.DirectoryNotice{
		RequestId:          bytes.Repeat([]byte{0xff}, 16),
		RequesterSidecarId: bytes.Repeat([]byte{0xff}, 16),
		EntrySeq:           math.MaxUint64,
		NotAfterMillis:     math.MinInt64,
		State:              math.MaxUint32,
		Outcome:            math.MaxUint32,
	}
	for index := range DirectoryNoticeDecisionCount {
		notice.Decisions = append(notice.Decisions, decision(byte(index+1)))
	}
	if size := proto.Size(notice); DirectoryNoticeByteCount < size {
		t.Errorf("a notice of %d bytes", size)
	}
}
