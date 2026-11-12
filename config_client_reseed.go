//go:build !ios_extension

// A device's part in §7.9's site loss (TEAM-M3-02; D-TEAM-19, I-16, FS-41; §19.10): while api's reseed is on, each
// member device that is not read_only uploads what it keeps of the authorization log through POST
// /network/config/reseed, and api adopts the run that devices of two members agree on, never re-sequenced.
//
//	full tail  a desktop or CLI member device (ConfigClientSettings.RetainFullTail) uploads the Signed Genesis, every
//	           entry it keeps verbatim from the retention point, and the rows of its bases
//	pins       any other device uploads the genesis and its (k, A_k) pins from the retention point to its tip, which
//	           vouch for digests without bytes
//	re-seed    a config writer's device that has re-seeded the config repo adds its head's config_pushes from version 1,
//	           which api walks from C_0 before it writes the adopted run back
//
// A device the verified state shows read_only, tagged or ephemeral uploads nothing: api would count none of it. The
// upload is idempotent: api keeps each sidecar's newest, so a retry after a lost answer is the same upload. Nothing here
// signs, creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// This device may not upload: read_only, tagged, ephemeral, or not admitted at the state it follows.
var ErrConfigReseedNotUploader = errors.New("config reseed: this device uploads nothing")

// What a device uploads (POST /network/config/reseed's body).
type ConfigReseedUpload struct {
	SignedGenesis []byte
	// verbatim AuthEntry bytes in position order, a full tail's
	Entries [][]byte
	// the rows of each base among Entries
	Rows [][]byte
	// (k, A_k) for positions the device keeps no bytes of
	Pins []*bridge.AuthPin
	// a config writer's re-seeded head's Signed EvsPush of every version from 1
	ConfigPushes [][]byte
}

// What api answered.
type ConfigReseedAnswer struct {
	// the run adopted so far, nil while none is
	Tip *bridge.AuthPin
	// the position the log stops before, as no two members' devices agree on it; 0 for none
	StoppedAt uint64
	// the adopted run is written back, and the log resumes at its tip plus one
	Written bool
}

// Where a device uploads: SidecarApi.PostConfigReseed, or a test's fake api.
type ConfigReseedPoster interface {
	PostConfigReseed(ctx context.Context, upload *ConfigReseedUpload) (*ConfigReseedAnswer, error)
}

// The upload this device makes for sidecarId (see the file header), configPushes a re-seeding config writer's, nil for
// any other device.
func (self *ConfigClient) ReseedUpload(sidecarId Id, configPushes [][]byte) (*ConfigReseedUpload, error) {
	log := self.configLog.Load()
	if log == nil {
		return nil, ErrConfigClientClosed
	}
	state := log.State()
	row := state.SidecarRow(sidecarId)
	if row == nil || row.GetRevokedAt() != 0 || row.GetEphemeral() || len(row.GetTagIds()) != 0 || configRowReadOnly(row) {
		return nil, ErrConfigReseedNotUploader
	}
	if 0 < len(configPushes) && !state.IsConfigWriter(sidecarId) {
		return nil, fmt.Errorf("%w: only a config writer's device carries the re-seeded head", ErrConfigReseedNotUploader)
	}
	retained := log.Retained()
	upload := &ConfigReseedUpload{SignedGenesis: retained.SignedGenesis, ConfigPushes: configPushes}
	if self.settings.RetainFullTail {
		upload.Entries = retained.Entries
		rowsKeys := make([][sha256.Size]byte, 0, len(retained.Rows))
		for rowsSha256 := range retained.Rows {
			rowsKeys = append(rowsKeys, rowsSha256)
		}
		slices.SortFunc(rowsKeys, func(a [sha256.Size]byte, b [sha256.Size]byte) int { return bytes.Compare(a[:], b[:]) })
		for _, rowsSha256 := range rowsKeys {
			upload.Rows = append(upload.Rows, retained.Rows[rowsSha256])
		}
		return upload, nil
	}
	tip := state.Pin().GetVersion()
	for k := state.RetentionPoint(); k <= tip; k += 1 {
		if k == 0 {
			continue
		}
		chain, ok := state.chainAt(k)
		if !ok {
			continue
		}
		upload.Pins = append(upload.Pins, &bridge.AuthPin{Version: k, Chain: append([]byte{}, chain[:]...)})
	}
	return upload, nil
}

// Uploads what this device keeps (ReseedUpload) through poster and answers what api adopted so far.
func (self *ConfigClient) UploadReseed(ctx context.Context, poster ConfigReseedPoster, sidecarId Id, configPushes [][]byte) (*ConfigReseedAnswer, error) {
	if poster == nil {
		return nil, ErrConfigClientClosed
	}
	upload, err := self.ReseedUpload(sidecarId, configPushes)
	if err != nil {
		return nil, err
	}
	return poster.PostConfigReseed(ctx, upload)
}

// POST /network/config/reseed's body (server's model.ConfigReseedArgs reads alike).
type sidecarConfigReseedWire struct {
	Genesis      []byte                   `json:"genesis,omitempty"`
	Entries      [][]byte                 `json:"entries,omitempty"`
	Rows         [][]byte                 `json:"rows,omitempty"`
	Pins         []*sidecarConfigPinReply `json:"pins,omitempty"`
	ConfigPushes [][]byte                 `json:"config_pushes,omitempty"`
}

// Its answer.
type sidecarConfigReseedReply struct {
	Tip       *sidecarConfigPinReply `json:"tip,omitempty"`
	StoppedAt uint64                 `json:"stopped_at,omitempty"`
	Written   bool                   `json:"written,omitempty"`
}

var _ ConfigReseedPoster = (*SidecarApi)(nil)

// POST /network/config/reseed (§7.9's site loss): the upload, with the client's token as bearer. A refusal is a
// *SidecarApiError: 403 config_refused outside a restore, for a run that disagrees with the restored head, or a
// re-seeded head off the adopted run; 503 while the store or the restored head cannot be read.
func (self *SidecarApi) PostConfigReseed(ctx context.Context, upload *ConfigReseedUpload) (*ConfigReseedAnswer, error) {
	route := "POST /network/config/reseed"
	if upload == nil {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	wire := &sidecarConfigReseedWire{
		Genesis:      upload.SignedGenesis,
		Entries:      upload.Entries,
		Rows:         upload.Rows,
		ConfigPushes: upload.ConfigPushes,
	}
	for _, pin := range upload.Pins {
		wire.Pins = append(wire.Pins, &sidecarConfigPinReply{N: pin.GetVersion(), Chain: pin.GetChain()})
	}
	reply := &sidecarConfigReseedReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "config_reseed",
		method:    "POST",
		url:       self.settings.ApiUrl + "/network/config/reseed",
		bearer:    true,
	}, wire, reply)
	if err != nil {
		return nil, err
	}
	answer := &ConfigReseedAnswer{StoppedAt: reply.StoppedAt, Written: reply.Written}
	if reply.Tip != nil {
		if reply.Tip.N == 0 || len(reply.Tip.Chain) != 32 {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
		}
		answer.Tip = &bridge.AuthPin{Version: reply.Tip.N, Chain: reply.Tip.Chain}
	}
	return answer, nil
}
