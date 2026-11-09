// §10.5's readerkey row at gkm (D-KEYS-25, D-KEYS-26): POST /gkm/reader-key, GET /gkm/reader-key/<sidecar_id> and
// POST /gkm/reader-keys, over gkm/rk/<sidecar_id> on the first cluster, which holds one sidecar's current ReaderKey,
// a Signed, purpose reader-key.
//
//   - An upload is the token's own sidecar's record: the ReaderKey's sidecar_id is the token's ur_sidecar_id, signed
//     by the identity key the log admits for that sidecar, with time < not_after <= time + 7 days + 10 min at gkm's
//     clock, from a sidecar admitted and not revoked, parked or suspended. A parked device's waits for its lift
//     (FS-106): it is refused until then, and the device's upkeep sends it again.
//   - At most once per 24 h per sidecar after its first, read from the stored object's write time, with no counter
//     (plan-KEYS-rate-counters keeps this rule exact). The same bytes again answer 200, so a retry after a lost
//     answer is safe.
//   - Reads serve the stored bytes as they are, a public record: gkm proves nothing by serving one, and a sealer
//     checks it before sealing to it (§10.5's readerkey row).

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §10.14's bound on one POST /gkm/reader-keys (QD-066): a format value.
const gkmReaderKeysMaxCount = 256

// The most a ReaderKey's Signed takes: 1,216 B of X-Wing key, a signature and the fields, well under this.
const gkmReaderKeyMaxByteCount = 4 * 1024

// POST /gkm/reader-key: the token's own sidecar's new ReaderKey.
func (self *GkmEngine) serveReaderKeyUpload(request *GkmRequest) {
	body, ok := request.ReadBody(gkmReaderKeyMaxByteCount)
	if !ok {
		return
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(body, signed); err != nil {
		request.BadRequest()
		return
	}
	now := request.Now()
	if _, err := sidecar.CheckGkmReaderKey(signed, request.SidecarId, request.Sidecar.IdentityPublicKey, now.UnixMilli()); err != nil {
		// another sidecar's record, another key's signature, or a validity out of §10.5's window
		request.Forbidden()
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	key := GkmReaderKeyKey(request.SidecarId)
	// what stands at the key: equal bytes are this upload's retry, and other bytes newer than a day refuse it
	judge := func() (done bool, etag string) {
		held, info, err := readGkmObject(request.Ctx, cluster, key, gkmReaderKeyMaxByteCount)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			return false, ""
		case err != nil:
			self.answerStoreError(request, err)
			return true, ""
		case bytes.Equal(held, body):
			request.Reply(nil)
			return true, ""
		}
		if next := info.LastModified.Add(self.settings.ReaderKeyUploadInterval); now.Before(next) {
			request.TooManyRequests(next.Sub(now))
			return true, ""
		}
		return false, info.Etag
	}
	done, etag := judge()
	if done {
		return
	}
	err = replaceGkmObject(request.Ctx, cluster, key, etag, body)
	var unknown *sidecar.BlobUnknownError
	switch {
	case err == nil:
		request.Reply(nil)
	case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		// another write moved the key, or this one's answer was lost: what stands now decides
		if done, _ := judge(); !done {
			request.Unavailable()
		}
	default:
		request.Unavailable()
	}
}

// GET /gkm/reader-key/<sidecar_id>: the Signed ReaderKey gkm serves for a sidecar, byte for byte.
func (self *GkmEngine) serveReaderKeyRead(request *GkmRequest) {
	sidecarId, err := parseGkmHexId(request.Http.PathValue(gkmPathValueSidecarId))
	if err != nil {
		request.BadRequest()
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	held, _, err := readGkmObject(request.Ctx, cluster, GkmReaderKeyKey(sidecarId), gkmReaderKeyMaxByteCount)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		request.NotFound()
	case err != nil:
		self.answerStoreError(request, err)
	default:
		request.ReplyBytes(200, held)
	}
}

// POST /gkm/reader-keys: a GkmReaderKeysRequest of at most 256 sidecars, answered in order, an empty Signed for a
// sidecar with none (QD-066), so a rotator needs no request per recipient.
func (self *GkmEngine) serveReaderKeysRead(request *GkmRequest) {
	readRequest := &protocol.GkmReaderKeysRequest{}
	if !request.ReadMessage(readRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	sidecarIdBytes := readRequest.GetSidecarIds()
	if len(sidecarIdBytes) == 0 || gkmReaderKeysMaxCount < len(sidecarIdBytes) {
		request.BadRequest()
		return
	}
	sidecarIds := make([]sidecar.Id, len(sidecarIdBytes))
	for i, idBytes := range sidecarIdBytes {
		sidecarId, err := sidecar.IdFromBytes(idBytes)
		if err != nil {
			request.BadRequest()
			return
		}
		sidecarIds[i] = sidecarId
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	readerKeys := make([]*bridge.Signed, len(sidecarIds))
	readErrs := make([]error, len(sidecarIds))
	// at most ReaderKeysReadConcurrency reads at once, each writing only its own slot
	func() {
		ctx, cancel := context.WithCancel(request.Ctx)
		defer cancel()
		slots := make(chan struct{}, self.settings.ReaderKeysReadConcurrency)
		var group sync.WaitGroup
		for i, sidecarId := range sidecarIds {
			slots <- struct{}{}
			group.Add(1)
			go func() {
				defer group.Done()
				defer func() { <-slots }()
				readerKeys[i], readErrs[i] = self.readReaderKey(ctx, cluster, sidecarId)
			}()
		}
		group.Wait()
	}()
	for _, err := range readErrs {
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
	}
	request.Reply(&protocol.GkmReaderKeysReply{ReaderKeys: readerKeys})
}

// A sidecar's stored ReaderKey, or an empty Signed for none.
func (self *GkmEngine) readReaderKey(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id) (*bridge.Signed, error) {
	held, _, err := readGkmObject(ctx, cluster, GkmReaderKeyKey(sidecarId), gkmReaderKeyMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return &bridge.Signed{}, nil
	}
	if err != nil {
		return nil, err
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(held, signed); err != nil {
		return nil, errors.Join(errGkmStoreFault, err)
	}
	return signed, nil
}
