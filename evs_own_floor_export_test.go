// A bridge for the external tests of the floor under a device's own pushes (directory_evs_own_floor_test.go;
// evs_read.go's own pushes row): what the client's reads of a ref are held to, a push of its noted, and a transport a
// test stands between the client and evs.

package sidecar

import (
	"net/http"
)

// What the client's reads of a ref are held to (evsClientEpochs.ownFloor).
func (self *EvsClient) OwnFloorForTest(repoId Id, refId Id) uint64 {
	return self.epochs.ownFloor(repoId, refId)
}

// Notes a push of the client's committed on a ref at version, as a push it made would (evsClientEpochs.noteCommitted).
func (self *EvsClient) NoteCommittedForTest(repoId Id, refId Id, version uint64) {
	self.epochs.noteCommitted(repoId, refId, version)
}

// Puts what wrap makes of the client's transport between it and evs, before any request of the test.
func (self *EvsClient) WrapTransportForTest(wrap func(transport http.RoundTripper) http.RoundTripper) {
	self.args.Transport = wrap(self.args.Transport)
	self.http.transport = wrapSidecarApiTransport(self.args.Transport)
}
