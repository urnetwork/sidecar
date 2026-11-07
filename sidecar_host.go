// The seams §5.4 names and leaves open, fixed here for every track that builds on them: what a host
// gives a Sidecar, and how a component reaches its secrets and its files. All of it is on every leg,
// so the page Worker's host and a fake in sidecartest implement the same interfaces as `ur daemon`.
//
// A name in SidecarSecrets or SidecarStore is the caller's, so an error here never repeats it, and
// never a value (I-7, I-13).

package sidecar

import (
	"errors"
	"io"
)

var (
	// Nothing is stored under the name. Only this means that: a fault or a lock is never this
	// (D-CORE-15).
	ErrSidecarStoreAbsent = errors.New("nothing stored")
	// The keychain is locked, so nothing can be read or written until it opens (§5.9).
	ErrSidecarStoreLocked = errors.New("keychain locked")
	// Bytes failed decoding or AEAD, or the medium failed. Never read this as absent, and never
	// answer it by creating anything (D-CORE-15).
	ErrSidecarStoreFailed = errors.New("store failed")
	// A store's file call on a directory no class seals, which is the store a host hands over.
	// Directory names the class.
	ErrSidecarStoreNoClass = errors.New("store has no file class")
	// A name that is not a clean relative path (SidecarStore's rule).
	ErrSidecarStoreName = errors.New("invalid store name")
)

// What a Sidecar takes from whatever hosts it (§5.4, §18.7).
type SidecarHost interface {
	// Where this sidecar's sealed state lives. It must come from SidecarInstance.Store, because
	// sealing is the core's: a host brings a SidecarStoreBackend, never its own sealing.
	Store() SidecarStore
	// The OS or app store holding the wrap of U. Nil: pass only (§5.9).
	KeyStore() SidecarKeyStore
	// The host's own refreshing token. Nil: D-CORE-8's refresher.
	TokenSource() SidecarTokenSource
}

// One answer from a SidecarKeyStore (D-CORE-15, D-SDK-15). A read answers Present, Absent, Locked or
// Failed, and a write Ok, Locked or Failed. Zero is Failed and anything else unknown is read as
// Failed, so an adapter that sets no status can never pass for Absent, which is the one answer that
// creates anything.
type SidecarKeyStoreStatus int32

const (
	// A fault, or a value this store cannot vouch for. As Locked, and alarms. Nothing is created,
	// overwritten or deleted on this answer.
	SidecarKeyStoreFailed SidecarKeyStoreStatus = 0
	// A write took.
	SidecarKeyStoreOk SidecarKeyStoreStatus = 1
	// A read found the value. One that then fails decoding or AEAD counts as Failed.
	SidecarKeyStorePresent SidecarKeyStoreStatus = 2
	// The store is working and holds no such item, which a lock must never be reported as.
	SidecarKeyStoreAbsent SidecarKeyStoreStatus = 3
	// The store cannot answer until it unlocks, after which the host calls Unlock(nil). Nothing is
	// created, overwritten or deleted on this answer.
	SidecarKeyStoreLocked SidecarKeyStoreStatus = 4
)

// The OS or app store that wraps U (§5.9's platform table): the data protection keychain, DPAPI,
// Secret Service, a 0600 key file, or an app's own (§18.5). Each call gives one terminal answer and
// never panics across the host boundary (D-SDK-15). Safe for concurrent use.
type SidecarKeyStore interface {
	// Keeps value under name, replacing any earlier one: Ok, Locked or Failed.
	PutSecret(name string, value []byte) SidecarKeyStoreStatus
	// The value under name with Present, or nil with Absent, Locked or Failed.
	GetSecret(name string) ([]byte, SidecarKeyStoreStatus)
	// Ok whether it was deleted or absent, else Locked or Failed.
	DeleteSecret(name string) SidecarKeyStoreStatus
}

// A component's namespace of this network's keychain.ur (§5.9), so the names one component sees are
// its own. Reads answer ErrSidecarStoreAbsent, ErrSidecarStoreLocked or ErrSidecarStoreFailed, and
// a write has reached the disk when it returns. Safe for concurrent use.
type SidecarSecrets interface {
	// A copy of the value under name.
	Get(name string) ([]byte, error)
	// Keeps a copy of value under name, replacing any earlier one.
	Put(name string, value []byte) error
	// Takes name away. Nothing there is not an error.
	Delete(name string) error
	// The names starting with prefix, sorted.
	List(prefix string) ([]string, error)
}

// A sealed directory of one network's local state (§5.9): a component's or a file class's files,
// each streamed through AEAD in chunks, so a large file needs no second copy in memory and no
// plaintext reaches the disk, temp files included (§5.4's SidecarEnv.Store).
//
// A name is a relative path, with / between segments. A segment is not empty, does not start with a
// dot, does not end in a dot or a space, and holds no \, :, or control character. Anything else answers
// ErrSidecarStoreName. A file opens only at its own path and under its own class, so a moved or
// swapped file fails. Calls answer ErrSidecarStoreLocked while the keychain is locked, and a stream
// open at that moment fails at its next chunk. Safe for concurrent use.
type SidecarStore interface {
	// Streams the plaintext of name, authenticating each chunk before it is read. A cut, reordered
	// or tampered file answers ErrSidecarStoreFailed from Read, at the chunk where it shows, so a
	// caller keeps nothing from a read that did not reach io.EOF. ErrSidecarStoreAbsent if nothing is
	// there.
	Open(name string) (io.ReadCloser, error)
	// Starts replacing name. Nothing shows until Commit, which swaps the whole file in at once, so a
	// kill leaves the old file or the new one and never a part.
	Create(name string) (SidecarStoreWriter, error)
	// Takes name away. Nothing there is not an error.
	Remove(name string) error
	// Each file under this directory whose name starts with prefix, sorted by name. Names are
	// relative to this directory.
	List(prefix string) ([]SidecarStoreEntry, error)
	// The directory name under this one, its files sealed under class. An empty name is this
	// directory, and an empty class keeps this one's, so Directory("", "search") is how
	// net/<network_id>/search.state is reached. Nothing is created until a file is.
	Directory(name string, class string) (SidecarStore, error)
}

// A file on its way into a SidecarStore. Write it, then Commit, and Close in every case:
//
//	writer, err := store.Create(name)
//	if err != nil {
//		return err
//	}
//	defer writer.Close()
//	if _, err := writer.Write(data); err != nil {
//		return err
//	}
//	return writer.Commit()
//
// Not safe for concurrent use.
type SidecarStoreWriter interface {
	io.Writer
	// Seals the last chunk and swaps the file in, durably: when this returns nil, a power cut keeps
	// it.
	Commit() error
	// Drops what was written unless Commit took it. Safe to call again.
	Close() error
}

// One file in a SidecarStore's listing.
type SidecarStoreEntry struct {
	// Relative to the directory listed.
	Name string
	// What it takes on disk, for a cache's bound. A little over its plaintext.
	ByteCount int64
}

// An sdk host's own refreshing token for this sidecar's child client (§5.6's sdk host row, §18.7).
// Its presence turns D-CORE-8's refresher off, so a host installs the core's DPoP signer first
// (CORE-M8-01). Safe for concurrent use.
type SidecarTokenSource interface {
	// The token now. A source that has none answers an error, never an empty token.
	ByJwt() (string, error)
	// Calls callback with each new token, on whatever goroutine refreshed it, so the core re-seals
	// it and installs it in its holders. Returns the removal.
	AddByJwtCallback(callback func(byJwt string)) func()
}
