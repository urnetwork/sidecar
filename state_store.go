// The SidecarStore implementation: a directory of one network's sealed files. A store holds no key and
// no file: it names a place, and each call finds the network's keychain, so it answers
// ErrSidecarStoreLocked while the instance is locked and works again once it opens. keys_keychain.go
// does the sealing.

package sidecar

import (
	"io"
	"strings"
)

// What SidecarInstance.Store answers, and what Directory narrows.
type sealedStore struct {
	instance *SidecarInstance
	// Nil until a Sidecar enrolls: nothing is stored here without a network.
	networkId *Id
	// Empty on the store a host hands over, whose file calls refuse: every file has a class.
	class string
	// Inside net/<network_id>, with no trailing /. Empty is the network's own directory.
	directory string
}

// Whether every segment of name is a clean one, as SidecarStore's comment states. A segment's last byte
// is held too, because Windows drops a trailing dot or space, which would make one name another.
func isStoreName(name string) bool {
	if name == "" {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment[0] == '.' {
			return false
		}
		if last := segment[len(segment)-1]; last == '.' || last == ' ' {
			return false
		}
		for i := 0; i < len(segment); i += 1 {
			if c := segment[i]; c < 0x20 || c == 0x7f || c == '\\' || c == ':' {
				return false
			}
		}
	}
	return true
}

// path inside the network's directory, with the names only the keychain may use refused: a component
// may not replace keychain.ur or keychain.wrap, whatever class it names, nor reach them by a name in
// another case, which is the same file on APFS and NTFS.
func (self *sealedStore) networkPath(name string) (string, error) {
	if !isStoreName(name) {
		return "", ErrSidecarStoreName
	}
	path := name
	if self.directory != "" {
		path = self.directory + "/" + name
	}
	if strings.EqualFold(path, keychainWrapName) || strings.EqualFold(path, keychainRecordsName) {
		return "", ErrSidecarStoreName
	}
	return path, nil
}

// This network's keychain, or why there is none to use.
func (self *sealedStore) openKeychain() (*keychain, error) {
	if self.networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	return self.instance.keychainFor(*self.networkId)
}

// The keychain and path a file call works on.
func (self *sealedStore) resolve(name string) (*keychain, string, error) {
	if self.class == "" {
		return nil, "", ErrSidecarStoreNoClass
	}
	path, err := self.networkPath(name)
	if err != nil {
		return nil, "", err
	}
	keychain, err := self.openKeychain()
	if err != nil {
		return nil, "", err
	}
	return keychain, path, nil
}

// Streams a sealed file. See SidecarStore.
func (self *sealedStore) Open(name string) (io.ReadCloser, error) {
	keychain, path, err := self.resolve(name)
	if err != nil {
		return nil, err
	}
	return keychain.openSealed(self.class, path)
}

// Starts replacing a sealed file. See SidecarStore.
func (self *sealedStore) Create(name string) (SidecarStoreWriter, error) {
	keychain, path, err := self.resolve(name)
	if err != nil {
		return nil, err
	}
	writer, err := keychain.createSealed(self.class, path)
	if err != nil {
		return nil, err
	}
	return writer, nil
}

// Takes a file away. See SidecarStore.
func (self *sealedStore) Remove(name string) error {
	keychain, path, err := self.resolve(name)
	if err != nil {
		return err
	}
	return keychain.removeSealed(path)
}

// Lists this directory by prefix. See SidecarStore.
func (self *sealedStore) List(prefix string) ([]SidecarStoreEntry, error) {
	if self.class == "" {
		return nil, ErrSidecarStoreNoClass
	}
	// a prefix may end mid-segment, so what it holds is held to the rule by finishing that segment
	if prefix != "" && !isStoreName(prefix+"x") {
		return nil, ErrSidecarStoreName
	}
	keychain, err := self.openKeychain()
	if err != nil {
		return nil, err
	}
	base := ""
	if self.directory != "" {
		base = self.directory + "/"
	}
	return keychain.listSealed(base, prefix)
}

// Narrows this store. See SidecarStore.
func (self *sealedStore) Directory(name string, class string) (SidecarStore, error) {
	narrowed := *self
	if name != "" {
		if !isStoreName(name) {
			return nil, ErrSidecarStoreName
		}
		if narrowed.directory == "" {
			narrowed.directory = name
		} else {
			narrowed.directory += "/" + name
		}
	}
	if class != "" {
		if !isSealClass(class) || class == keychainRecordsClass {
			return nil, ErrSidecarStoreName
		}
		narrowed.class = class
	}
	return &narrowed, nil
}
