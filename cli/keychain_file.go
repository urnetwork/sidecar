// The files the Windows DPAPI store and the headless Linux key file keep (§5.9): one file a name, under the store's
// directory, which is 0700 and the user's. A file is written to a temporary name, synced and renamed, then the
// directory synced, so a kill leaves the old value or the new one. On Unix a file whose mode is looser than 0600, or
// that another user owns, is refused rather than read, and so is a directory open to others (§5.9's 0600 key file).

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/urnetwork/sidecar"
)

// The OS files under one directory.
type osKeyStoreDirectory struct {
	directory string
}

// Makes the directory 0700 if it is missing, and checks the one there.
func (self *osKeyStoreDirectory) prepare() error {
	if err := os.MkdirAll(self.directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(self.directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("the key store's directory is not a directory")
	}
	return checkOsKeyStoreDirectoryMode(info)
}

// The file's bytes. See osKeyStoreFiles.
func (self *osKeyStoreDirectory) read(file string) ([]byte, error) {
	if err := self.prepare(); err != nil {
		return nil, err
	}
	path := filepath.Join(self.directory, file)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errOsKeyStoreFileAbsent
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the key store's file is not a regular file")
	}
	if err := checkOsKeyStoreFileMode(info); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// Replaces the file whole and durably. See osKeyStoreFiles.
func (self *osKeyStoreDirectory) write(file string, content []byte) error {
	if err := self.prepare(); err != nil {
		return err
	}
	temp, err := os.CreateTemp(self.directory, ".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			temp.Close()
			os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(content); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(self.directory, file)); err != nil {
		return err
	}
	committed = true
	return syncOsKeyStoreDirectory(self.directory)
}

// Removes the file. See osKeyStoreFiles.
func (self *osKeyStoreDirectory) remove(file string) error {
	err := os.Remove(filepath.Join(self.directory, file))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncOsKeyStoreDirectory(self.directory)
}

// The headless Linux store (§5.9): a 0600 file a name. It has no lock, so an error, a loose mode included, is Failed,
// and only a file that is not there is Absent. `ur status` warns while U sits here.
type keyFileStore struct {
	files osKeyStoreFiles
}

// The value, or the status that says why not. See sidecar.SidecarKeyStore.
func (self *keyFileStore) GetSecret(name string) ([]byte, sidecar.SidecarKeyStoreStatus) {
	type answer struct {
		value  []byte
		status sidecar.SidecarKeyStoreStatus
	}
	result := osKeyStoreGuard(answer{status: sidecar.SidecarKeyStoreFailed}, func() answer {
		value, err := self.files.read(osKeyStoreItemFile(name))
		if errors.Is(err, errOsKeyStoreFileAbsent) {
			return answer{status: sidecar.SidecarKeyStoreAbsent}
		}
		if err != nil {
			return answer{status: sidecar.SidecarKeyStoreFailed}
		}
		return answer{value: value, status: sidecar.SidecarKeyStorePresent}
	})
	return result.value, result.status
}

// Replaces the item's file. See sidecar.SidecarKeyStore.
func (self *keyFileStore) PutSecret(name string, value []byte) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		if err := self.files.write(osKeyStoreItemFile(name), osKeyStoreCopy(value)); err != nil {
			return sidecar.SidecarKeyStoreFailed
		}
		return sidecar.SidecarKeyStoreOk
	})
}

// Removes the item's file. See sidecar.SidecarKeyStore.
func (self *keyFileStore) DeleteSecret(name string) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		if err := self.files.remove(osKeyStoreItemFile(name)); err != nil {
			return sidecar.SidecarKeyStoreFailed
		}
		return sidecar.SidecarKeyStoreOk
	})
}

// A loose mode's refusal, which names no path.
var errOsKeyStoreLooseMode = fmt.Errorf("a key store file is open to other users")
