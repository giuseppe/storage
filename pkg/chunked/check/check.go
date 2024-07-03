package check

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/containers/storage/pkg/chunked/internal"
	securejoin "github.com/cyphar/filepath-securejoin"
	json "github.com/json-iterator/go"
	"github.com/opencontainers/go-digest"
)

// BigDataStore is a store for big data blobs.
type BigDataStore interface {
	// BigData retrieves a big data blob from the store.
	BigData(id, key string) (io.ReadCloser, error)
}

func Check(store BigDataStore, layer, mountPoint string) (exists bool, errors []error) {
	rc, err := store.BigData(layer, internal.BigDataKey)
	if err != nil {
		return false, nil
	}
	defer rc.Close()

	exists = true

	var toc internal.TOC

	data, err := ioutil.ReadAll(rc)
	if err != nil {
		errors = append(errors, err)
		return
	}

	if err := json.Unmarshal(data, &toc); err != nil {
		errors = append(errors, err)
		return
	}

	for _, e := range toc.Entries {
		if e.Type == internal.TypeChunk {
			continue
		}

		st, err := os.Lstat(filepath.Join(mountPoint, e.Name))
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if e.Type != internal.TypeSymlink {
			modeMask := int64(os.ModePerm)
			if (int64(st.Mode()) & modeMask) != (e.Mode & modeMask) {
				errors = append(errors, fmt.Errorf("mode mismatch for %s: expected %o, got %o", e.Name, e.Mode&modeMask, int64(st.Mode())&modeMask))
			}
		}
		if e.UID != int(st.Sys().(*syscall.Stat_t).Uid) {
			errors = append(errors, fmt.Errorf("uid mismatch for %s: expected %d, got %d", e.Name, e.UID, int(st.Sys().(*syscall.Stat_t).Uid)))
		}
		if e.GID != int(st.Sys().(*syscall.Stat_t).Gid) {
			errors = append(errors, fmt.Errorf("gid mismatch for %s: expected %d, got %d", e.Name, e.GID, int(st.Sys().(*syscall.Stat_t).Gid)))
		}
		if e.Type == internal.TypeReg {
			if st.Size() != e.Size {
				errors = append(errors, fmt.Errorf("size mismatch for %s: expected %d, got %d", e.Name, e.Size, st.Size()))
			}

			expectedDigest, err := digest.Parse(e.Digest)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			newPath, err := securejoin.SecureJoin(mountPoint, e.Name)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			f, err := os.Open(newPath)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			defer f.Close()

			digest, err := expectedDigest.Algorithm().FromReader(f)
			if err != nil {
				errors = append(errors, err)
				continue
			}

			if digest != expectedDigest {
				errors = append(errors, fmt.Errorf("digest mismatch for %s: expected %s, got %s", e.Name, expectedDigest, digest))
			}
		}
	}
	return
}
