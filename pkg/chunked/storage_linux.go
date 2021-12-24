package chunked

import (
	archivetar "archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/stargz-snapshotter/estargz"
	storage "github.com/containers/storage"
	graphdriver "github.com/containers/storage/drivers"
	driversCopy "github.com/containers/storage/drivers/copy"
	"github.com/containers/storage/pkg/archive"
	"github.com/containers/storage/pkg/chunked/internal"
	"github.com/containers/storage/pkg/idtools"
	"github.com/containers/storage/pkg/system"
	"github.com/containers/storage/types"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vbatts/tar-split/archive/tar"
	"golang.org/x/sys/unix"
)

const (
	maxNumberMissingChunks  = 1024
	newFileFlags            = (unix.O_CREAT | unix.O_TRUNC | unix.O_EXCL | unix.O_WRONLY)
	containersOverrideXattr = "user.containers.override_stat"
	bigDataKey              = "zstd-chunked-manifest"

	fileTypeZstdChunked   = iota
	fileTypeEstargz       = iota
	fileTypeNoCompression = iota
)

type compressedFileType int

type chunkedDiffer struct {
	stream      ImageSourceSeekable
	manifest    []byte
	layersCache *layersCache
	tocOffset   int64
	fileType    compressedFileType

	copyBuffer []byte

	gzipReader *pgzip.Reader
	zstdReader *zstd.Decoder
	rawReader  io.Reader
}

var xattrsToIgnore = map[string]interface{}{
	"security.selinux": true,
}

func timeToTimespec(time *time.Time) (ts unix.Timespec) {
	if time == nil || time.IsZero() {
		// Return UTIME_OMIT special value
		ts.Sec = 0
		ts.Nsec = ((1 << 30) - 2)
		return
	}
	return unix.NsecToTimespec(time.UnixNano())
}

func doHardLink(srcFd int, destDirFd int, destBase string) error {
	doLink := func() error {
		// Using unix.AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH while this variant that uses
		// /proc/self/fd doesn't and can be used with rootless.
		srcPath := fmt.Sprintf("/proc/self/fd/%d", srcFd)
		return unix.Linkat(unix.AT_FDCWD, srcPath, destDirFd, destBase, unix.AT_SYMLINK_FOLLOW)
	}

	err := doLink()

	// if the destination exists, unlink it first and try again
	if err != nil && os.IsExist(err) {
		unix.Unlinkat(destDirFd, destBase, 0)
		return doLink()
	}
	return err
}

func copyFileContent(srcFd int, destFile string, dirfd int, mode os.FileMode, useHardLinks bool) (*os.File, int64, error) {
	src := fmt.Sprintf("/proc/self/fd/%d", srcFd)
	st, err := os.Stat(src)
	if err != nil {
		return nil, -1, fmt.Errorf("copy file content for %q: %w", destFile, err)
	}

	copyWithFileRange, copyWithFileClone := true, true

	if useHardLinks {
		destDirPath := filepath.Dir(destFile)
		destBase := filepath.Base(destFile)
		destDir, err := openFileUnderRoot(destDirPath, dirfd, 0, mode)
		if err == nil {
			defer destDir.Close()

			err := doHardLink(srcFd, int(destDir.Fd()), destBase)
			if err == nil {
				return nil, st.Size(), nil
			}
		}
	}

	// If the destination file already exists, we shouldn't blow it away
	dstFile, err := openFileUnderRoot(destFile, dirfd, newFileFlags, mode)
	if err != nil {
		return nil, -1, fmt.Errorf("open file %q under rootfs for copy: %w", destFile, err)
	}

	err = driversCopy.CopyRegularToFile(src, dstFile, st, &copyWithFileRange, &copyWithFileClone)
	if err != nil {
		dstFile.Close()
		return nil, -1, fmt.Errorf("copy to file %q under rootfs: %w", destFile, err)
	}
	return dstFile, st.Size(), nil
}

// GetDiffer returns a differ than can be used with ApplyDiffWithDiffer.
func GetDiffer(ctx context.Context, store storage.Store, blobSize int64, annotations map[string]string, iss ImageSourceSeekable) (graphdriver.Differ, error) {
	if _, ok := annotations[internal.ManifestChecksumKey]; ok {
		return makeZstdChunkedDiffer(ctx, store, blobSize, annotations, iss)
	}
	if _, ok := annotations[estargz.TOCJSONDigestAnnotation]; ok {
		return makeEstargzChunkedDiffer(ctx, store, blobSize, annotations, iss)
	}
	return nil, errors.New("blob type not supported for partial retrieval")
}

func makeZstdChunkedDiffer(ctx context.Context, store storage.Store, blobSize int64, annotations map[string]string, iss ImageSourceSeekable) (*chunkedDiffer, error) {
	manifest, tocOffset, err := readZstdChunkedManifest(iss, blobSize, annotations)
	if err != nil {
		return nil, fmt.Errorf("read zstd:chunked manifest: %w", err)
	}
	layersCache, err := getLayersCache(store)
	if err != nil {
		return nil, err
	}

	return &chunkedDiffer{
		copyBuffer:  makeCopyBuffer(),
		stream:      iss,
		manifest:    manifest,
		layersCache: layersCache,
		tocOffset:   tocOffset,
		fileType:    fileTypeZstdChunked,
	}, nil
}

func makeEstargzChunkedDiffer(ctx context.Context, store storage.Store, blobSize int64, annotations map[string]string, iss ImageSourceSeekable) (*chunkedDiffer, error) {
	manifest, tocOffset, err := readEstargzChunkedManifest(iss, blobSize, annotations)
	if err != nil {
		return nil, fmt.Errorf("read zstd:chunked manifest: %w", err)
	}
	layersCache, err := getLayersCache(store)
	if err != nil {
		return nil, err
	}

	return &chunkedDiffer{
		copyBuffer:  makeCopyBuffer(),
		stream:      iss,
		manifest:    manifest,
		layersCache: layersCache,
		tocOffset:   tocOffset,
		fileType:    fileTypeEstargz,
	}, nil
}

func makeCopyBuffer() []byte {
	return make([]byte, 1<<18)
}

// copyFileFromOtherLayer copies a file from another layer
// file is the file to look for.
// source is the path to the source layer checkout.
// otherFile contains the metadata for the file.
// dirfd is an open file descriptor to the destination root directory.
// useHardLinks defines whether the deduplication can be performed using hard links.
func copyFileFromOtherLayer(file *internal.FileMetadata, source string, otherFile *internal.FileMetadata, dirfd int, useHardLinks bool) (bool, *os.File, int64, error) {
	srcDirfd, err := unix.Open(source, unix.O_RDONLY, 0)
	if err != nil {
		return false, nil, 0, fmt.Errorf("open source file %q: %w", source, err)
	}
	defer unix.Close(srcDirfd)

	srcFile, err := openFileUnderRoot(otherFile.Name, srcDirfd, unix.O_RDONLY, 0)
	if err != nil {
		return false, nil, 0, fmt.Errorf("open source file %q under target rootfs: %w", otherFile.Name, err)
	}
	defer srcFile.Close()

	dstFile, written, err := copyFileContent(int(srcFile.Fd()), file.Name, dirfd, 0, useHardLinks)
	if err != nil {
		return false, nil, 0, fmt.Errorf("copy content to %q: %w", file.Name, err)
	}
	return true, dstFile, written, nil
}

// canDedupMetadataWithHardLink says whether it is possible to deduplicate file with otherFile.
// It checks that the two files have the same UID, GID, file mode and xattrs.
func canDedupMetadataWithHardLink(file *internal.FileMetadata, otherFile *internal.FileMetadata) bool {
	if file.UID != otherFile.UID {
		return false
	}
	if file.GID != otherFile.GID {
		return false
	}
	if file.Mode != otherFile.Mode {
		return false
	}
	if !reflect.DeepEqual(file.Xattrs, otherFile.Xattrs) {
		return false
	}
	return true
}

// canDedupFileWithHardLink checks if the specified file can be deduplicated by an
// open file, given its descriptor and stat data.
func canDedupFileWithHardLink(file *internal.FileMetadata, fd int, s os.FileInfo) bool {
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	path := fmt.Sprintf("/proc/self/fd/%d", fd)

	listXattrs, err := system.Llistxattr(path)
	if err != nil {
		return false
	}

	xattrs := make(map[string]string)
	for _, x := range listXattrs {
		v, err := system.Lgetxattr(path, x)
		if err != nil {
			return false
		}

		if _, found := xattrsToIgnore[x]; found {
			continue
		}
		xattrs[x] = string(v)
	}
	// fill only the attributes used by canDedupMetadataWithHardLink.
	otherFile := internal.FileMetadata{
		UID:    int(st.Uid),
		GID:    int(st.Gid),
		Mode:   int64(st.Mode),
		Xattrs: xattrs,
	}
	return canDedupMetadataWithHardLink(file, &otherFile)
}

func getFileDigest(f *os.File, buf []byte) (digest.Digest, error) {
	digester := digest.Canonical.Digester()
	if _, err := io.CopyBuffer(digester.Hash(), f, buf); err != nil {
		return "", err
	}
	return digester.Digest(), nil
}

// findFileInOSTreeRepos checks whether the requested file already exist in one of the OSTree repo and copies the file content from there if possible.
// file is the file to look for.
// ostreeRepos is a list of OSTree repos.
// dirfd is an open fd to the destination checkout.
// useHardLinks defines whether the deduplication can be performed using hard links.
func findFileInOSTreeRepos(file *internal.FileMetadata, ostreeRepos []string, dirfd int, useHardLinks bool) (bool, *os.File, int64, error) {
	digest, err := digest.Parse(file.Digest)
	if err != nil {
		return false, nil, 0, nil
	}
	payloadLink := digest.Encoded() + ".payload-link"
	if len(payloadLink) < 2 {
		return false, nil, 0, nil
	}

	for _, repo := range ostreeRepos {
		sourceFile := filepath.Join(repo, "objects", payloadLink[:2], payloadLink[2:])
		st, err := os.Stat(sourceFile)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if st.Size() != file.Size {
			continue
		}
		fd, err := unix.Open(sourceFile, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return false, nil, 0, nil
		}
		f := os.NewFile(uintptr(fd), "fd")
		defer f.Close()

		// check if the open file can be deduplicated with hard links
		if useHardLinks && !canDedupFileWithHardLink(file, fd, st) {
			continue
		}

		dstFile, written, err := copyFileContent(fd, file.Name, dirfd, 0, useHardLinks)
		if err != nil {
			return false, nil, 0, nil
		}
		return true, dstFile, written, nil
	}
	// If hard links deduplication was used and it has failed, try again without hard links.
	if useHardLinks {
		return findFileInOSTreeRepos(file, ostreeRepos, dirfd, false)
	}

	return false, nil, 0, nil
}

// findFileOnTheHost checks whether the requested file already exist on the host and copies the file content from there if possible.
// It is currently implemented to look only at the file with the same path.  Ideally it can detect the same content also at different
// paths.
// file is the file to look for.
// dirfd is an open fd to the destination checkout.
// useHardLinks defines whether the deduplication can be performed using hard links.
func findFileOnTheHost(file *internal.FileMetadata, dirfd int, useHardLinks bool, buf []byte) (bool, *os.File, int64, error) {
	sourceFile := filepath.Clean(filepath.Join("/", file.Name))
	if !strings.HasPrefix(sourceFile, "/usr/") {
		// limit host deduplication to files under /usr.
		return false, nil, 0, nil
	}

	st, err := os.Stat(sourceFile)
	if err != nil || !st.Mode().IsRegular() {
		return false, nil, 0, nil
	}

	if st.Size() != file.Size {
		return false, nil, 0, nil
	}

	fd, err := unix.Open(sourceFile, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, nil, 0, nil
	}

	f := os.NewFile(uintptr(fd), "fd")
	defer f.Close()

	manifestChecksum, err := digest.Parse(file.Digest)
	if err != nil {
		return false, nil, 0, err
	}

	checksum, err := getFileDigest(f, buf)
	if err != nil {
		return false, nil, 0, err
	}

	if checksum != manifestChecksum {
		return false, nil, 0, nil
	}

	// check if the open file can be deduplicated with hard links
	useHardLinks = useHardLinks && canDedupFileWithHardLink(file, fd, st)

	dstFile, written, err := copyFileContent(fd, file.Name, dirfd, 0, useHardLinks)
	if err != nil {
		return false, nil, 0, nil
	}

	// calculate the checksum again to make sure the file wasn't modified while it was copied
	if _, err := f.Seek(0, 0); err != nil {
		dstFile.Close()
		return false, nil, 0, err
	}
	checksum, err = getFileDigest(f, buf)
	if err != nil {
		dstFile.Close()
		return false, nil, 0, err
	}
	if checksum != manifestChecksum {
		dstFile.Close()
		return false, nil, 0, nil
	}
	return true, dstFile, written, nil
}

type findFileState struct {
	file         *internal.FileMetadata
	useHardLinks bool
	dirfd        int

	found    bool
	dstFile  *os.File
	written  int64
	retError error
}

func (v *findFileState) VisitFile(candidate *internal.FileMetadata, target string) (bool, error) {
	if v.useHardLinks && !canDedupMetadataWithHardLink(v.file, candidate) {
		return true, nil
	}
	found, dstFile, written, err := copyFileFromOtherLayer(v.file, target, candidate, v.dirfd, v.useHardLinks)
	if found && err == nil {
		v.found = found
		v.dstFile = dstFile
		v.written = written
		v.retError = err
		return false, nil
	}
	return true, nil
}

// findFileInOtherLayers finds the specified file in other layers.
// cache is the layers cache to use.
// file is the file to look for.
// dirfd is an open file descriptor to the checkout root directory.
// useHardLinks defines whether the deduplication can be performed using hard links.
func findFileInOtherLayers(cache *layersCache, file *internal.FileMetadata, dirfd int, useHardLinks bool) (bool, *os.File, int64, error) {
	visitor := &findFileState{
		file:         file,
		useHardLinks: useHardLinks,
		dirfd:        dirfd,
	}
	if err := cache.findFileInOtherLayers(file, visitor); err != nil {
		return false, nil, 0, err
	}
	return visitor.found, visitor.dstFile, visitor.written, visitor.retError
}

func maybeDoIDRemap(manifest []internal.FileMetadata, options *archive.TarOptions) error {
	if options.ChownOpts == nil && len(options.UIDMaps) == 0 || len(options.GIDMaps) == 0 {
		return nil
	}

	idMappings := idtools.NewIDMappingsFromMaps(options.UIDMaps, options.GIDMaps)

	for i := range manifest {
		if options.ChownOpts != nil {
			manifest[i].UID = options.ChownOpts.UID
			manifest[i].GID = options.ChownOpts.GID
		} else {
			pair := idtools.IDPair{
				UID: manifest[i].UID,
				GID: manifest[i].GID,
			}
			var err error
			manifest[i].UID, manifest[i].GID, err = idMappings.ToContainer(pair)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type originFile struct {
	Root string
	Path string

	Offset int64
}

type missingFileChunk struct {
	Gap int64

	File *internal.FileMetadata

	CompressedSize   int64
	UncompressedSize int64
}

type missingPart struct {
	SourceChunk *ImageSourceChunk
	OriginFile  *originFile
	Chunks      []missingFileChunk
}

func (o *originFile) OpenFile() (io.ReadCloser, error) {
	srcDirfd, err := unix.Open(o.Root, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open source file %q: %w", o.Root, err)
	}
	defer unix.Close(srcDirfd)

	srcFile, err := openFileUnderRoot(o.Path, srcDirfd, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open source file %q under target rootfs: %w", o.Path, err)
	}

	if _, err := srcFile.Seek(o.Offset, 0); err != nil {
		srcFile.Close()
		return nil, err
	}
	return srcFile, nil
}

// setFileAttrs sets the file attributes for file given metadata
func setFileAttrs(dirfd int, file *os.File, mode os.FileMode, metadata *internal.FileMetadata, options *archive.TarOptions, usePath bool) error {
	if file == nil || file.Fd() < 0 {
		return errors.Errorf("invalid file")
	}
	fd := int(file.Fd())

	t, err := typeToTarType(metadata.Type)
	if err != nil {
		return err
	}

	// If it is a symlink, force to use the path
	if t == tar.TypeSymlink {
		usePath = true
	}

	baseName := ""
	if usePath {
		dirName := filepath.Dir(metadata.Name)
		if dirName != "" {
			parentFd, err := openFileUnderRoot(dirName, dirfd, unix.O_PATH|unix.O_DIRECTORY, 0)
			if err != nil {
				return err
			}
			defer parentFd.Close()

			dirfd = int(parentFd.Fd())
		}
		baseName = filepath.Base(metadata.Name)
	}

	doChown := func() error {
		if usePath {
			return unix.Fchownat(dirfd, baseName, metadata.UID, metadata.GID, unix.AT_SYMLINK_NOFOLLOW)
		}
		return unix.Fchown(fd, metadata.UID, metadata.GID)
	}

	doSetXattr := func(k string, v []byte) error {
		return unix.Fsetxattr(fd, k, v, 0)
	}

	doUtimes := func() error {
		ts := []unix.Timespec{timeToTimespec(metadata.AccessTime), timeToTimespec(metadata.ModTime)}
		if usePath {
			return unix.UtimesNanoAt(dirfd, baseName, ts, unix.AT_SYMLINK_NOFOLLOW)
		}
		return unix.UtimesNanoAt(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", fd), ts, 0)
	}

	doChmod := func() error {
		if usePath {
			return unix.Fchmodat(dirfd, baseName, uint32(mode), unix.AT_SYMLINK_NOFOLLOW)
		}
		return unix.Fchmod(fd, uint32(mode))
	}

	if err := doChown(); err != nil {
		if !options.IgnoreChownErrors {
			return fmt.Errorf("chown %q to %d:%d: %w", metadata.Name, metadata.UID, metadata.GID, err)
		}
	}

	canIgnore := func(err error) bool {
		return err == nil || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP)
	}

	for k, v := range metadata.Xattrs {
		if _, found := xattrsToIgnore[k]; found {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return fmt.Errorf("decode xattr %q: %w", v, err)
		}
		if err := doSetXattr(k, data); !canIgnore(err) {
			return fmt.Errorf("set xattr %s=%q for %q: %w", k, data, metadata.Name, err)
		}
	}

	if err := doUtimes(); !canIgnore(err) {
		return fmt.Errorf("set utimes for %q: %w", metadata.Name, err)
	}

	if err := doChmod(); !canIgnore(err) {
		return fmt.Errorf("chmod %q: %w", metadata.Name, err)
	}
	return nil
}

func openFileUnderRootFallback(dirfd int, name string, flags uint64, mode os.FileMode) (int, error) {
	root := fmt.Sprintf("/proc/self/fd/%d", dirfd)

	targetRoot, err := os.Readlink(root)
	if err != nil {
		return -1, err
	}

	hasNoFollow := (flags & unix.O_NOFOLLOW) != 0

	fd := -1
	// If O_NOFOLLOW is specified in the flags, then resolve only the parent directory and use the
	// last component as the path to openat().
	if hasNoFollow {
		dirName := filepath.Dir(name)
		if dirName != "" {
			newRoot, err := securejoin.SecureJoin(root, filepath.Dir(name))
			if err != nil {
				return -1, err
			}
			root = newRoot
		}

		parentDirfd, err := unix.Open(root, unix.O_PATH, 0)
		if err != nil {
			return -1, err
		}
		defer unix.Close(parentDirfd)

		fd, err = unix.Openat(parentDirfd, filepath.Base(name), int(flags), uint32(mode))
		if err != nil {
			return -1, err
		}
	} else {
		newPath, err := securejoin.SecureJoin(root, name)
		if err != nil {
			return -1, err
		}
		fd, err = unix.Openat(dirfd, newPath, int(flags), uint32(mode))
		if err != nil {
			return -1, err
		}
	}

	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		unix.Close(fd)
		return -1, err
	}

	// Add an additional check to make sure the opened fd is inside the rootfs
	if !strings.HasPrefix(target, targetRoot) {
		unix.Close(fd)
		return -1, fmt.Errorf("error while resolving %q.  It resolves outside the root directory", name)
	}

	return fd, err
}

func openFileUnderRootOpenat2(dirfd int, name string, flags uint64, mode os.FileMode) (int, error) {
	how := unix.OpenHow{
		Flags:   flags,
		Mode:    uint64(mode & 07777),
		Resolve: unix.RESOLVE_IN_ROOT,
	}
	return unix.Openat2(dirfd, name, &how)
}

// skipOpenat2 is set when openat2 is not supported by the underlying kernel and avoid
// using it again.
var skipOpenat2 int32

// openFileUnderRootRaw tries to open a file using openat2 and if it is not supported fallbacks to a
// userspace lookup.
func openFileUnderRootRaw(dirfd int, name string, flags uint64, mode os.FileMode) (int, error) {
	var fd int
	var err error
	if atomic.LoadInt32(&skipOpenat2) > 0 {
		fd, err = openFileUnderRootFallback(dirfd, name, flags, mode)
	} else {
		fd, err = openFileUnderRootOpenat2(dirfd, name, flags, mode)
		// If the function failed with ENOSYS, switch off the support for openat2
		// and fallback to using safejoin.
		if err != nil && errors.Is(err, unix.ENOSYS) {
			atomic.StoreInt32(&skipOpenat2, 1)
			fd, err = openFileUnderRootFallback(dirfd, name, flags, mode)
		}
	}
	return fd, err
}

// openFileUnderRoot safely opens a file under the specified root directory using openat2
// name is the path to open relative to dirfd.
// dirfd is an open file descriptor to the target checkout directory.
// flags are the flags to pass to the open syscall.
// mode specifies the mode to use for newly created files.
func openFileUnderRoot(name string, dirfd int, flags uint64, mode os.FileMode) (*os.File, error) {
	fd, err := openFileUnderRootRaw(dirfd, name, flags, mode)
	if err == nil {
		return os.NewFile(uintptr(fd), name), nil
	}

	hasCreate := (flags & unix.O_CREAT) != 0
	if errors.Is(err, unix.ENOENT) && hasCreate {
		parent := filepath.Dir(name)
		if parent != "" {
			newDirfd, err2 := openOrCreateDirUnderRoot(parent, dirfd, 0)
			if err2 == nil {
				defer newDirfd.Close()
				fd, err := openFileUnderRootRaw(dirfd, name, flags, mode)
				if err == nil {
					return os.NewFile(uintptr(fd), name), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("open %q under the rootfs: %w", name, err)
}

// openOrCreateDirUnderRoot safely opens a directory or create it if it is missing.
// name is the path to open relative to dirfd.
// dirfd is an open file descriptor to the target checkout directory.
// mode specifies the mode to use for newly created files.
func openOrCreateDirUnderRoot(name string, dirfd int, mode os.FileMode) (*os.File, error) {
	fd, err := openFileUnderRootRaw(dirfd, name, unix.O_DIRECTORY|unix.O_RDONLY, mode)
	if err == nil {
		return os.NewFile(uintptr(fd), name), nil
	}

	if errors.Is(err, unix.ENOENT) {
		parent := filepath.Dir(name)
		if parent != "" {
			pDir, err2 := openOrCreateDirUnderRoot(parent, dirfd, mode)
			if err2 != nil {
				return nil, err
			}
			defer pDir.Close()

			baseName := filepath.Base(name)

			if err2 := unix.Mkdirat(int(pDir.Fd()), baseName, 0755); err2 != nil {
				return nil, err
			}

			fd, err = openFileUnderRootRaw(int(pDir.Fd()), baseName, unix.O_DIRECTORY|unix.O_RDONLY, mode)
			if err == nil {
				return os.NewFile(uintptr(fd), name), nil
			}
		}
	}
	return nil, err
}

func (c *chunkedDiffer) prepareCompressedStreamToFile(compression compressedFileType, from io.Reader, mf *missingFileChunk) error {
	switch compression {
	case fileTypeZstdChunked:
		c.rawReader = io.LimitReader(from, mf.CompressedSize)
		if c.zstdReader == nil {
			r, err := zstd.NewReader(c.rawReader, zstd.WithDecoderConcurrency(1))
			if err != nil {
				return err
			}
			c.zstdReader = r
		} else {
			if err := c.zstdReader.Reset(c.rawReader); err != nil {
				return err
			}
		}

	case fileTypeEstargz:
		c.rawReader = io.LimitReader(from, mf.CompressedSize)
		if c.gzipReader == nil {
			r, err := pgzip.NewReader(c.rawReader)
			if err != nil {
				return err
			}
			c.gzipReader = r
		} else {
			if err := c.gzipReader.Reset(c.rawReader); err != nil {
				return err
			}
		}

	case fileTypeNoCompression:
		c.rawReader = io.LimitReader(from, mf.UncompressedSize)
	default:
		return fmt.Errorf("unknown file type %q", c.fileType)
	}
	return nil
}

func (c *chunkedDiffer) appendCompressedStreamToFile(compression compressedFileType, to io.Writer, size int64) error {
	switch compression {
	case fileTypeZstdChunked:
		defer c.zstdReader.Reset(nil)
		if _, err := io.CopyBuffer(to, io.LimitReader(c.zstdReader, size), c.copyBuffer); err != nil {
			return err
		}
	case fileTypeEstargz:
		defer c.gzipReader.Close()
		if _, err := io.CopyBuffer(to, io.LimitReader(c.gzipReader, size), c.copyBuffer); err != nil {
			return err
		}
	case fileTypeNoCompression:
		if _, err := io.CopyBuffer(to, io.LimitReader(c.rawReader, size), c.copyBuffer); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown file type %q", c.fileType)
	}
	return nil
}

type destinationFile struct {
	dirfd    int
	file     *os.File
	digester digest.Digester
	to       io.Writer
	metadata *internal.FileMetadata
	options  *archive.TarOptions
}

func openDestinationFile(dirfd int, metadata *internal.FileMetadata, options *archive.TarOptions) (*destinationFile, error) {
	file, err := openFileUnderRoot(metadata.Name, dirfd, newFileFlags, 0)
	if err != nil {
		return nil, err
	}

	digester := digest.Canonical.Digester()
	to := io.MultiWriter(file, digester.Hash())

	return &destinationFile{
		file:     file,
		digester: digester,
		to:       to,
		metadata: metadata,
		options:  options,
		dirfd:    dirfd,
	}, nil
}

func (d *destinationFile) Close() error {
	manifestChecksum, err := digest.Parse(d.metadata.Digest)
	if err != nil {
		return err
	}
	if d.digester.Digest() != manifestChecksum {
		return fmt.Errorf("checksum mismatch for %q (got %q instead of %q)", d.file.Name(), d.digester.Digest(), manifestChecksum)
	}

	return setFileAttrs(d.dirfd, d.file, os.FileMode(d.metadata.Mode), d.metadata, d.options, false)
}

func closeDestinationFiles(files chan *destinationFile, errors chan error) {
	for f := range files {
		errors <- f.Close()
	}
	close(errors)
}

func (c *chunkedDiffer) storeMissingFiles(streams chan io.ReadCloser, errs chan error, dest string, dirfd int, missingParts []missingPart, options *archive.TarOptions) (Err error) {
	var destFile *destinationFile

	filesToClose := make(chan *destinationFile, 3)
	closeFilesErrors := make(chan error, 2)

	go closeDestinationFiles(filesToClose, closeFilesErrors)
	defer func() {
		close(filesToClose)
		for e := range closeFilesErrors {
			if e != nil && Err == nil {
				Err = e
			}
		}
	}()

	for _, missingPart := range missingParts {
		var part io.ReadCloser
		compression := c.fileType
		switch {
		case missingPart.OriginFile != nil:
			var err error
			part, err = missingPart.OriginFile.OpenFile()
			if err != nil {
				return err
			}
			compression = fileTypeNoCompression
		case missingPart.SourceChunk != nil:
			select {
			case p := <-streams:
				part = p
			case err := <-errs:
				return err
			}
			if part == nil {
				return errors.Errorf("invalid stream returned")
			}
		default:
			return errors.Errorf("internal error: missing part misses both local and remote data stream")
		}

		for _, mf := range missingPart.Chunks {
			if mf.Gap > 0 {
				limitReader := io.LimitReader(part, mf.Gap)
				_, err := io.CopyBuffer(ioutil.Discard, limitReader, c.copyBuffer)
				if err != nil {
					Err = err
					goto exit
				}
				continue
			}

			if mf.File.Name == "" {
				Err = errors.Errorf("file name empty")
				goto exit
			}

			if err := c.prepareCompressedStreamToFile(compression, part, &mf); err != nil {
				Err = err
				goto exit
			}

			// Open the new file if it is different that what is already
			// opened
			if destFile == nil || destFile.metadata.Name != mf.File.Name {
				var err error
				if destFile != nil {
				cleanup:
					for {
						select {
						case err = <-closeFilesErrors:
							if err != nil {
								Err = err
								goto exit
							}
						default:
							break cleanup
						}
					}
					filesToClose <- destFile
				}
				destFile, err = openDestinationFile(dirfd, mf.File, options)
				if err != nil {
					Err = err
					goto exit
				}
			}

			if err := c.appendCompressedStreamToFile(compression, destFile.to, mf.UncompressedSize); err != nil {
				Err = err
				goto exit
			}
			if _, err := io.CopyBuffer(ioutil.Discard, c.rawReader, c.copyBuffer); err != nil {
				Err = err
				goto exit
			}
		}
	exit:
		part.Close()
		if Err != nil {
			break
		}
	}

	if destFile != nil {
		return destFile.Close()
	}

	return nil
}

func mergeMissingChunks(missingParts []missingPart, target int) []missingPart {
	getGap := func(missingParts []missingPart, i int) int {
		prev := missingParts[i-1].SourceChunk.Offset + missingParts[i-1].SourceChunk.Length
		return int(missingParts[i].SourceChunk.Offset - prev)
	}
	getCost := func(missingParts []missingPart, i int) int {
		cost := getGap(missingParts, i)
		if missingParts[i-1].OriginFile != nil {
			cost += int(missingParts[i-1].SourceChunk.Length)
		}
		if missingParts[i].OriginFile != nil {
			cost += int(missingParts[i].SourceChunk.Length)
		}
		return cost
	}

	// simple case: merge chunks from the same file.
	newMissingParts := missingParts[0:1]
	prevIndex := 0
	for i := 1; i < len(missingParts); i++ {
		gap := getGap(missingParts, i)
		if gap == 0 && missingParts[prevIndex].OriginFile == nil &&
			missingParts[i].OriginFile == nil &&
			len(missingParts[prevIndex].Chunks) == 1 && len(missingParts[i].Chunks) == 1 &&
			missingParts[prevIndex].Chunks[0].File.Name == missingParts[i].Chunks[0].File.Name {
			missingParts[prevIndex].SourceChunk.Length += uint64(gap) + missingParts[i].SourceChunk.Length
			missingParts[prevIndex].Chunks[0].CompressedSize += missingParts[i].Chunks[0].CompressedSize
			missingParts[prevIndex].Chunks[0].UncompressedSize += missingParts[i].Chunks[0].UncompressedSize
		} else {
			newMissingParts = append(newMissingParts, missingParts[i])
			prevIndex++
		}
	}
	missingParts = newMissingParts

	if len(missingParts) <= target {
		return missingParts
	}

	// this implementation doesn't account for duplicates, so it could merge
	// more than necessary to reach the specified target.  Since target itself
	// is a heuristic value, it doesn't matter.
	costs := make([]int, len(missingParts)-1)
	for i := 1; i < len(missingParts); i++ {
		costs[i-1] = getCost(missingParts, i)
	}
	sort.Ints(costs)

	toShrink := len(missingParts) - target
	targetValue := costs[toShrink]

	newMissingParts = missingParts[0:1]
	for i := 1; i < len(missingParts); i++ {
		if getCost(missingParts, i) > targetValue {
			newMissingParts = append(newMissingParts, missingParts[i])
		} else {
			gap := getGap(missingParts, i)
			prev := &newMissingParts[len(newMissingParts)-1]
			prev.SourceChunk.Length += uint64(gap) + missingParts[i].SourceChunk.Length
			prev.OriginFile = nil
			if gap > 0 {
				gapFile := missingFileChunk{
					Gap: int64(gap),
				}
				prev.Chunks = append(prev.Chunks, gapFile)
			}
			prev.Chunks = append(prev.Chunks, missingParts[i].Chunks...)
		}
	}
	return newMissingParts
}

func (c *chunkedDiffer) retrieveMissingFiles(dest string, dirfd int, missingParts []missingPart, options *archive.TarOptions) error {
	var chunksToRequest []ImageSourceChunk
	for _, c := range missingParts {
		if c.OriginFile == nil {
			chunksToRequest = append(chunksToRequest, *c.SourceChunk)
		}
	}

	// There are some missing files.  Prepare a multirange request for the missing chunks.
	var streams chan io.ReadCloser
	var err error
	var errs chan error
	for {
		streams, errs, err = c.stream.GetBlobAt(chunksToRequest)
		if err == nil {
			break
		}

		if _, ok := err.(ErrBadRequest); ok {
			requested := len(missingParts)
			// If the server cannot handle at least 64 chunks in a single request, just give up.
			if requested < 64 {
				return err
			}

			// Merge more chunks to request
			missingParts = mergeMissingChunks(missingParts, requested/2)
			continue
		}
		return err
	}

	if err := c.storeMissingFiles(streams, errs, dest, dirfd, missingParts, options); err != nil {
		return err
	}
	return nil
}

func safeMkdir(dirfd int, mode os.FileMode, name string, metadata *internal.FileMetadata, options *archive.TarOptions) error {
	parent := filepath.Dir(name)
	base := filepath.Base(name)

	parentFd := dirfd
	if parent != "." {
		parentFile, err := openOrCreateDirUnderRoot(parent, dirfd, 0)
		if err != nil {
			return err
		}
		defer parentFile.Close()
		parentFd = int(parentFile.Fd())
	}

	if err := unix.Mkdirat(parentFd, base, uint32(mode)); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("mkdir %q: %w", name, err)
		}
	}

	file, err := openFileUnderRoot(name, dirfd, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	return setFileAttrs(dirfd, file, mode, metadata, options, false)
}

func safeLink(dirfd int, mode os.FileMode, metadata *internal.FileMetadata, options *archive.TarOptions) error {
	sourceFile, err := openFileUnderRoot(metadata.Linkname, dirfd, unix.O_PATH|unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destDir, destBase := filepath.Dir(metadata.Name), filepath.Base(metadata.Name)
	destDirFd := dirfd
	if destDir != "." {
		f, err := openOrCreateDirUnderRoot(destDir, dirfd, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		destDirFd = int(f.Fd())
	}

	err = doHardLink(int(sourceFile.Fd()), destDirFd, destBase)
	if err != nil {
		return fmt.Errorf("create hardlink %q pointing to %q: %w", metadata.Name, metadata.Linkname, err)
	}

	newFile, err := openFileUnderRoot(metadata.Name, dirfd, unix.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		// If the target is a symlink, open the file with O_PATH.
		if errors.Is(err, unix.ELOOP) {
			newFile, err := openFileUnderRoot(metadata.Name, dirfd, unix.O_PATH|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			defer newFile.Close()

			return setFileAttrs(dirfd, newFile, mode, metadata, options, true)
		}
		return err
	}
	defer newFile.Close()

	return setFileAttrs(dirfd, newFile, mode, metadata, options, false)
}

func safeSymlink(dirfd int, mode os.FileMode, metadata *internal.FileMetadata, options *archive.TarOptions) error {
	destDir, destBase := filepath.Dir(metadata.Name), filepath.Base(metadata.Name)
	destDirFd := dirfd
	if destDir != "." {
		f, err := openOrCreateDirUnderRoot(destDir, dirfd, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		destDirFd = int(f.Fd())
	}

	if err := unix.Symlinkat(metadata.Linkname, destDirFd, destBase); err != nil {
		return fmt.Errorf("create symlink %q pointing to %q: %w", metadata.Name, metadata.Linkname, err)
	}
	return nil
}

type whiteoutHandler struct {
	Dirfd int
	Root  string
}

func (d whiteoutHandler) Setxattr(path, name string, value []byte) error {
	file, err := openOrCreateDirUnderRoot(path, d.Dirfd, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := unix.Fsetxattr(int(file.Fd()), name, value, 0); err != nil {
		return fmt.Errorf("set xattr %s=%q for %q: %w", name, value, path, err)
	}
	return nil
}

func (d whiteoutHandler) Mknod(path string, mode uint32, dev int) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	dirfd := d.Dirfd
	if dir != "" {
		dir, err := openOrCreateDirUnderRoot(dir, d.Dirfd, 0)
		if err != nil {
			return err
		}
		defer dir.Close()

		dirfd = int(dir.Fd())
	}

	if err := unix.Mknodat(dirfd, base, mode, dev); err != nil {
		return fmt.Errorf("mknod %q: %w", path, err)
	}

	return nil
}

func checkChownErr(err error, name string, uid, gid int) error {
	if errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("potentially insufficient UIDs or GIDs available in user namespace (requested %d:%d for %s): Check /etc/subuid and /etc/subgid if configured locally: %w", uid, gid, name, err)
	}
	return err
}

func (d whiteoutHandler) Chown(path string, uid, gid int) error {
	file, err := openFileUnderRoot(path, d.Dirfd, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := unix.Fchownat(int(file.Fd()), "", uid, gid, unix.AT_EMPTY_PATH); err != nil {
		var stat unix.Stat_t
		if unix.Fstat(int(file.Fd()), &stat) == nil {
			if stat.Uid == uint32(uid) && stat.Gid == uint32(gid) {
				return nil
			}
		}
		return checkChownErr(err, path, uid, gid)
	}
	return nil
}

type hardLinkToCreate struct {
	dest     string
	dirfd    int
	mode     os.FileMode
	metadata *internal.FileMetadata
}

func parseBooleanPullOption(storeOpts *storage.StoreOptions, name string, def bool) bool {
	if value, ok := storeOpts.PullOptions[name]; ok {
		return strings.ToLower(value) == "true"
	}
	return def
}

func (c *chunkedDiffer) ApplyDiff(dest string, options *archive.TarOptions) (graphdriver.DriverWithDifferOutput, error) {
	defer c.layersCache.release()
	defer func() {
		if c.zstdReader != nil {
			c.zstdReader.Close()
		}
	}()

	bigData := map[string][]byte{
		bigDataKey: c.manifest,
	}
	output := graphdriver.DriverWithDifferOutput{
		Differ:  c,
		BigData: bigData,
	}

	storeOpts, err := types.DefaultStoreOptionsAutoDetectUID()
	if err != nil {
		return output, err
	}

	if !parseBooleanPullOption(&storeOpts, "enable_partial_images", false) {
		return output, errors.New("enable_partial_images not configured")
	}

	enableHostDedup := parseBooleanPullOption(&storeOpts, "enable_host_deduplication", false)

	// When the hard links deduplication is used, file attributes are ignored because setting them
	// modifies the source file as well.
	useHardLinks := parseBooleanPullOption(&storeOpts, "use_hard_links", false)

	// List of OSTree repositories to use for deduplication
	ostreeRepos := strings.Split(storeOpts.PullOptions["ostree_repos"], ":")

	// Generate the manifest
	var toc internal.TOC
	if err := json.Unmarshal(c.manifest, &toc); err != nil {
		return output, err
	}

	whiteoutConverter := archive.GetWhiteoutConverter(options.WhiteoutFormat, options.WhiteoutData)

	var missingParts []missingPart

	mergedEntries, err := c.mergeTocEntries(c.fileType, toc.Entries)
	if err != nil {
		return output, err
	}
	if err := maybeDoIDRemap(mergedEntries, options); err != nil {
		return output, err
	}

	if options.ForceMask != nil {
		uid, gid, mode, err := archive.GetFileOwner(dest)
		if err == nil {
			value := fmt.Sprintf("%d:%d:0%o", uid, gid, mode)
			if err := unix.Setxattr(dest, containersOverrideXattr, []byte(value), 0); err != nil {
				return output, err
			}
		}
	}

	dirfd, err := unix.Open(dest, unix.O_RDONLY|unix.O_PATH, 0)
	if err != nil {
		return output, fmt.Errorf("cannot open %q: %w", dest, err)
	}
	defer unix.Close(dirfd)

	// hardlinks can point to missing files.  So create them after all files
	// are retrieved
	var hardLinks []hardLinkToCreate

	missingPartsSize, totalChunksSize := int64(0), int64(0)
	for i, r := range mergedEntries {
		if options.ForceMask != nil {
			value := fmt.Sprintf("%d:%d:0%o", r.UID, r.GID, r.Mode&07777)
			r.Xattrs[containersOverrideXattr] = base64.StdEncoding.EncodeToString([]byte(value))
			r.Mode = int64(*options.ForceMask)
		}

		mode := os.FileMode(r.Mode)

		r.Name = filepath.Clean(r.Name)
		r.Linkname = filepath.Clean(r.Linkname)

		t, err := typeToTarType(r.Type)
		if err != nil {
			return output, err
		}
		if whiteoutConverter != nil {
			hdr := archivetar.Header{
				Typeflag: t,
				Name:     r.Name,
				Linkname: r.Linkname,
				Size:     r.Size,
				Mode:     r.Mode,
				Uid:      r.UID,
				Gid:      r.GID,
			}
			handler := whiteoutHandler{
				Dirfd: dirfd,
				Root:  dest,
			}
			writeFile, err := whiteoutConverter.ConvertReadWithHandler(&hdr, r.Name, &handler)
			if err != nil {
				return output, err
			}
			if !writeFile {
				continue
			}
		}
		switch t {
		case tar.TypeReg:
			// Create directly empty files.
			if r.Size == 0 {
				// Used to have a scope for cleanup.
				createEmptyFile := func() error {
					file, err := openFileUnderRoot(r.Name, dirfd, newFileFlags, 0)
					if err != nil {
						return err
					}
					defer file.Close()
					if err := setFileAttrs(dirfd, file, mode, &r, options, false); err != nil {
						return err
					}
					return nil
				}
				if err := createEmptyFile(); err != nil {
					return output, err
				}
				continue
			}

		case tar.TypeDir:
			if err := safeMkdir(dirfd, mode, r.Name, &r, options); err != nil {
				return output, err
			}
			continue

		case tar.TypeLink:
			dest := dest
			dirfd := dirfd
			mode := mode
			r := r
			hardLinks = append(hardLinks, hardLinkToCreate{
				dest:     dest,
				dirfd:    dirfd,
				mode:     mode,
				metadata: &r,
			})
			continue

		case tar.TypeSymlink:
			if err := safeSymlink(dirfd, mode, &r, options); err != nil {
				return output, err
			}
			continue

		case tar.TypeChar:
		case tar.TypeBlock:
		case tar.TypeFifo:
			/* Ignore.  */
		default:
			return output, fmt.Errorf("invalid type %q", t)
		}

		totalChunksSize += r.Size

		finalizeFile := func(dstFile *os.File) error {
			if dstFile != nil {
				defer dstFile.Close()
				if err := setFileAttrs(dirfd, dstFile, mode, &r, options, false); err != nil {
					return err
				}
			}
			return nil
		}

		found, dstFile, _, err := findFileInOtherLayers(c.layersCache, &r, dirfd, useHardLinks)
		if err != nil {
			return output, err
		}
		if found {
			if err := finalizeFile(dstFile); err != nil {
				return output, err
			}
			continue
		}

		found, dstFile, _, err = findFileInOSTreeRepos(&r, ostreeRepos, dirfd, useHardLinks)
		if err != nil {
			return output, err
		}
		if found {
			if err := finalizeFile(dstFile); err != nil {
				return output, err
			}
			continue
		}

		if enableHostDedup {
			found, dstFile, _, err = findFileOnTheHost(&r, dirfd, useHardLinks, c.copyBuffer)
			if err != nil {
				return output, err
			}
			if found {
				if err := finalizeFile(dstFile); err != nil {
					return output, err
				}
				continue
			}
		}

		missingPartsSize += r.Size
		if t == tar.TypeReg {
			remainingSize := r.Size
			for _, chunk := range r.Chunks {
				compressedSize := int64(chunk.EndOffset - chunk.Offset)
				size := remainingSize
				if chunk.ChunkSize > 0 {
					size = chunk.ChunkSize
				}
				remainingSize = remainingSize - size

				rawChunk := ImageSourceChunk{
					Offset: uint64(chunk.Offset),
					Length: uint64(compressedSize),
				}
				file := missingFileChunk{
					File:             &mergedEntries[i],
					CompressedSize:   compressedSize,
					UncompressedSize: size,
				}
				mp := missingPart{
					SourceChunk: &rawChunk,
					Chunks: []missingFileChunk{
						file,
					},
				}

				root, path, offset := c.layersCache.findChunkInOtherLayers(chunk)
				if offset >= 0 {
					missingPartsSize -= size
					mp.OriginFile = &originFile{
						Root:   root,
						Path:   path,
						Offset: offset,
					}
				}
				missingParts = append(missingParts, mp)
			}
		}
	}
	// There are some missing files.  Prepare a multirange request for the missing chunks.
	if len(missingParts) > 0 {
		missingParts = mergeMissingChunks(missingParts, maxNumberMissingChunks)
		if err := c.retrieveMissingFiles(dest, dirfd, missingParts, options); err != nil {
			return output, err
		}
	}

	for _, m := range hardLinks {
		if err := safeLink(m.dirfd, m.mode, m.metadata, options); err != nil {
			return output, err
		}
	}

	if totalChunksSize > 0 {
		logrus.Debugf("Missing %d bytes out of %d (%.2f %%)", missingPartsSize, totalChunksSize, float32(missingPartsSize*100.0)/float32(totalChunksSize))
	}
	return output, nil
}

func mustSkipFile(fileType compressedFileType, e internal.FileMetadata) bool {
	// ignore the metadata files for the estargz format.
	if fileType != fileTypeEstargz {
		return false
	}
	switch e.Name {
	// ignore the metadata files for the estargz format.
	case estargz.PrefetchLandmark, estargz.NoPrefetchLandmark, estargz.TOCTarName:
		return true
	}
	return false
}

func (c *chunkedDiffer) mergeTocEntries(fileType compressedFileType, entries []internal.FileMetadata) ([]internal.FileMetadata, error) {
	countNextChunks := func(start int) int {
		count := 0
		for _, e := range entries[start:] {
			if e.Type != TypeChunk {
				return count
			}
			count++
		}
		return count
	}

	size := 0
	for _, entry := range entries {
		if mustSkipFile(fileType, entry) {
			continue
		}
		if entry.Type != TypeChunk {
			size++
		}
	}

	mergedEntries := make([]internal.FileMetadata, size)
	m := 0
	for i := 0; i < len(entries); i++ {
		e := entries[i]
		if mustSkipFile(fileType, e) {
			continue
		}
		if e.Type == TypeChunk {
			return nil, fmt.Errorf("chunk type without a regular file")
		}

		if e.Type == TypeReg {
			nChunks := countNextChunks(i + 1)

			e.Chunks = make([]*internal.FileMetadata, nChunks+1)
			for j := 0; j <= nChunks; j++ {
				e.Chunks[j] = &entries[i+j]
				e.EndOffset = entries[i+j].EndOffset
			}
			i += nChunks
		}
		mergedEntries[m] = e
		m++
	}
	// stargz/estargz doesn't store EndOffset so let's calculate it here
	lastOffset := c.tocOffset
	for i := len(mergedEntries) - 1; i >= 0; i-- {
		if mergedEntries[i].EndOffset == 0 {
			mergedEntries[i].EndOffset = lastOffset
		}
		if mergedEntries[i].Offset != 0 {
			lastOffset = mergedEntries[i].Offset
		}

		lastChunkOffset := mergedEntries[i].EndOffset
		for j := len(mergedEntries[i].Chunks) - 1; j >= 0; j-- {
			mergedEntries[i].Chunks[j].EndOffset = lastChunkOffset
			mergedEntries[i].Chunks[j].Size = mergedEntries[i].Chunks[j].EndOffset - mergedEntries[i].Chunks[j].Offset
			lastChunkOffset = mergedEntries[i].Chunks[j].Offset
		}
	}
	return mergedEntries, nil
}
