//go:build linux && composefs && cgo
// +build linux,composefs,cgo

package overlay

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"github.com/containers/storage/pkg/loopback"
	"golang.org/x/sys/unix"
)

/*
#cgo LDFLAGS: -l composefs -l yajl

#include <string.h>
#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <yajl/yajl_tree.h>
#include <getopt.h>

#include <libcomposefs/lcfs-writer.h>

char *fread_file(FILE *stream, size_t *length)
{
	char *buf = NULL;
	size_t alloc = BUFSIZ;
	{
		struct stat st;

		if (fstat(fileno(stream), &st) >= 0 && S_ISREG(st.st_mode)) {
			off_t pos = ftello(stream);

			if (pos >= 0 && pos < st.st_size) {
				off_t alloc_off = st.st_size - pos;
				if (SIZE_MAX - 1 < (uintmax_t)(alloc_off)) {
					errno = ENOMEM;
					return NULL;
				}

				alloc = alloc_off + 1;
			}
		}
	}

	if (!(buf = malloc(alloc)))
		return NULL;

	{
		size_t size = 0;
		int save_errno;

		for (;;) {
			size_t requested = alloc - size;
			size_t count = fread(buf + size, 1, requested, stream);
			size += count;

			if (count != requested) {
				save_errno = errno;
				if (ferror(stream))
					break;

				if (size < alloc - 1) {
					char *reduce_buf = realloc(buf, size + 1);
					if (reduce_buf != NULL)
						buf = reduce_buf;
				}

				buf[size] = '\0';
				*length = size;
				return buf;
			}

			{
				char *temp_buf;

				if (alloc == SIZE_MAX) {
					save_errno = ENOMEM;
					break;
				}

				if (alloc < SIZE_MAX - alloc / 2)
					alloc = alloc + alloc / 2;
				else {
					save_errno = E2BIG;
					break;
				}

				if (!(temp_buf = realloc(buf, alloc))) {
					save_errno = errno;
					break;
				}

				buf = temp_buf;
			}
		}

		free(buf);
		errno = save_errno;
		return NULL;
	}
}

static int b64_input(char c)
{
	const char table[64] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i;

	for (i = 0; i < 64; i++) {
		if (table[i] == c)
			return i;
	}
	return -1;
}

static int base64_decode(const char *iptr, size_t isize, char *optr,
			 size_t osize, size_t *nbytes)
{
	int i = 0, tmp = 0, pad = 0;
	size_t consumed = 0;
	unsigned char data[4];

	*nbytes = 0;
	while (consumed < isize && (*nbytes) + 3 < osize) {
		while ((i < 4) && (consumed < isize)) {
			tmp = b64_input(*iptr++);
			consumed++;
			if (tmp != -1)
				data[i++] = tmp;
			else if (*(iptr - 1) == '=') {
				data[i++] = '\0';
				pad++;
			}
		}

		if (i == 4) {
			*optr++ = (data[0] << 2) | ((data[1] & 0x30) >> 4);
			*optr++ = ((data[1] & 0xf) << 4) | ((data[2] & 0x3c) >> 2);
			*optr++ = ((data[2] & 0x3) << 6) | data[3];
			(*nbytes) += 3 - pad;
		} else {
			consumed -= i;
			return consumed;
		}
		i = 0;
	}
	return consumed;
}

static yajl_val parse_file(FILE *f)
{
	size_t l;
	yajl_val node;
	char *content;
	char errbuf[1024];

	content = fread_file(f, &l);
	if (content == NULL)
		return NULL;

	errbuf[0] = '\0';

	node = yajl_tree_parse(content, errbuf, sizeof(errbuf));
	free(content);
	if (node == NULL) {
		fprintf(stderr, "parse_error: %s\n", errbuf);
		return NULL;
	}

	return node;
}

static yajl_val get_child(yajl_val node, const char *name, int type)
{
	const char *path[] = { name, NULL };

	return yajl_tree_get(node, path, type);
}

static struct lcfs_node_s *append_child(struct lcfs_node_s *dir, const char *name)
{
	struct lcfs_node_s *child;
	struct lcfs_node_s *parent;

	for (parent = dir; parent != NULL; parent = lcfs_node_get_parent(parent)) {
		if (lcfs_node_get_mode(parent) == 0) {
			lcfs_node_set_mode(parent, 0755 | S_IFDIR);
		}
	}

	child = lcfs_node_new();
	if (child == NULL)
		return NULL;

	if (lcfs_node_add_child(dir, child, name) < 0) {
		lcfs_node_unref(child);
		return NULL;
	}

	return child;
}

static int fill_xattrs(struct lcfs_node_s *node, yajl_val xattrs)
{
	size_t i;
	char v_buffer[4096];

	if (!YAJL_IS_OBJECT(xattrs))
		return 0;

	for (i = 0; i < YAJL_GET_OBJECT(xattrs)->len; i++) {
		int r;
		size_t written;
		const char *v, *k = YAJL_GET_OBJECT(xattrs)->keys[i];

		if (!YAJL_IS_STRING(YAJL_GET_OBJECT(xattrs)->values[i])) {
			return -1;
		}

		v = YAJL_GET_STRING(YAJL_GET_OBJECT(xattrs)->values[i]);

		r = base64_decode(v, strlen(v), v_buffer, sizeof(v_buffer), &written);
		if (r < 0) {
			return -1;
		}

		r = lcfs_node_set_xattr(node, k, v_buffer, written);
		if (r < 0) {
			return -1;
		}
	}

	return 0;
}

static struct lcfs_node_s *get_node(struct lcfs_node_s *root, const char *what)
{
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;

	path = strdup(what);
	if (path == NULL)
		return NULL;

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		if (node == root && strcmp(it, "..") == 0)
			continue;
		node = lcfs_node_lookup_child(node, it);
		if (!node)
			break;
	}

	free(path);
	return node;
}

static int fill_file(const char *typ, struct lcfs_node_s *root,
		     struct lcfs_node_s *node, yajl_val entry)
{
	const char *payload = NULL;
	char payload_buffer[128];
	uint16_t min = 0, maj = 0;
	mode_t mode = 0;
	yajl_val v;
	int res;
	bool is_regular_file = false;

	if (node == NULL) {
		return 0;
	}

	if (strcmp(typ, "reg") == 0) {
		mode |= S_IFREG;
		is_regular_file = true;
	} else if (strcmp(typ, "dir") == 0)
		mode |= S_IFDIR;
	else if (strcmp(typ, "char") == 0)
		mode |= S_IFCHR;
	else if (strcmp(typ, "block") == 0)
		mode |= S_IFBLK;
	else if (strcmp(typ, "fifo") == 0)
		mode |= S_IFIFO;
	else if (strcmp(typ, "symlink") == 0) {
		mode |= S_IFLNK;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			return -1;
		}

		payload = YAJL_GET_STRING(v);
	} else if (strcmp(typ, "hardlink") == 0) {
		struct lcfs_node_s *target;

		mode |= S_IFREG;

		v = get_child(entry, "linkName", yajl_t_string);
		if (!v) {
			error(0, 0, "linkName not specified");
			return -1;
		}

		target = get_node(root, YAJL_GET_STRING(v));
		if (!target) {
			error(0, 0, "could not find target %s", YAJL_GET_STRING(v));
			return -1;
		}

		lcfs_node_make_hardlink(node, target);
	}

	v = get_child(entry, "mode", yajl_t_number);
	if (v)
		mode |= (YAJL_GET_INTEGER(v));

	lcfs_node_set_mode(node, mode);

	v = get_child(entry, "uid", yajl_t_number);
	if (v)
		lcfs_node_set_uid(node, YAJL_GET_INTEGER(v));

	v = get_child(entry, "gid", yajl_t_number);
	if (v)
		lcfs_node_set_gid(node, YAJL_GET_INTEGER(v));

	if ((mode & S_IFMT) != S_IFDIR) {
		v = get_child(entry, "size", yajl_t_number);
		if (v)
			lcfs_node_set_size(node, YAJL_GET_INTEGER(v));
	}

	v = get_child(entry, "devMinor", yajl_t_number);
	if (v)
		min = YAJL_GET_INTEGER(v);
	v = get_child(entry, "devMajor", yajl_t_number);
	if (v)
		maj = YAJL_GET_INTEGER(v);

	lcfs_node_set_rdev(node, makedev(maj, min));

	v = get_child(entry, "x-payload", yajl_t_string);
	if (v)
		payload = YAJL_GET_STRING(v);
	if (payload == NULL && is_regular_file) {
		char *tmp = NULL;
		v = get_child(entry, "digest", yajl_t_string);
		if (v) {
			tmp = YAJL_GET_STRING(v);
		}
		if (tmp) {
			if (strncmp(tmp, "sha256:", 7) == 0)
				tmp += 7;
			snprintf(payload_buffer, sizeof(payload_buffer) - 1,
				 "%.*s/%s", 2, tmp, tmp + 2);
			payload_buffer[sizeof(payload_buffer) - 1] = '\0';
			payload = payload_buffer;
		}
	}

	if (payload) {
		int r;

		r = lcfs_node_set_payload(node, payload);
		if (r < 0) {
			return -1;
		}
	}

	v = get_child(entry, "xattrs", yajl_t_object);
	if (v) {
		res = fill_xattrs(node, v);
		if (res < 0)
			return -1;
	}

	return 0;
}

static struct lcfs_node_s *get_or_add_node(const char *typ,
					   struct lcfs_node_s *root, yajl_val entry)
{
	yajl_val tmp;
	char *path, *dpath, *it;
	struct lcfs_node_s *node = root;
	int res;

	tmp = get_child(entry, "name", yajl_t_string);
	if (tmp == NULL) {
		return NULL;
	}

	it = YAJL_GET_STRING(tmp);
	if (it == NULL) {
		return NULL;
	}

	path = strdup(it);
	if (path == NULL)
		return NULL;

	dpath = path;
	while ((it = strsep(&dpath, "/"))) {
		struct lcfs_node_s *c;

		c = lcfs_node_lookup_child(node, it);
		if (c) {
			node = c;
			continue;
		}

		node = append_child(node, it);
		if (node == NULL) {
			free(path);
			return NULL;
		}
	}

	free(path);

	res = fill_file(typ, root, node, entry);
	if (res < 0) {
		return NULL;
	}
	return node;
}

static int do_file(struct lcfs_node_s *root, FILE *file)
{
	yajl_val entries, root_val, tmp;
        int ret = -1;
	size_t i;

	root_val = parse_file(file);
	if (root_val == NULL)
		return -1;

	if (!YAJL_IS_OBJECT(root_val))
		goto cleanup;

	entries = get_child(root_val, "entries", yajl_t_array);
	if (entries == NULL)
		goto cleanup;

	for (i = 0; i < YAJL_GET_ARRAY(entries)->len; i++) {
		static struct lcfs_node_s *n;
		const char *typ;
		yajl_val entry = YAJL_GET_ARRAY(entries)->values[i];

		tmp = get_child(entry, "type", yajl_t_string);
		if (tmp == NULL)
			goto cleanup;

		typ = YAJL_GET_STRING(tmp);

		if (typ == NULL || (strcmp(typ, "chunk") == 0))
			continue;

		n = get_or_add_node(typ, root, entry);
		if (n == NULL)
			goto cleanup;
	}

	ret = 0;

cleanup:
	yajl_tree_free(root_val);
	return ret;
}

static ssize_t write_cb(void *_file, void *buf, size_t count)
{
	FILE *file = _file;

	return fwrite(buf, 1, count, file);
}

int convert_json(FILE *f, int out_fd)
{
	struct lcfs_write_options_s options = { 0 };
	struct lcfs_node_s *root = NULL;
        FILE *out_file = NULL;
	int ret = -1;

	out_file = fdopen(out_fd, "w");
	if (out_file == NULL) {
		close(out_fd);
		goto cleanup;
	}

	root = lcfs_node_new();
	if (root == NULL)
		goto cleanup;

	if (do_file(root, f) < 0)
		goto cleanup;

	options.format = LCFS_FORMAT_COMPOSEFS;
	options.file = out_file;
	options.file_write_cb = write_cb;
	options.format = LCFS_FORMAT_EROFS;

	if (lcfs_write_to(root, &options) < 0)
		goto cleanup;

	ret = 0;
cleanup:
	if (root)
		lcfs_node_unref(root);
	if (out_file)
		fclose(out_file);
	return ret;
}
*/
import "C"

func composeFsSupported() bool {
	return true
}

func generateComposeFsBlob(toc []byte, destFile string) error {
	cstring := C.CString(string(toc))
	defer C.free(unsafe.Pointer(cstring))

	outFd, err := unix.Openat(unix.AT_FDCWD, destFile, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}


	if writerJson, err := exec.LookPath("composefs-from-json"); err == nil {
		err := func() error {
			// Use a func to have a scope for the close.
			defer unix.Close(outFd)

			fd, err := unix.MemfdCreate("json-toc", unix.MFD_ALLOW_SEALING)
			if err != nil {
				return fmt.Errorf("failed to create memfd: %w", err)
			}
			defer unix.Close(fd)

			if err := unix.Ftruncate(fd, int64(len(toc))); err != nil {
				return fmt.Errorf("failed to truncate memfd: %w", err)
			}

			buf := toc
			for len(buf) > 0 {
				n, err := unix.Write(fd, buf)
				if err != nil {
					return fmt.Errorf("failed to write to memfd: %w", err)
				}
				buf = buf[n:]
			}

			cmd := exec.Command(writerJson, "--format=erofs", fmt.Sprintf("--out=/proc/self/fd/%d", outFd), fmt.Sprintf("/proc/self/fd/%d", fd))
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to convert json to erofs")
			}
			return nil
		}()
		if err != nil {
			return err
		}
	} else {
		f := C.fmemopen(unsafe.Pointer(cstring), C.size_t(len(toc)), C.CString("r"))
		if f == nil {
			return fmt.Errorf("failed to open memory stream")
		}
		defer C.fclose(f)

		// outFd ownership is passed to convert_json.
		ret := C.convert_json(f, C.int(outFd))
		if ret != 0 {
			return fmt.Errorf("failed to convert json to erofs")
		}
	}
	return nil
}

func mountErofsBlob(blobFile, mountPoint string) error {
	loop, err := loopback.AttachLoopDevice(blobFile)
	if err != nil {
		return err
	}
	defer loop.Close()

	return unix.Mount(loop.Name(), mountPoint, "erofs", unix.MS_RDONLY, "")
}
