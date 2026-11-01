package safeio

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReadFile bounds memory, rejects FIFOs/devices and final-component symlinks,
// and checks the opened object, not a prior pathname stat. Parent directories
// are still trusted; this is not an arbitrary-path sandbox.
func ReadFile(path string, max int64) ([]byte, error) {
	if max <= 0 || max == 1<<63-1 {
		return nil, fmt.Errorf("invalid file size limit")
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	f := os.NewFile(uintptr(fd), path)

	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("%s must be a regular file no larger than %d bytes", path, max)
	}

	return Read(f, max)
}

// Read preserves all bytes, including trailing newlines, but never consumes
// more than max+1 bytes. The extra byte detects oversize streams.
func Read(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 || max == 1<<63-1 {
		return nil, fmt.Errorf("invalid input size limit")
	}

	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		clear(data)

		return nil, err
	}

	if int64(len(data)) > max {
		clear(data)

		return nil, fmt.Errorf("input exceeds %d bytes", max)
	}

	return data, nil
}
