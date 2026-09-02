package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ReadProjected reads a small secret file while allowing Kubernetes' projected
// ..data symlink layout. The resolved file must remain inside its configured
// mount directory and is opened without following a final symlink.
func ReadProjected(path string, maximumSize int64, allowedModes ...os.FileMode) ([]byte, error) {
	clean := filepath.Clean(path)
	if path == "" || clean != path || maximumSize <= 0 || len(allowedModes) == 0 {
		return nil, errors.New("secret file contract is invalid")
	}
	root := filepath.Dir(clean)
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("secret mount directory must be a real directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("resolve secret mount directory")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, errors.New("resolve projected secret file")
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, errors.New("projected secret file escapes its mount directory")
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open projected secret file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumSize || !modeAllowed(info.Mode().Perm(), allowedModes) {
		return nil, fmt.Errorf("secret file must be a small regular file with an approved mode")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil || int64(len(raw)) > maximumSize {
		return nil, errors.New("read projected secret file")
	}
	return raw, nil
}

func modeAllowed(mode os.FileMode, allowed []os.FileMode) bool {
	for _, candidate := range allowed {
		if mode == candidate {
			return true
		}
	}
	return false
}
