// Package toolcheck answers "is this external binary actually here?" for
// the /health endpoint and for start-up warnings.
package toolcheck

import (
	"os"
	"os/exec"
	"strings"

	"github.com/Krutik090/scan-helper/internal/modules"
)

// Present reports whether binPath is runnable — either as an absolute or
// relative path that exists, or as a bare command name found on PATH.
func Present(binPath string) bool {
	if strings.TrimSpace(binPath) == "" {
		return false
	}
	if strings.ContainsRune(binPath, os.PathSeparator) {
		info, err := os.Stat(binPath)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(binPath)
	return err == nil
}

// Check maps each requirement's tool name to whether it is present.
func Check(reqs []modules.ToolRequirement) map[string]bool {
	out := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		out[r.Name] = Present(r.BinPath)
	}
	return out
}
