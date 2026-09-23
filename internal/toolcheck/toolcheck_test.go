package toolcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Krutik090/scan-helper/internal/modules"
)

func TestPresent_AbsolutePathAndPATHLookup(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "faketool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !Present(bin) {
		t.Errorf("an existing executable at an absolute path should be present")
	}
	if Present(filepath.Join(dir, "missing")) {
		t.Errorf("a non-existent path should not be present")
	}
	if !Present("sh") {
		t.Errorf("a bare name on PATH (sh) should resolve")
	}
	if Present("") {
		t.Errorf("an empty path should never be present")
	}

	nonexec := filepath.Join(dir, "nonexec")
	if err := os.WriteFile(nonexec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if Present(nonexec) {
		t.Errorf("a non-executable file should not be present")
	}
}

func TestCheck_ReportsPerTool(t *testing.T) {
	got := Check([]modules.ToolRequirement{
		{Name: "shell", BinPath: "sh"},
		{Name: "ghost", BinPath: "/definitely/not/here"},
	})
	if !got["shell"] || got["ghost"] {
		t.Fatalf("unexpected check result: %+v", got)
	}
}
