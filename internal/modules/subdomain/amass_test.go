package subdomain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One JSON object per line is amass's actual -oA .json format — not a
// JSON array. A malformed line must be skipped, not abort the parse.
const amassJSONFixture = `{"name":"api.acme.test","addresses":[{"ip":"10.0.0.7","cidr":"10.0.0.0/8"}]}
{"name":"vpn.acme.test","addresses":[]}
not json at all
{"name":"","addresses":[{"ip":"10.0.0.9"}]}
{"name":"mail.acme.test","addresses":[{"ip":"10.0.0.8"}]}
`

func TestParseAmassJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte(amassJSONFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseAmassJSON(path)
	if err != nil {
		t.Fatalf("parseAmassJSON: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (malformed line and empty name skipped): %+v", len(got), got)
	}
	byName := map[string]string{}
	for _, s := range got {
		byName[s.Sub] = s.IP
	}
	if byName["api.acme.test"] != "10.0.0.7" {
		t.Errorf("api.acme.test ip = %q", byName["api.acme.test"])
	}
	if byName["vpn.acme.test"] != "" {
		t.Errorf("vpn.acme.test has no addresses, ip should be empty, got %q", byName["vpn.acme.test"])
	}
}

func TestParseAmassJSON_MissingFileIsNotAnError(t *testing.T) {
	got, err := parseAmassJSON(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || got != nil {
		t.Fatalf("got (%v, %v), want (nil, nil) — amass may simply not have written a JSON file", got, err)
	}
}

func TestParseAmassTxt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	body := "api.acme.test\n\n  mail.acme.test  \nvpn.acme.test\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseAmassTxt(path)
	if err != nil {
		t.Fatalf("parseAmassTxt: %v", err)
	}
	want := []string{"api.acme.test", "mail.acme.test", "vpn.acme.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestRunAmass_TotalFailureIsAnError covers the gap the brief left open:
// if amass errors out and writes NEITHER output file, that must surface
// as an error, not as a silent "zero subdomains found" success — an
// empty result set downstream is read as "legitimately nothing found",
// which is a worse outcome than a visible failure.
func TestRunAmass_TotalFailureIsAnError(t *testing.T) {
	dir := t.TempDir()
	records, names, err := runAmass(context.Background(), "/nonexistent/amass-binary-xyz", "acme.test", 1, dir)
	if err == nil {
		t.Fatal("expected an error when amass fails to run and writes no output")
	}
	if records != nil || names != nil {
		t.Fatalf("a failed run should return no records and no names, got %v / %v", records, names)
	}
	if !strings.Contains(err.Error(), "amass") {
		t.Errorf("error should mention amass, got %q", err)
	}
}

// TestRunAmass_SuccessWithNoOutputIsNotAnError pins the other half of
// the rule: a command that exits cleanly but happens to write no output
// files is a legitimate "amass found nothing" result, not an error. No
// scanner binary is installed in this environment, so this uses
// /bin/true — a real, always-present executable that exits 0 and writes
// nothing — to exercise the runErr == nil / no-files path without
// depending on amass or subfinder being installed.
func TestRunAmass_SuccessWithNoOutputIsNotAnError(t *testing.T) {
	if _, statErr := os.Stat("/bin/true"); statErr != nil {
		t.Skip("/bin/true not available in this environment; cannot exercise the clean-exit/no-output path")
	}
	dir := t.TempDir()
	records, names, err := runAmass(context.Background(), "/bin/true", "acme.test", 1, dir)
	if err != nil {
		t.Fatalf("a clean exit with no output should not be an error, got %v", err)
	}
	if records != nil || names != nil {
		t.Fatalf("expected no records and no names, got %v / %v", records, names)
	}
}
