package subdomain

import (
	"os"
	"path/filepath"
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
