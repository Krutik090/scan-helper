package modules

import (
	"strings"
	"testing"
)

func TestIsValidHostname(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"a plain hostname", "acme.test", true},
		{"a subdomain", "www.shop.acme.test", true},
		{"digits and hyphens inside labels", "web-01.eu-west-2.acme.test", true},
		{"mixed case", "WWW.Acme.Test", true},
		{"the fully-qualified trailing dot", "acme.test.", true},
		{"a single label", "localhost", true},
		{"an IPv4 literal", "10.0.0.1", true},
		{"a label at the 63-char limit", strings.Repeat("a", 63) + ".test", true},

		{"empty", "", false},
		{"a leading hyphen — an nmap option, not a host", "-oN", false},
		{"an nmap output-file injection", "-oN /etc/cron.d/x", false},
		{"an nmap script injection", "--script=http-put", false},
		{"a space", "acme.test evil.test", false},
		{"a slash", "acme.test/../etc", false},
		{"a shell metacharacter", "acme.test;id", false},
		{"a backtick", "acme.test`id`", false},
		{"a dollar", "$(id).test", false},
		{"a newline", "acme.test\nevil.test", false},
		{"a label ending in a hyphen", "acme-.test", false},
		{"a label starting with a hyphen", "acme.-test", false},
		{"an empty label", "acme..test", false},
		{"a leading dot", ".acme.test", false},
		{"an underscore", "_dmarc.acme.test", false},
		{"a label over 63 chars", strings.Repeat("a", 64) + ".test", false},
		{"a name over 253 chars", strings.Repeat("a.", 130) + "test", false},
		{"a bare dot", ".", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidHostname(tc.in); got != tc.want {
				t.Errorf("IsValidHostname(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
