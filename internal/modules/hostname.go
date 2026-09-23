package modules

import "strings"

// Hostname length limits, from RFC 1035 §2.3.4.
const (
	maxHostnameLength = 253
	maxLabelLength    = 63
)

// IsValidHostname reports whether s is something that can only ever be a
// hostname — never an option, a path, or a shell word.
//
// This is the one gate between operator- and client-supplied names and
// the scanners' argv. nmap accepts options ANYWHERE on its command line,
// so a "domain" of `-oN /etc/cron.d/x` or `--script=...` is honoured as
// an option, not scanned as a target; the README tells operators to run
// this service as root or to grant it cap_net_raw, which is what turns
// that from a nuisance into a takeover. Port-scan targets are worse
// still: they come from STORED subdomain values, so a client-requested
// row beginning with "-" is a persisted injection that fires on every
// later scan.
//
// The rule is an allowlist by construction rather than a blocklist of
// dangerous characters: labels of ASCII letters, digits and hyphens,
// none starting or ending with a hyphen, separated by dots. Nothing
// beginning with "-", and no whitespace, slash, quote, semicolon,
// backtick, dollar or any other metacharacter, can satisfy it — there is
// no list of them to keep up to date.
//
// A single trailing dot (the fully-qualified form, "acme.test.") is
// accepted: it is legal DNS, the scanners take it, and stored rows can
// carry it. An underscore is NOT accepted; it appears in some service
// records but never in a host this tool should be scanning.
func IsValidHostname(s string) bool {
	// The trailing dot is part of the name, so it counts toward the
	// overall limit, but it does not make an empty final label.
	if s == "" || len(s) > maxHostnameLength {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}

	for _, label := range strings.Split(s, ".") {
		if !isValidLabel(label) {
			return false
		}
	}
	return true
}

func isValidLabel(label string) bool {
	if label == "" || len(label) > maxLabelLength {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}
