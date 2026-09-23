package portscan

import "strings"

func normHost(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	return strings.TrimPrefix(s, "www.")
}

// belongsToDomain reports whether host is domain itself or a subdomain of it.
func belongsToDomain(host, domain string) bool {
	h, d := normHost(host), normHost(domain)
	if d == "" {
		return false
	}
	return h == d || strings.HasSuffix(h, "."+d)
}

// Merge swaps this domain's host groups for this run's findings, leaving
// every other root domain's groups untouched.
//
// Unlike the subdomain module's merge, this is a real replace within the
// domain, NOT an upsert. Every target in scope is actively re-scanned on
// every run, so a host that returns nothing now genuinely has no open
// ports, and keeping its previous ports would report something that is
// no longer true. Nothing here is hand-added the way a client-requested
// subdomain is, so there is nothing to preserve.
func Merge(existing, fresh []HostGroup, domain string) []HostGroup {
	kept := make([]HostGroup, 0, len(existing))
	for _, hg := range existing {
		if hg.Host == "" || !belongsToDomain(hg.Host, domain) {
			kept = append(kept, hg)
		}
	}
	merged := make([]HostGroup, 0, len(kept)+len(fresh))
	merged = append(merged, kept...)
	merged = append(merged, fresh...)
	return merged
}
