package subdomain

import (
	"strings"
	"time"
)

// hostKey is an entry's identity: lowercased, trailing dot stripped,
// "www." KEPT. www.acme.test and acme.test are two different entries —
// deliberately different from normHost, which strips www. for
// ROOT-DOMAIN ATTRIBUTION only. Conflating the two is what previously
// let a per-entry check write to the wrong row.
func hostKey(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// normHost additionally strips a leading "www." — for deciding which
// root domain a host belongs to, never for entry identity.
func normHost(s string) string {
	return strings.TrimPrefix(hostKey(s), "www.")
}

// belongsToDomain reports whether host is domain itself or a subdomain of it.
func belongsToDomain(host, domain string) bool {
	h, d := normHost(host), normHost(domain)
	if d == "" {
		return false
	}
	return h == d || strings.HasSuffix(h, "."+d)
}

// MergeResult reports what a merge did, for logging and job progress.
type MergeResult struct {
	Merged   []Subdomain
	Created  int
	Updated  int
	Retained int
	Kept     int // entries of OTHER root domains, untouched
}

// Merge upserts a scan's findings for one domain into a tenant's full
// subdomain list (which spans every root domain it owns):
//
//   - an entry not belonging to domain is kept untouched;
//   - a found-again entry takes the fresh ip/status/rootDomain but keeps
//     every admin-owned field from the stored entry (criticality, owner,
//     source, addedAt/By, lastCheckedAt, checkError, SSL data) — a
//     rescan must never erase what an admin, a client request, or a
//     per-entry check put there;
//   - an unmatched fresh entry is created with source "scan";
//   - a stored entry of this domain that the scan did NOT return is
//     retained untouched, because hand-added and client-requested
//     subdomains are not things the scanner independently rediscovers.
//
// O(n+m) through one hash map keyed by hostKey — never a nested scan.
func Merge(existing, fresh []Subdomain, domain string, now time.Time) MergeResult {
	root := normHost(domain)

	kept := make([]Subdomain, 0, len(existing))
	prev := make(map[string]Subdomain, len(existing))
	for _, s := range existing {
		if s.Sub == "" {
			// A stored row with no identity cannot be matched against a scan result,
			// but must not be deleted by a merge — pass it through unchanged.
			kept = append(kept, s)
			continue
		}
		if belongsToDomain(s.Sub, domain) {
			key := hostKey(s.Sub)
			if _, alreadyPresent := prev[key]; alreadyPresent {
				// Pre-existing duplicate rows are upstream corruption; de-duplicating them
				// is not this function's job, but losing one silently is unacceptable.
				// First write wins the prev slot; the duplicate survives untouched in kept.
				kept = append(kept, s)
			} else {
				prev[key] = s
			}
		} else {
			kept = append(kept, s)
		}
	}

	out := make([]Subdomain, 0, len(fresh))
	seen := make(map[string]struct{}, len(fresh))
	created, updated := 0, 0

	for _, raw := range fresh {
		if raw.Sub == "" {
			continue
		}
		key := hostKey(raw.Sub)
		if _, dup := seen[key]; dup {
			continue // scanners can repeat a name
		}
		seen[key] = struct{}{}

		status := "Inactive"
		if raw.IP != "" {
			status = "Active"
		}
		entry := Subdomain{Sub: key, IP: raw.IP, Status: status, RootDomain: root}

		stored, found := prev[key]
		if !found {
			t := now
			entry.Source = "scan"
			entry.AddedAt = &t
			out = append(out, entry)
			created++
			continue
		}
		delete(prev, key)

		entry.AssetCriticality = stored.AssetCriticality
		entry.SSLGrade = stored.SSLGrade
		entry.SSLDaysRemaining = stored.SSLDaysRemaining
		entry.SSLExpiresAt = stored.SSLExpiresAt
		entry.OwnerName = stored.OwnerName
		entry.OwnerEmail = stored.OwnerEmail
		entry.Source = stored.Source
		entry.AddedAt = stored.AddedAt
		entry.AddedBy = stored.AddedBy
		entry.LastCheckedAt = stored.LastCheckedAt
		entry.CheckError = stored.CheckError
		// Everything the stored row carried that this struct does not
		// name — `_id` first of all. An updated entry is built fresh from
		// the scan result, so without this line the round trip through
		// Mongo would drop those keys. Kept and retained entries pass
		// through whole and carry theirs already.
		entry.Extra = stored.Extra
		if entry.Source == "" {
			entry.Source = "scan"
		}
		out = append(out, entry)
		updated++
	}

	retained := make([]Subdomain, 0, len(prev))
	for _, s := range prev {
		retained = append(retained, s)
	}

	merged := make([]Subdomain, 0, len(kept)+len(out)+len(retained))
	merged = append(merged, kept...)
	merged = append(merged, out...)
	merged = append(merged, retained...)

	return MergeResult{Merged: merged, Created: created, Updated: updated, Retained: len(retained), Kept: len(kept)}
}
