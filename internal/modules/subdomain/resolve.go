package subdomain

import (
	"context"
	"net"
	"sync"
	"time"
)

const lookupTimeout = 5 * time.Second

// resolveFunc resolves one hostname to an IP, or "" if it doesn't
// resolve. It is a parameter rather than a hard-coded call so tests can
// prove the pool's behaviour without touching real DNS.
type resolveFunc func(ctx context.Context, name string) string

func realResolve(ctx context.Context, name string) string {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(lookupCtx, name)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// resolveAll resolves every name through a bounded pool of `workers`
// goroutines: a fan-out over one shared channel, fan-in over another.
//
// Wall-clock is O(n/workers) rather than the O(n) of sequential lookups,
// and because workers pull individually, one slow name delays only
// itself — unlike fixed-size sequential batches, where the whole batch
// waits for its slowest member before the next batch starts.
func resolveAll(ctx context.Context, names []string, workers int, resolve resolveFunc) []Subdomain {
	if workers < 1 {
		workers = 1
	}
	if len(names) == 0 {
		return nil
	}

	in := make(chan string)
	out := make(chan Subdomain, len(names))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range in {
				ip := resolve(ctx, name)
				status := "Inactive"
				if ip != "" {
					status = "Active"
				}
				out <- Subdomain{Sub: name, IP: ip, Status: status}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, n := range names {
			select {
			case in <- n:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	results := make([]Subdomain, 0, len(names))
	for s := range out {
		results = append(results, s)
	}
	return results
}

// fillMissingIPs resolves only the entries that don't already have an IP.
// amass's JSON output already carries addresses for many names; there is
// no reason to ask DNS again for those.
func fillMissingIPs(ctx context.Context, subs []Subdomain, workers int, resolve resolveFunc) []Subdomain {
	var missing []string
	for _, s := range subs {
		if s.IP == "" {
			missing = append(missing, s.Sub)
		}
	}

	resolved := make(map[string]Subdomain, len(missing))
	if len(missing) > 0 {
		for _, s := range resolveAll(ctx, missing, workers, resolve) {
			resolved[s.Sub] = s
		}
	}

	out := make([]Subdomain, len(subs))
	for i, s := range subs {
		if s.IP == "" {
			if got, ok := resolved[s.Sub]; ok {
				out[i] = got
				continue
			}
			s.Status = "Inactive"
			out[i] = s
			continue
		}
		if s.Status == "" {
			s.Status = "Active"
		}
		out[i] = s
	}
	return out
}
