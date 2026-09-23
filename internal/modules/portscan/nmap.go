package portscan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// scanFunc scans one target, returning its open ports and resolved
// address. A parameter rather than a direct call so the worker pool can
// be tested without nmap installed.
type scanFunc func(ctx context.Context, target string) ([]Port, string, error)

// runNmap scans one target. Flags match the Node implementation:
// -sV service/version detection, --open open ports only, -T4 timing, and
// nmap's default top-1000 ports (no -p). `-oX -` streams XML to stdout,
// so there is no temp file to create, read back, or clean up.
//
// The `--` before the target is defence in depth behind
// modules.IsValidHostname: nmap honours options anywhere on its command
// line, so without it a target of `-oN /etc/cron.d/x` is an option, not
// a host. Verified against nmap 7.98: without `--` that argument writes
// the file; with it, nmap reports "Unable to split netmask from target
// expression" and writes nothing.
func runNmap(ctx context.Context, bin, target string, timeout time.Duration) ([]Port, string, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, bin, "-sV", "--open", "-T4", "-oX", "-", "--", target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if runCtx.Err() != nil {
			return nil, "", fmt.Errorf("nmap timed out scanning %s after %s", target, timeout)
		}
		// nmap can exit non-zero having still written usable XML (a host
		// it could not fully profile, for instance). Prefer real output
		// over the exit code; only a truly empty result is a failure.
		if stdout.Len() == 0 {
			return nil, "", fmt.Errorf("nmap failed on %s: %w: %s", target, err, stderr.String())
		}
	}
	return parseNmapXML(stdout.Bytes())
}
