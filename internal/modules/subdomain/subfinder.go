package subdomain

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
)

const scannerMaxLine = 1024 * 1024

// runSubfinder streams subfinder's stdout line by line as it arrives.
// A busy domain can return tens of thousands of names; buffering the
// whole output and splitting it afterwards would hold all of it twice.
//
// There is no `--` here, unlike the nmap invocation: the domain is the
// VALUE of -d, not a positional argument, so `--` has nowhere to go that
// would guard it — it would only become a stray positional. What guards
// this call is modules.IsValidHostname, applied in discover before
// either tool is invoked.
func runSubfinder(ctx context.Context, bin, domain string) ([]string, error) {
	cmd := exec.CommandContext(ctx, bin, "-d", domain, "-silent")
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var names []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), scannerMaxLine)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			names = append(names, line)
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	// subfinder can exit non-zero after a partial failure while still
	// having produced usable names; a partial result beats none.
	if len(names) == 0 {
		if waitErr != nil {
			return nil, waitErr
		}
		if scanErr != nil {
			return nil, scanErr
		}
	}
	return names, nil
}
