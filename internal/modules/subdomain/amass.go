package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type amassRecord struct {
	Name      string `json:"name"`
	Addresses []struct {
		IP string `json:"ip"`
	} `json:"addresses"`
}

// runAmass runs `amass enum -oA <prefix>` and reads back what it wrote.
// amass's own exit code is not a reliable signal on its own — a non-zero
// exit with usable output in either file is still tolerated, same as the
// Node implementation did. But an exit that produced NEITHER file is a
// different case entirely: a crash, a bad binary, no network — and
// reporting that as a clean empty result would let a real failure look
// like "domain has no subdomains" to everything downstream. So the
// command's own error is only consulted once both output sources have
// come back empty.
func runAmass(ctx context.Context, bin, domain string, timeoutMinutes int, workDir string) ([]Subdomain, []string, error) {
	prefix := filepath.Join(workDir, "amass")
	cmd := exec.CommandContext(ctx, bin,
		"enum", "-d", domain,
		"-timeout", strconv.Itoa(timeoutMinutes),
		"-nocolor",
		"-oA", prefix,
	)
	cmd.Env = os.Environ()
	runErr := cmd.Run()

	records, err := parseAmassJSON(prefix + ".json")
	if err != nil {
		return nil, nil, err
	}
	if len(records) > 0 {
		return records, nil, nil
	}

	names, err := parseAmassTxt(prefix + ".txt")
	if err != nil {
		return nil, nil, err
	}
	if len(names) > 0 {
		return nil, names, nil
	}

	// Neither file had anything. If the command itself failed, that's
	// why — surface it rather than returning a silent empty success.
	if runErr != nil {
		return nil, nil, fmt.Errorf("amass (%s) produced no output for %s: %w", bin, domain, runErr)
	}
	return nil, nil, nil
}

// parseAmassJSON reads amass's JSON output: one object per line, NOT a
// JSON array. A line that doesn't parse is skipped rather than failing
// the whole scan. A missing file is not an error — amass may not have
// written one.
func parseAmassJSON(path string) ([]Subdomain, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Subdomain
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), scannerMaxLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec amassRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Name == "" {
			continue
		}
		ip := ""
		if len(rec.Addresses) > 0 {
			ip = rec.Addresses[0].IP
		}
		out = append(out, Subdomain{Sub: rec.Name, IP: ip})
	}
	return out, scanner.Err()
}

// parseAmassTxt reads the plain one-name-per-line output.
func parseAmassTxt(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var names []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), scannerMaxLine)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			names = append(names, line)
		}
	}
	return names, scanner.Err()
}
