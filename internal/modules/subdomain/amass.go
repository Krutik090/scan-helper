package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
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
// amass's own exit code is not a reliable signal, so the output files
// are what decide success — the JSON file first (it carries addresses
// amass already resolved), falling back to the plain name list. Same
// order the Node implementation used.
func runAmass(ctx context.Context, bin, domain string, timeoutMinutes int, workDir string) ([]Subdomain, []string, error) {
	prefix := filepath.Join(workDir, "amass")
	cmd := exec.CommandContext(ctx, bin,
		"enum", "-d", domain,
		"-timeout", strconv.Itoa(timeoutMinutes),
		"-nocolor",
		"-oA", prefix,
	)
	cmd.Env = os.Environ()
	_ = cmd.Run()

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
	return nil, names, nil
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
