package portscan

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// nmap's -oX schema, trimmed to what this tool uses. Parsing the XML
// rather than scraping -oN text means nmap's own structured output is
// the contract, instead of a regex over a human-readable report that
// shifts between versions.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Port []nmapPort `xml:"port"`
}

type nmapPort struct {
	PortID   string          `xml:"portid,attr"`
	Protocol string          `xml:"protocol,attr"`
	State    nmapPortState   `xml:"state"`
	Service  nmapPortService `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapPortService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// parseNmapXML turns one scan's XML into open-port findings plus the
// address nmap resolved. This tool scans one target per invocation, so
// only the first host element is read. A scan that found no host (target
// down) is not an error — it yields no ports.
func parseNmapXML(data []byte) ([]Port, string, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, "", fmt.Errorf("parsing nmap XML: %w", err)
	}
	if len(run.Hosts) == 0 {
		return nil, "", nil
	}
	host := run.Hosts[0]

	ip := ""
	for _, a := range host.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			ip = a.Addr
			break
		}
	}

	var ports []Port
	for _, p := range host.Ports.Port {
		// --open already filters these at scan time; checking the parsed
		// state too means a caller that drops the flag still gets truth.
		if p.State.State != "open" {
			continue
		}
		num, err := strconv.Atoi(p.PortID)
		if err != nil {
			continue // malformed entry: skip it, don't fail the scan
		}
		ports = append(ports, Port{
			Port:     num,
			Protocol: p.Protocol,
			Service:  p.Service.Name,
			Version:  strings.TrimSpace(p.Service.Product + " " + p.Service.Version),
			State:    "Open",
			// Newly scanned ports start Low; an analyst raises risk from
			// asset criticality. Matches the Node implementation.
			Risk: "Low",
		})
	}
	return ports, ip, nil
}
