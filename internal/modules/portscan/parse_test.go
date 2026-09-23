package portscan

import (
	"os"
	"testing"
)

// A trimmed but structurally exact nmap -oX document. The real captured
// fixture in testdata/ is parsed too (TestParseNmapXML_RealFixture), so
// both the schema this test encodes and the live schema stay honest.
const nmapXMLFixture = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -oX - scanme.nmap.org" version="7.94">
<host starttime="1695000000" endtime="1695000060">
<status state="up" reason="syn-ack"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.7" method="probed"/></port>
<port protocol="tcp" portid="9929"><state state="closed" reason="reset"/><service name="nping-echo"/></port>
<port protocol="tcp" portid="31337"><state state="open" reason="syn-ack"/><service name="tcpwrapped"/></port>
</ports>
</host>
</nmaprun>`

func TestParseNmapXML_KeepsOnlyOpenPortsWithServiceDetail(t *testing.T) {
	ports, ip, err := parseNmapXML([]byte(nmapXMLFixture))
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if ip != "45.33.32.156" {
		t.Errorf("ip = %q, want 45.33.32.156", ip)
	}
	if len(ports) != 3 {
		t.Fatalf("got %d ports, want 3 (the closed one must be dropped): %+v", len(ports), ports)
	}

	byPort := map[int]Port{}
	for _, p := range ports {
		byPort[p.Port] = p
	}
	ssh := byPort[22]
	if ssh.Protocol != "tcp" || ssh.Service != "ssh" || ssh.State != "Open" {
		t.Errorf("port 22: %+v", ssh)
	}
	if ssh.Version != "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13" {
		t.Errorf("port 22 version = %q, want product and version joined", ssh.Version)
	}
	if ssh.Risk != "Low" {
		t.Errorf("newly scanned ports start at Low risk, got %q", ssh.Risk)
	}
	// A service with no product/version must not produce a stray space.
	if got := byPort[31337].Version; got != "" {
		t.Errorf("port 31337 version = %q, want empty", got)
	}
	if _, found := byPort[9929]; found {
		t.Error("closed port 9929 must not be reported")
	}
}

func TestParseNmapXML_RealFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/nmap-sample.xml")
	if err != nil {
		t.Skipf("no captured fixture yet (%v) — run the capture step of Task 8", err)
	}
	ports, ip, err := parseNmapXML(data)
	if err != nil {
		t.Fatalf("parsing a real nmap capture failed: %v", err)
	}
	if ip == "" {
		t.Error("a real capture should carry an address")
	}
	for _, p := range ports {
		if p.Port == 0 || p.Protocol == "" || p.State != "Open" {
			t.Errorf("malformed port parsed from a real capture: %+v", p)
		}
	}
}

func TestParseNmapXML_HostDownOrNoPorts(t *testing.T) {
	const noHosts = `<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>`
	ports, ip, err := parseNmapXML([]byte(noHosts))
	if err != nil {
		t.Fatalf("a host-down scan is not a parse error: %v", err)
	}
	if len(ports) != 0 || ip != "" {
		t.Fatalf("got (%+v, %q), want (none, empty)", ports, ip)
	}
}

func TestParseNmapXML_GarbageIsAnError(t *testing.T) {
	if _, _, err := parseNmapXML([]byte("this is not xml at all")); err == nil {
		t.Fatal("expected a parse error for non-XML input")
	}
}
