package portscan

// Port is one open port finding. The bson tags match
// CTEMData.openPorts[].ports[] as the ThreatIntel backend reads it.
type Port struct {
	Port     int    `json:"port" bson:"port"`
	Protocol string `json:"protocol" bson:"protocol"`
	Service  string `json:"service" bson:"service"`
	// index.js always emitted version, as '' when nmap reported none, so
	// no bson omitempty here — the key is part of what the platform reads.
	Version string `json:"version,omitempty" bson:"version"`
	State   string `json:"state" bson:"state"`
	Risk    string `json:"risk" bson:"risk"`

	// Extra preserves every stored key this struct does not name — see
	// the long note on subdomain.Subdomain.Extra. A merge rewrites the
	// whole openPorts array, so without this a port row that merely
	// passes through would come back shorn of its `_id` and of anything
	// the platform has added to it.
	Extra map[string]any `json:"-" bson:",inline"`
}

// HostGroup is one host's open ports — the element type of
// CTEMData.openPorts.
type HostGroup struct {
	Host string `json:"host" bson:"host"`
	// Always emitted, as '' when nothing resolved — see Port.Version.
	IP         string `json:"ip,omitempty" bson:"ip"`
	Ports      []Port `json:"ports" bson:"ports"`
	RootDomain string `json:"rootDomain,omitempty" bson:"rootDomain,omitempty"`

	// Extra preserves every stored key this struct does not name,
	// starting with `_id` — see subdomain.Subdomain.Extra.
	Extra map[string]any `json:"-" bson:",inline"`
}

// Result is what Run returns: every host in scope that had at least one
// open port this run. A host with none is simply absent — see Merge.
type Result struct {
	Domain     string      `json:"domain"`
	HostGroups []HostGroup `json:"hostGroups"`
}
