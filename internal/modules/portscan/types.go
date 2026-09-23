package portscan

// Port is one open port finding. The bson tags match
// CTEMData.openPorts[].ports[] as the ThreatIntel backend reads it.
type Port struct {
	Port     int    `json:"port" bson:"port"`
	Protocol string `json:"protocol" bson:"protocol"`
	Service  string `json:"service" bson:"service"`
	Version  string `json:"version,omitempty" bson:"version,omitempty"`
	State    string `json:"state" bson:"state"`
	Risk     string `json:"risk" bson:"risk"`
}

// HostGroup is one host's open ports — the element type of
// CTEMData.openPorts.
type HostGroup struct {
	Host       string `json:"host" bson:"host"`
	IP         string `json:"ip,omitempty" bson:"ip,omitempty"`
	Ports      []Port `json:"ports" bson:"ports"`
	RootDomain string `json:"rootDomain,omitempty" bson:"rootDomain,omitempty"`
}

// Result is what Run returns: every host in scope that had at least one
// open port this run. A host with none is simply absent — see Merge.
type Result struct {
	Domain     string      `json:"domain"`
	HostGroups []HostGroup `json:"hostGroups"`
}
