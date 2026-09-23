package subdomain

import "time"

// Subdomain is one entry of CTEMData.subdomains. The bson tags are the
// mongo-mode compatibility contract with the ThreatIntel backend — the
// driver would lowercase these names without them, which the backend
// does not expect.
type Subdomain struct {
	Sub              string     `json:"sub" bson:"sub"`
	IP               string     `json:"ip" bson:"ip"`
	Status           string     `json:"status" bson:"status"`
	AssetCriticality string     `json:"assetCriticality,omitempty" bson:"assetCriticality,omitempty"`
	SSLGrade         string     `json:"sslGrade,omitempty" bson:"sslGrade,omitempty"`
	SSLDaysRemaining *int       `json:"sslDaysRemaining,omitempty" bson:"sslDaysRemaining,omitempty"`
	SSLExpiresAt     *time.Time `json:"sslExpiresAt,omitempty" bson:"sslExpiresAt,omitempty"`
	RootDomain       string     `json:"rootDomain,omitempty" bson:"rootDomain,omitempty"`
	OwnerName        string     `json:"ownerName,omitempty" bson:"ownerName,omitempty"`
	OwnerEmail       string     `json:"ownerEmail,omitempty" bson:"ownerEmail,omitempty"`
	Source           string     `json:"source,omitempty" bson:"source,omitempty"`
	AddedAt          *time.Time `json:"addedAt,omitempty" bson:"addedAt,omitempty"`
	AddedBy          string     `json:"addedBy,omitempty" bson:"addedBy,omitempty"`
	LastCheckedAt    *time.Time `json:"lastCheckedAt,omitempty" bson:"lastCheckedAt,omitempty"`
	CheckError       string     `json:"checkError,omitempty" bson:"checkError,omitempty"`
}

// Result is what Run returns: this run's discovered and resolved
// subdomains for one domain, before any merge with stored state.
type Result struct {
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
}
