package subdomain

import "time"

// Subdomain is one entry of CTEMData.subdomains. The bson tags are the
// mongo-mode compatibility contract with the ThreatIntel backend — the
// driver would lowercase these names without them, which the backend
// does not expect.
type Subdomain struct {
	Sub              string `json:"sub" bson:"sub"`
	IP               string `json:"ip" bson:"ip"`
	Status           string `json:"status" bson:"status"`
	AssetCriticality string `json:"assetCriticality,omitempty" bson:"assetCriticality,omitempty"`
	SSLGrade         string `json:"sslGrade,omitempty" bson:"sslGrade,omitempty"`
	// No bson omitempty: index.js wrote `sslDaysRemaining: null` on every
	// row it created, and the platform reads the key. With omitempty a
	// nil would simply vanish from the document — a newly created row
	// would lack the key, and a stored row whose value IS null would lose
	// it on the next merge. The JSON tag keeps omitempty: the API
	// response shape is not part of the Mongo contract.
	SSLDaysRemaining *int       `json:"sslDaysRemaining,omitempty" bson:"sslDaysRemaining"`
	SSLExpiresAt     *time.Time `json:"sslExpiresAt,omitempty" bson:"sslExpiresAt,omitempty"`
	RootDomain       string     `json:"rootDomain,omitempty" bson:"rootDomain,omitempty"`
	OwnerName        string     `json:"ownerName,omitempty" bson:"ownerName,omitempty"`
	OwnerEmail       string     `json:"ownerEmail,omitempty" bson:"ownerEmail,omitempty"`
	Source           string     `json:"source,omitempty" bson:"source,omitempty"`
	AddedAt          *time.Time `json:"addedAt,omitempty" bson:"addedAt,omitempty"`
	AddedBy          string     `json:"addedBy,omitempty" bson:"addedBy,omitempty"`
	LastCheckedAt    *time.Time `json:"lastCheckedAt,omitempty" bson:"lastCheckedAt,omitempty"`
	CheckError       string     `json:"checkError,omitempty" bson:"checkError,omitempty"`

	// Extra is the catch-all for every key of a stored row this struct
	// does not name — `_id` above all, but also anything the ThreatIntel
	// platform has added to a row since this tool was written. Without
	// it, decoding a row into this struct and writing the struct back
	// would silently delete those keys: the merge rewrites the WHOLE
	// subdomains array, so a row that merely passes through is re-encoded
	// from whatever the struct captured.
	//
	// `bson:",inline"` splices the map's keys into the same document
	// rather than nesting them under a field. The driver refuses to
	// encode a key here that collides with a named field above, and never
	// decodes a named field's key into here, so the two can't fight.
	//
	// `json:"-"` keeps this storage plumbing out of the API response.
	//
	// A plain map (rather than bson.M) keeps the Mongo driver out of the
	// module packages, which the package doc for internal/modules
	// forbids; the driver only requires an inline field to be a map with
	// string keys.
	Extra map[string]any `json:"-" bson:",inline"`
}

// Result is what Run returns: this run's discovered and resolved
// subdomains for one domain, before any merge with stored state.
type Result struct {
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
}
