package model

// VulnSearchResult is one row of the vulnerability search endpoint. JSON tags
// mirror the frontend VulnSearchResult type (frozen contract, ADR-002).
type VulnSearchResult struct {
	Cluster          string   `json:"cluster"`
	Namespace        string   `json:"namespace"`
	Name             string   `json:"name"`
	App              string   `json:"app"`
	Image            string   `json:"image"`
	VulnerabilityID  string   `json:"vulnerability_id"`
	Severity         string   `json:"severity"`
	Score            *float64 `json:"score"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	UpdatedAt        string   `json:"updated_at"`
}

// ComponentSearchResult is one row of the SBOM component search endpoint.
// JSON tags mirror the frontend ComponentSearchResult type.
type ComponentSearchResult struct {
	Cluster          string `json:"cluster"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	App              string `json:"app"`
	Image            string `json:"image"`
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	ComponentType    string `json:"component_type"`
	UpdatedAt        string `json:"updated_at"`
}
