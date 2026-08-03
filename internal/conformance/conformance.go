// Package conformance scores skil's own coverage of the Agent Skill Security
// Properties Specification (ASPS, compat/asps) against named profiles — a
// full-specification "core" profile or a narrower slice (MCP, multi-agent,
// identity, ...) relevant to a specific integration — so an operator or a
// CI gate can ask "how much of ASPS-MCP does this skil build actually
// implement" instead of only "what does skil implement" in the abstract.
package conformance

import (
	"fmt"
	"sort"

	"github.com/domehahn/skil/compat/asps"
)

// Profile is a named subset of ASPS domains to score conformance against.
// A nil Domains list means every domain in the registry.
type Profile struct {
	Name    string
	Domains []string
}

// Profiles are the named, orderable slices of ASPS a caller can request by
// key (e.g. "mcp"). New profiles are additive: they only ever narrow which
// existing registry domains are considered, never change scoring.
var Profiles = map[string]Profile{
	"core":         {Name: "ASPS-Core", Domains: nil},
	"identity":     {Name: "ASPS-Identity", Domains: []string{"ASP-04"}},
	"multi-agent":  {Name: "ASPS-MultiAgent", Domains: []string{"ASP-08"}},
	"supply-chain": {Name: "ASPS-SupplyChain", Domains: []string{"ASP-09"}},
	"mcp":          {Name: "ASPS-MCP", Domains: []string{"ASP-10"}},
	"privacy":      {Name: "ASPS-Privacy", Domains: []string{"ASP-03"}},
	"resilience":   {Name: "ASPS-Resilience", Domains: []string{"ASP-12"}},
	"audit":        {Name: "ASPS-Audit", Domains: []string{"ASP-14"}},
}

// ProfileNames returns every registered profile key, sorted, for usage text
// and input validation.
func ProfileNames() []string {
	names := make([]string, 0, len(Profiles))
	for name := range Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DomainReport tallies one ASPS domain's properties by skil_status.
type DomainReport struct {
	DomainID       string  `json:"domain_id"`
	DomainName     string  `json:"domain_name"`
	Total          int     `json:"total"`
	Implemented    int     `json:"implemented"`
	ProviderBacked int     `json:"provider_backed"`
	Partial        int     `json:"partial"`
	Missing        int     `json:"missing"`
	Score          float64 `json:"score"`
}

// Report is a full conformance evaluation of one profile.
type Report struct {
	Profile         string         `json:"profile"`
	Snapshot        string         `json:"asps_snapshot"`
	Domains         []DomainReport `json:"domains"`
	TotalProperties int            `json:"total_properties"`
	Score           float64        `json:"score"`
}

// statusWeight is how fully a property's skil_status counts toward
// conformance: IMPLEMENTED and PROVIDER_BACKED are complete controls (the
// latter simply depends on an external provider being configured rather
// than being weaker), PARTIAL is half credit for a real but incomplete
// control, and NEW earns nothing.
func statusWeight(status string) float64 {
	switch status {
	case "IMPLEMENTED", "PROVIDER_BACKED":
		return 1
	case "PARTIAL":
		return 0.5
	default:
		return 0
	}
}

// Evaluate scores reg against the named profile.
func Evaluate(reg asps.Registry, profileKey string) (Report, error) {
	profile, ok := Profiles[profileKey]
	if !ok {
		return Report{}, fmt.Errorf("unknown conformance profile %q (available: %v)", profileKey, ProfileNames())
	}
	allowed := map[string]bool{}
	for _, d := range profile.Domains {
		allowed[d] = true
	}
	scoped := len(profile.Domains) > 0

	byDomain := map[string]*DomainReport{}
	var order []string
	var totalWeight float64
	var totalCount int
	for _, p := range reg.Properties {
		if scoped && !allowed[p.DomainID] {
			continue
		}
		dr, exists := byDomain[p.DomainID]
		if !exists {
			dr = &DomainReport{DomainID: p.DomainID, DomainName: p.Domain}
			byDomain[p.DomainID] = dr
			order = append(order, p.DomainID)
		}
		dr.Total++
		switch p.SKILStatus {
		case "IMPLEMENTED":
			dr.Implemented++
		case "PROVIDER_BACKED":
			dr.ProviderBacked++
		case "PARTIAL":
			dr.Partial++
		default:
			dr.Missing++
		}
		totalWeight += statusWeight(p.SKILStatus)
		totalCount++
	}
	sort.Strings(order)

	report := Report{Profile: profile.Name, Snapshot: reg.Snapshot}
	for _, id := range order {
		dr := byDomain[id]
		dr.Score = domainScore(*dr)
		report.Domains = append(report.Domains, *dr)
		report.TotalProperties += dr.Total
	}
	if totalCount > 0 {
		report.Score = totalWeight / float64(totalCount)
	}
	return report, nil
}

func domainScore(dr DomainReport) float64 {
	if dr.Total == 0 {
		return 0
	}
	weight := float64(dr.Implemented) + float64(dr.ProviderBacked) + float64(dr.Partial)*0.5
	return weight / float64(dr.Total)
}
