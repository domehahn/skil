package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

const RuleTaintPipeline = "SKIL-COMPOSE-TAINT-PIPELINE"

type TaintChain struct {
	ID          string        `json:"id"`
	RuleID      string        `json:"rule_id"`
	Severity    skil.Severity `json:"severity"`
	Title       string        `json:"title"`
	Message     string        `json:"message"`
	SourceSkill string        `json:"source_skill"`
	SourceType  string        `json:"source_type"`
	RelaySkill  string        `json:"relay_skill,omitempty"`
	SinkSkill   string        `json:"sink_skill"`
	SinkType    string        `json:"sink_type"`
	TaintPath   []string      `json:"taint_path"`
	Fingerprint string        `json:"fingerprint"`
}

type TaintResult struct {
	SchemaVersion string       `json:"schema_version"`
	Source        string       `json:"source"`
	Skills        []string     `json:"skills"`
	TaintChains   []TaintChain `json:"taint_chains"`
	GeneratedAt   time.Time    `json:"generated_at"`
}

var taintSources = map[string]bool{
	"network.outbound":     true,
	"http.fetch":           true,
	"user.prompt":          true,
	"file.read.external":   true,
	"mcp.untrusted_input":  true,
	"model.external-cli":   true,
	"hook.execute.command": true,
}

var taintSinks = map[string]bool{
	"commands.execute":            true,
	"permission.shell":            true,
	"permission.filesystem.write": true,
	"permission.bypass":           true,
	"hook.call.http":              true,
}

// AnalyzeTaintFlows performs inter-skill taint flow correlation across scanned skills.
func AnalyzeTaintFlows(source string, scans []skil.ScanResult) TaintResult {
	result := TaintResult{
		SchemaVersion: "1.0.0",
		Source:        source,
		TaintChains:   []TaintChain{},
		GeneratedAt:   time.Now().UTC(),
	}

	for _, scan := range scans {
		result.Skills = append(result.Skills, scan.Artifact.Name)
	}

	if len(scans) < 2 {
		return result
	}

	type SkillRole struct {
		Name       string
		HasSource  bool
		SourceType string
		HasSink    bool
		SinkType   string
	}

	roles := make([]SkillRole, len(scans))

	for i, scan := range scans {
		roles[i].Name = scan.Artifact.Name
		for _, obs := range scan.Observations {
			if taintSources[obs.Capability] && !roles[i].HasSource {
				roles[i].HasSource = true
				roles[i].SourceType = obs.Capability
			}
			if taintSinks[obs.Capability] && !roles[i].HasSink {
				roles[i].HasSink = true
				roles[i].SinkType = obs.Capability
			}
		}
		// Also check findings if capabilities were reported as findings
		for _, f := range scan.Findings {
			if f.Suppressed {
				continue
			}
			if strings.HasPrefix(f.RuleID, "SKIL-AGENT-HOOK-") || strings.HasPrefix(f.RuleID, "SKIL-SH-") || strings.HasPrefix(f.RuleID, "SKIL-PY-") {
				roles[i].HasSink = true
				roles[i].SinkType = f.RuleID
			}
		}
	}

	for i := 0; i < len(roles); i++ {
		if !roles[i].HasSource {
			continue
		}
		for j := 0; j < len(roles); j++ {
			if i == j || !roles[j].HasSink {
				continue
			}

			// Found source skill i and sink skill j
			path := []string{roles[i].Name, roles[j].Name}
			relaySkill := ""

			// Check for intermediate relay skill k if 3+ skills exist
			for k := 0; k < len(roles); k++ {
				if k != i && k != j {
					relaySkill = roles[k].Name
					path = []string{roles[i].Name, relaySkill, roles[j].Name}
					break
				}
			}

			fpSum := sha256.Sum256([]byte(strings.Join(path, "->") + ":" + roles[i].SourceType + ":" + roles[j].SinkType))
			fp := hex.EncodeToString(fpSum[:])

			chain := TaintChain{
				ID:          "TC-" + strings.ToUpper(fp[:12]),
				RuleID:      RuleTaintPipeline,
				Severity:    skil.SeverityCritical,
				Title:       fmt.Sprintf("Cross-skill taint pipeline: %s -> %s", roles[i].Name, roles[j].Name),
				Message:     fmt.Sprintf("Untrusted data source (%s) in skill %q flows to execution sink (%s) in skill %q across composition boundary.", roles[i].SourceType, roles[i].Name, roles[j].SinkType, roles[j].Name),
				SourceSkill: roles[i].Name,
				SourceType:  roles[i].SourceType,
				RelaySkill:  relaySkill,
				SinkSkill:   roles[j].Name,
				SinkType:    roles[j].SinkType,
				TaintPath:   path,
				Fingerprint: fp,
			}

			result.TaintChains = append(result.TaintChains, chain)
		}
	}

	sort.Slice(result.TaintChains, func(i, j int) bool {
		return result.TaintChains[i].ID < result.TaintChains[j].ID
	})

	return result
}
