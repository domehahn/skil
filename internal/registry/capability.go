package registry

import (
	"regexp"
	"sort"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
	"gopkg.in/yaml.v3"
)

var synonymMap = map[string]string{
	"k8s":            "kubernetes",
	"kubectl":        "kubectl",
	"helm install":   "deploy",
	"helm upgrade":   "deploy",
	"kubectl apply":  "deploy",
	"kubectl create": "deploy",
	"docker build":   "build",
	"docker run":     "execute",
	"git push":       "deploy",
	"tf apply":       "deploy",
	"terraform":      "terraform",
}

type CapabilityWeights struct {
	Actions     float64
	Tools       float64
	Resources   float64
	Permissions float64
	Domain      float64
}

func DefaultCapabilityWeights() CapabilityWeights {
	return CapabilityWeights{
		Actions:     0.35,
		Tools:       0.25,
		Resources:   0.20,
		Permissions: 0.10,
		Domain:      0.10,
	}
}

func ExtractCapabilities(workspace string, files []skil.File) (CapabilityFingerprint, error) {
	var fp CapabilityFingerprint

	actionSet := make(map[string]bool)
	toolSet := make(map[string]bool)
	resourceSet := make(map[string]bool)
	permissionSet := make(map[string]bool)
	domainSet := make(map[string]bool)
	integrationSet := make(map[string]bool)

	for _, f := range files {
		contentStr := string(f.Data)
		baseName := strings.ToLower(filepathBase(f.Path))

		if baseName == "skil.yaml" || baseName == "skil.yml" {
			var manifest struct {
				Domain       []string `yaml:"domain"`
				Capabilities []string `yaml:"capabilities"`
				Tools        []string `yaml:"tools"`
				Permissions  []string `yaml:"permissions"`
				Resources    []string `yaml:"resources"`
			}
			if err := yaml.Unmarshal(f.Data, &manifest); err == nil {
				for _, d := range manifest.Domain {
					domainSet[normalizeTerm(d)] = true
				}
				for _, c := range manifest.Capabilities {
					actionSet[normalizeTerm(c)] = true
				}
				for _, t := range manifest.Tools {
					toolSet[normalizeTerm(t)] = true
				}
				for _, p := range manifest.Permissions {
					permissionSet[normalizeTerm(p)] = true
				}
				for _, r := range manifest.Resources {
					resourceSet[normalizeTerm(r)] = true
				}
			}
		}

		if baseName == "skill.md" {
			extractCapabilitiesFromMarkdown(contentStr, domainSet, actionSet, toolSet, resourceSet, permissionSet, integrationSet)
		}
	}

	fp.Domain = mapToSortedSlice(domainSet)
	fp.Actions = mapToSortedSlice(actionSet)
	fp.Tools = mapToSortedSlice(toolSet)
	fp.Resources = mapToSortedSlice(resourceSet)
	fp.Permissions = mapToSortedSlice(permissionSet)
	fp.Integrations = mapToSortedSlice(integrationSet)

	return fp, nil
}

func extractCapabilitiesFromMarkdown(content string, domainSet, actionSet, toolSet, resourceSet, permissionSet, integrationSet map[string]bool) {
	lower := strings.ToLower(content)

	domains := []string{"kubernetes", "terraform", "npm", "pip", "cargo", "docker", "aws", "gcp", "azure", "github", "gitlab", "slack"}
	for _, d := range domains {
		if strings.Contains(lower, d) {
			domainSet[d] = true
		}
	}

	actions := []string{"deploy", "rollback", "canary", "health-check", "scan", "audit", "lint", "build", "publish", "monitor", "test", "validate", "cleanup", "restart"}
	for _, a := range actions {
		if strings.Contains(lower, a) {
			actionSet[a] = true
		}
	}

	tools := []string{"kubectl", "helm", "docker", "git", "terraform", "pip", "npm", "cargo", "pytest", "yara", "trivy"}
	for _, t := range tools {
		if strings.Contains(lower, t) {
			toolSet[t] = true
		}
	}

	resources := []string{"deployment", "service", "pod", "ingress", "secret", "configmap", "cluster", "container", "image", "pipeline", "repository", "vectorstore", "rag"}
	for _, r := range resources {
		if strings.Contains(lower, r) {
			resourceSet[r] = true
		}
	}

	permissions := []string{"cluster-read", "cluster-write", "shell", "network", "filesystem.read", "filesystem.write", "bypass"}
	for _, p := range permissions {
		if strings.Contains(lower, p) {
			permissionSet[p] = true
		}
	}
}

func CalculateCapabilityOverlap(cand, exist CapabilityFingerprint, weights CapabilityWeights) CapabilityOverlapResult {
	actionScore, actionShared, candOnlyActions, _ := setOverlap(cand.Actions, exist.Actions)
	toolScore, toolShared, candOnlyTools, _ := setOverlap(cand.Tools, exist.Tools)
	resourceScore, resourceShared, _, _ := setOverlap(cand.Resources, exist.Resources)
	permissionScore, permShared, _, _ := setOverlap(cand.Permissions, exist.Permissions)
	domainScore, domainShared, _, _ := setOverlap(cand.Domain, exist.Domain)

	overall := (actionScore * weights.Actions) +
		(toolScore * weights.Tools) +
		(resourceScore * weights.Resources) +
		(permissionScore * weights.Permissions) +
		(domainScore * weights.Domain)

	overlapping := combineUnique(actionShared, toolShared, resourceShared, permShared, domainShared)
	uniqueCand := combineUnique(candOnlyActions, candOnlyTools)

	return CapabilityOverlapResult{
		ActionOverlap:           actionScore,
		ToolOverlap:             toolScore,
		ResourceOverlap:         resourceScore,
		PermissionOverlap:       permissionScore,
		OverallScore:            overall,
		UniqueCapabilities:      uniqueCand,
		OverlappingCapabilities: overlapping,
	}
}

// DirectionalContainment checks if candidate capabilities are a subset or superset of existing.
func DirectionalContainment(cand, exist []string) (candSubExist float64, existSubCand float64) {
	if len(cand) == 0 && len(exist) == 0 {
		return 1.0, 1.0
	}
	if len(cand) == 0 {
		return 1.0, 0.0
	}
	if len(exist) == 0 {
		return 0.0, 1.0
	}

	existMap := make(map[string]bool, len(exist))
	for _, item := range exist {
		existMap[item] = true
	}
	candMap := make(map[string]bool, len(cand))
	for _, item := range cand {
		candMap[item] = true
	}

	candInExist := 0
	for _, c := range cand {
		if existMap[c] {
			candInExist++
		}
	}

	existInCand := 0
	for _, e := range exist {
		if candMap[e] {
			existInCand++
		}
	}

	return float64(candInExist) / float64(len(cand)), float64(existInCand) / float64(len(exist))
}

func setOverlap(a, b []string) (jaccard float64, shared []string, aOnly []string, bOnly []string) {
	if len(a) == 0 && len(b) == 0 {
		return 1.0, nil, nil, nil
	}
	bMap := make(map[string]bool, len(b))
	for _, v := range b {
		bMap[v] = true
	}
	aMap := make(map[string]bool, len(a))
	for _, v := range a {
		aMap[v] = true
	}

	for _, v := range a {
		if bMap[v] {
			shared = append(shared, v)
		} else {
			aOnly = append(aOnly, v)
		}
	}
	for _, v := range b {
		if !aMap[v] {
			bOnly = append(bOnly, v)
		}
	}

	union := len(a) + len(b) - len(shared)
	if union == 0 {
		return 0.0, shared, aOnly, bOnly
	}
	return float64(len(shared)) / float64(union), shared, aOnly, bOnly
}

func normalizeTerm(t string) string {
	lower := strings.TrimSpace(strings.ToLower(t))
	if norm, ok := synonymMap[lower]; ok {
		return norm
	}
	re := regexp.MustCompile(`[^a-z0-9\-]+`)
	return re.ReplaceAllString(lower, "")
}

func filepathBase(path string) string {
	parts := strings.Split(filepathToSlash(path), "/")
	return parts[len(parts)-1]
}

func filepathToSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func mapToSortedSlice(m map[string]bool) []string {
	slice := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			slice = append(slice, k)
		}
	}
	sort.Strings(slice)
	return slice
}

func combineUnique(slices ...[]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slices {
		for _, item := range s {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}
	sort.Strings(result)
	return result
}
