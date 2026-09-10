package versioning

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Ecosystem identifies dependency package manager version semantics.
type Ecosystem string

const (
	EcosystemSemVer Ecosystem = "semver"
	EcosystemPEP440 Ecosystem = "pep440"
	EcosystemMaven  Ecosystem = "maven"
	EcosystemCargo  Ecosystem = "cargo"
	EcosystemNPM    Ecosystem = "npm"
)

// CompareEcosystemVersions compares two version strings according to ecosystem rules.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareEcosystemVersions(eco Ecosystem, v1, v2 string) (int, error) {
	v1Norm := strings.TrimSpace(v1)
	v2Norm := strings.TrimSpace(v2)

	if v1Norm == v2Norm {
		return 0, nil
	}

	switch eco {
	case EcosystemSemVer, EcosystemCargo, EcosystemNPM:
		return CompareSemVer(v1Norm, v2Norm)
	case EcosystemPEP440:
		return ComparePEP440(v1Norm, v2Norm)
	case EcosystemMaven:
		return CompareMaven(v1Norm, v2Norm)
	default:
		return CompareSemVer(v1Norm, v2Norm)
	}
}

var semverRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)

// CompareSemVer implements standard Semantic Versioning 2.0 comparison rules.
func CompareSemVer(v1, v2 string) (int, error) {
	v1Clean := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	v2Clean := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	m1 := semverRegex.FindStringSubmatch(v1Clean)
	m2 := semverRegex.FindStringSubmatch(v2Clean)

	if m1 == nil || m2 == nil {
		// Fallback to basic dot-separated numerical comparison
		return fallbackCompare(v1Clean, v2Clean), nil
	}

	// Compare major, minor, patch
	for i := 1; i <= 3; i++ {
		n1, _ := strconv.Atoi(m1[i])
		n2, _ := strconv.Atoi(m2[i])
		if n1 < n2 {
			return -1, nil
		}
		if n1 > n2 {
			return 1, nil
		}
	}

	pre1 := m1[4]
	pre2 := m2[4]

	// Non-prerelease > prerelease (e.g. 1.2.3 > 1.2.3-rc1)
	if pre1 == "" && pre2 != "" {
		return 1, nil
	}
	if pre1 != "" && pre2 == "" {
		return -1, nil
	}
	if pre1 == pre2 {
		return 0, nil
	}

	// Compare prerelease identifiers
	return comparePreReleaseIdentifiers(pre1, pre2), nil
}

func comparePreReleaseIdentifiers(pre1, pre2 string) int {
	parts1 := strings.Split(pre1, ".")
	parts2 := strings.Split(pre2, ".")

	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		p1 := parts1[i]
		p2 := parts2[i]

		n1, err1 := strconv.Atoi(p1)
		n2, err2 := strconv.Atoi(p2)

		if err1 == nil && err2 == nil {
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		} else if err1 == nil && err2 != nil {
			// Numeric identifiers have lower precedence than non-numeric
			return -1
		} else if err1 != nil && err2 == nil {
			return 1
		} else {
			if p1 < p2 {
				return -1
			}
			if p1 > p2 {
				return 1
			}
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

// ComparePEP440 implements Python PEP 440 version ordering (e.g. 1.0.0a1 < 1.0.0b1 < 1.0.0rc1 < 1.0.0).
func ComparePEP440(v1, v2 string) (int, error) {
	rank1 := getPEP440Rank(v1)
	rank2 := getPEP440Rank(v2)

	v1Base, phase1, num1 := parsePEP440(v1)
	v2Base, phase2, num2 := parsePEP440(v2)

	if v1Base != v2Base {
		return fallbackCompare(v1Base, v2Base), nil
	}

	if rank1 < rank2 {
		return -1, nil
	}
	if rank1 > rank2 {
		return 1, nil
	}

	if phase1 == phase2 {
		if num1 < num2 {
			return -1, nil
		}
		if num1 > num2 {
			return 1, nil
		}
	}

	return 0, nil
}

func parsePEP440(v string) (base string, phase string, num int) {
	re := regexp.MustCompile(`^(\d+(?:\.\d+)*)(?:(a|b|rc|dev|post)(\d+))?`)
	matches := re.FindStringSubmatch(v)
	if len(matches) < 2 {
		return v, "", 0
	}
	base = matches[1]
	if len(matches) >= 3 {
		phase = matches[2]
	}
	if len(matches) >= 4 && matches[3] != "" {
		num, _ = strconv.Atoi(matches[3])
	}
	return base, phase, num
}

func getPEP440Rank(v string) int {
	vLower := strings.ToLower(v)
	if strings.Contains(vLower, "dev") {
		return 1
	}
	if strings.Contains(vLower, "a") {
		return 2
	}
	if strings.Contains(vLower, "b") {
		return 3
	}
	if strings.Contains(vLower, "rc") {
		return 4
	}
	if strings.Contains(vLower, "post") {
		return 6
	}
	return 5 // Final release
}

// CompareMaven implements Maven version ordering (SNAPSHOT < alpha < beta < Milestone < CR/RC < GA/final).
func CompareMaven(v1, v2 string) (int, error) {
	rank1 := getMavenRank(v1)
	rank2 := getMavenRank(v2)

	base1 := getMavenBase(v1)
	base2 := getMavenBase(v2)

	if base1 != base2 {
		return fallbackCompare(base1, base2), nil
	}

	if rank1 < rank2 {
		return -1, nil
	}
	if rank1 > rank2 {
		return 1, nil
	}
	return 0, nil
}

func getMavenBase(v string) string {
	parts := strings.Split(v, "-")
	return parts[0]
}

func getMavenRank(v string) int {
	vUpper := strings.ToUpper(v)
	if strings.Contains(vUpper, "SNAPSHOT") {
		return 1
	}
	if strings.Contains(vUpper, "ALPHA") || strings.Contains(vUpper, ".A") || strings.Contains(vUpper, "-A") {
		return 2
	}
	if strings.Contains(vUpper, "BETA") || strings.Contains(vUpper, ".B") || strings.Contains(vUpper, "-B") {
		return 3
	}
	if strings.Contains(vUpper, "MILESTONE") || strings.Contains(vUpper, ".M") || strings.Contains(vUpper, "-M") {
		return 4
	}
	if strings.Contains(vUpper, "CR") || strings.Contains(vUpper, "RC") {
		return 5
	}
	if strings.Contains(vUpper, "GA") || strings.Contains(vUpper, "FINAL") || strings.Contains(vUpper, "RELEASE") {
		return 7
	}
	return 6
}

func fallbackCompare(v1, v2 string) int {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")

	minLen := len(p1)
	if len(p2) < minLen {
		minLen = len(p2)
	}

	for i := 0; i < minLen; i++ {
		n1, err1 := strconv.Atoi(p1[i])
		n2, err2 := strconv.Atoi(p2[i])

		if err1 == nil && err2 == nil {
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		} else {
			if p1[i] < p2[i] {
				return -1
			}
			if p1[i] > p2[i] {
				return 1
			}
		}
	}

	if len(p1) < len(p2) {
		return -1
	}
	if len(p1) > len(p2) {
		return 1
	}
	return 0
}

// FormatEcosystemVersion validates and formats a version string for display.
func FormatEcosystemVersion(eco Ecosystem, ver string) string {
	return fmt.Sprintf("[%s] %s", eco, strings.TrimSpace(ver))
}
