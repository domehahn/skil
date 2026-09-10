package versioning

import (
	"testing"
)

func TestCompareSemVer(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.2.3-rc1", "1.2.3", -1},
		{"1.2.3", "1.2.3-rc1", 1},
		{"1.0.0", "1.0.0", 0},
		{"v2.0.0", "v1.9.9", 1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"1.0.0-alpha.1", "1.0.0-beta.1", -1},
	}

	for _, tt := range tests {
		res, err := CompareSemVer(tt.v1, tt.v2)
		if err != nil {
			t.Errorf("Unexpected error comparing %s and %s: %v", tt.v1, tt.v2, err)
		}
		if res != tt.expected {
			t.Errorf("CompareSemVer(%s, %s) = %d; want %d", tt.v1, tt.v2, res, tt.expected)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0a1", "1.0.0b1", -1},
		{"1.0.0b1", "1.0.0rc1", -1},
		{"1.0.0rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0post1", -1},
	}

	for _, tt := range tests {
		res, err := ComparePEP440(tt.v1, tt.v2)
		if err != nil {
			t.Errorf("Unexpected error comparing %s and %s: %v", tt.v1, tt.v2, err)
		}
		if res != tt.expected {
			t.Errorf("ComparePEP440(%s, %s) = %d; want %d", tt.v1, tt.v2, res, tt.expected)
		}
	}
}

func TestCompareMaven(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0-SNAPSHOT", "1.0.0-GA", -1},
		{"1.0.0-RC1", "1.0.0-GA", -1},
		{"1.0.0-GA", "1.0.0-GA", 0},
	}

	for _, tt := range tests {
		res, err := CompareMaven(tt.v1, tt.v2)
		if err != nil {
			t.Errorf("Unexpected error comparing %s and %s: %v", tt.v1, tt.v2, err)
		}
		if res != tt.expected {
			t.Errorf("CompareMaven(%s, %s) = %d; want %d", tt.v1, tt.v2, res, tt.expected)
		}
	}
}

func TestCompareEcosystemVersions(t *testing.T) {
	res, err := CompareEcosystemVersions(EcosystemSemVer, "1.2.3-rc1", "1.2.3")
	if err != nil || res != -1 {
		t.Errorf("CompareEcosystemVersions failed for SemVer: res=%d, err=%v", res, err)
	}
}
