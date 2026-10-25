package skil

import "testing"

func TestUnknownSeverityNeverDowngrades(t *testing.T) {
	for _, label := range []string{"bogus", "severe", "moderate", "0", "none"} {
		n := NormalizeSeverity(label)
		if n.Known || n.Canonical != SeverityUnknown || n.Original != label {
			t.Fatalf("%q: %+v", label, n)
		}
		if SeverityRank(n.Canonical) < SeverityRank(SeverityHigh) {
			t.Fatalf("unknown %q ranks below HIGH", label)
		}
	}
}

func TestEmptyLabelNormalizesToUnknown(t *testing.T) {
	if NormalizeSeverity("").Known {
		t.Fatal("empty label must not be known")
	}
	if SeverityRank("") != 0 {
		t.Fatal("absent severity ranks 0")
	}
}

func TestSeverityRankMonotonic(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i]) <= SeverityRank(order[i-1]) {
			t.Fatalf("%s !> %s", order[i], order[i-1])
		}
	}
	if n := NormalizeSeverity(" critical "); !n.Known || n.Canonical != SeverityCritical {
		t.Fatalf("%+v", n)
	}
}
