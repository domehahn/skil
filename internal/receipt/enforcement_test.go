package receipt

import "testing"

func goodReceipt() (EnforcementReceipt, EnforcementExpectation) {
	want := EnforcementExpectation{"sha256:pol", "sha256:sub", "rt-1", "inv-1"}
	return EnforcementReceipt{Stage: StageEnforced, PolicyDecisionDigest: "sha256:pol", SubjectDigest: "sha256:sub",
		RuntimeIdentity: "rt-1", InvocationID: "inv-1", TransportStatus: 200,
		Ack: &EnforcementAck{Accepted: true, Enforced: true, PolicyDigest: "sha256:pol"}}, want
}

func TestEnforcedReceiptValidates(t *testing.T) {
	r, want := goodReceipt()
	if err := ValidateEnforcement(r, want); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyProvenEnforcementValidates(t *testing.T) {
	mutations := map[string]func(*EnforcementReceipt){
		"attempted only":         func(r *EnforcementReceipt) { r.Stage = StageAttempted },
		"transport only":         func(r *EnforcementReceipt) { r.Stage = StageTransport },
		"accepted not enforced":  func(r *EnforcementReceipt) { r.Stage = StageAccepted },
		"explicit failure":       func(r *EnforcementReceipt) { r.Stage = StageFailed },
		"HTTP 200 without ack":   func(r *EnforcementReceipt) { r.Ack = nil },
		"ack not enforced":       func(r *EnforcementReceipt) { r.Ack.Enforced = false },
		"ack not accepted":       func(r *EnforcementReceipt) { r.Ack.Accepted = false },
		"ack reports error":      func(r *EnforcementReceipt) { r.Ack.Error = "denied by kernel" },
		"ack other policy":       func(r *EnforcementReceipt) { r.Ack.PolicyDigest = "sha256:other" },
		"other policy decision":  func(r *EnforcementReceipt) { r.PolicyDecisionDigest = "sha256:other" },
		"other subject":          func(r *EnforcementReceipt) { r.SubjectDigest = "sha256:other" },
		"other runtime":          func(r *EnforcementReceipt) { r.RuntimeIdentity = "rt-2" },
		"other invocation":       func(r *EnforcementReceipt) { r.InvocationID = "inv-2" },
		"HTTP 500 with ok ack":   func(r *EnforcementReceipt) { r.TransportStatus = 500 },
		"non-zero exit with ack": func(r *EnforcementReceipt) { r.ExitCode = 1 },
	}
	for name, mutate := range mutations {
		r, want := goodReceipt()
		mutate(&r)
		if ValidateEnforcement(r, want) == nil {
			t.Errorf("%s: validated", name)
		}
	}
	r, _ := goodReceipt()
	if ValidateEnforcement(r, EnforcementExpectation{}) == nil {
		t.Error("empty expectation validated")
	}
}

func TestGateModes(t *testing.T) {
	type in struct {
		mode                        EnforcementMode
		available, blocked, failOpn bool
	}
	cases := []struct {
		in   in
		want GateAction
	}{
		{in{ModeEnforce, true, false, false}, ActionAllow},
		{in{ModeEnforce, true, true, true}, ActionDeny},
		{in{ModeEnforce, false, false, false}, ActionDeny},
		{in{ModeEnforce, false, false, true}, ActionWarn},
		{in{ModeAdvise, false, false, false}, ActionWarn},
		{in{ModeAdvise, true, true, false}, ActionWarn},
		{in{ModeObserve, false, true, false}, ActionAllow},
	}
	for _, c := range cases {
		got, err := DecideGate(c.in.mode, c.in.available, c.in.blocked, c.in.failOpn)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %s,%v want %s", c.in, got, err, c.want)
		}
	}
	if got, err := DecideGate("bogus", true, false, true); err == nil || got != ActionDeny {
		t.Fatal("unknown mode must deny")
	}
}
