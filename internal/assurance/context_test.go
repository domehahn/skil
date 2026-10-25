package assurance

import "testing"

func mustConstraint(t *testing.T, effect ConstraintEffect, confirm bool) AuthorizationConstraint {
	t.Helper()
	c, err := (AuthorizationConstraint{PrincipalID: "parent", Action: "execute", Resource: "shell", Scope: "workspace", Effect: effect, RequiresConfirmation: confirm, Provenance: EvidenceRef{ID: "ev-1"}}).Finalize()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthorizationContinuityDetectsWeakeningAndLoss(t *testing.T) {
	declared := mustConstraint(t, EffectDeny, false)
	allowed := declared
	allowed.PrincipalID = "child"
	allowed.Effect = EffectAllow
	allowed.Digest = ""
	allowed, _ = allowed.Finalize()
	drift := CompareConstraints([]AuthorizationConstraint{declared}, []AuthorizationConstraint{allowed}, "subagent")
	if len(drift) != 1 || drift[0].State != ConstraintLost {
		t.Fatalf("expected LOST, got %#v", drift)
	}

	confirm := mustConstraint(t, EffectAllow, true)
	noConfirm := confirm
	noConfirm.RequiresConfirmation = false
	noConfirm.Digest = ""
	noConfirm, _ = noConfirm.Finalize()
	drift = CompareConstraints([]AuthorizationConstraint{confirm}, []AuthorizationConstraint{noConfirm}, "compaction")
	if drift[0].State != ConstraintWeakened {
		t.Fatalf("expected WEAKENED, got %#v", drift)
	}
}

func TestChildNeverInheritsVerifiedAndSecurityDeltaChangesClosure(t *testing.T) {
	c := mustConstraint(t, EffectDeny, false)
	parent, err := FinalizeContext(AssuranceContext{
		PrincipalID: "agent-a", WorkspaceIdentity: "workspace:abc", SessionIdentity: "session:1",
		ModelIdentity: "model:a", ProviderIdentity: "provider:a", PolicyDigest: "sha256:p",
		InstructionsDigest: "sha256:i", Constraints: []AuthorizationConstraint{c}, EffectiveAuthority: []AuthorizationConstraint{c}, Verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	parent.Verified = true
	child, drift, err := DeriveChild(parent, "agent-b", "session:2", "subagent", ContextDelta{ModelIdentity: "model:b"})
	if err != nil {
		t.Fatal(err)
	}
	if child.Verified {
		t.Fatal("child inherited VERIFIED")
	}
	if child.ClosureDigest == parent.ClosureDigest {
		t.Fatal("security-relevant child delta preserved parent closure")
	}
	if len(drift) != 1 || drift[0].State != ConstraintPreserved {
		t.Fatalf("unexpected authority drift: %#v", drift)
	}
}

func TestAuthorityGraphFindsOnlyEvidenceBackedReachableEscalation(t *testing.T) {
	g := AuthorityGraph{Principals: []Principal{{"a", PrincipalAgent}, {"b", PrincipalSubagent}, {"shell", PrincipalTool}}, Edges: []AuthorityEdge{
		{From: "a", To: "b", Relation: RelationDelegatesTo, Evidence: EvidenceRef{ID: "ev-delegate"}},
		{From: "b", To: "shell", Relation: RelationAuthorizedFor, Capability: "shell", Evidence: EvidenceRef{ID: "ev-allow"}},
	}}
	escalations, err := g.TransitiveEscalations("a", []string{"shell"})
	if err != nil {
		t.Fatal(err)
	}
	if len(escalations) != 1 || len(escalations[0].Evidence) != 2 {
		t.Fatalf("expected proven escalation, got %#v", escalations)
	}
	g.Edges[1].Evidence = EvidenceRef{}
	escalations, err = g.TransitiveEscalations("a", []string{"shell"})
	if err != nil || len(escalations) != 0 {
		t.Fatalf("speculative edge produced escalation: %#v, %v", escalations, err)
	}
}

func FuzzWideningAuthorityNeverPreservesAttestation(f *testing.F) {
	f.Add("shell", "workspace")
	f.Fuzz(func(t *testing.T, resource, scope string) {
		if resource == "" || scope == "" {
			return
		}
		d, err := (AuthorizationConstraint{PrincipalID: "p", Action: "execute", Resource: resource, Scope: scope, Effect: EffectDeny}).Finalize()
		if err != nil {
			return
		}
		e := d
		e.Effect = EffectAllow
		e.Digest = ""
		e, _ = e.Finalize()
		drift := CompareConstraints([]AuthorizationConstraint{d}, []AuthorizationConstraint{e}, "tool")
		if len(drift) != 1 || drift[0].State == ConstraintPreserved {
			t.Fatal("widened authority preserved")
		}
	})
}
