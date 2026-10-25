package verification_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"testing/quick"
	"time"

	"github.com/domehahn/skil/internal/attackpath"
	"github.com/domehahn/skil/internal/continuous"
	"github.com/domehahn/skil/internal/eval"
	"github.com/domehahn/skil/internal/evidence"
	"github.com/domehahn/skil/internal/receipt"
	"github.com/domehahn/skil/internal/redteam"
	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/pkg/skil"
)

type invariantEnv struct {
	issuerPub, runtimePub   ed25519.PublicKey
	issuerPriv, runtimePriv ed25519.PrivateKey
	issuerKeyID, rtKeyID    string
	now                     time.Time
}

func setupInvariantEnv(t testing.TB) invariantEnv {
	t.Helper()
	iPub, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return invariantEnv{
		issuerPub:   iPub,
		issuerPriv:  iPriv,
		issuerKeyID: signing.KeyID(iPub),
		runtimePub:  rPub,
		runtimePriv: rPriv,
		rtKeyID:     signing.KeyID(rPub),
		now:         time.Date(2026, 10, 26, 2, 0, 0, 0, time.UTC),
	}
}

func (e invariantEnv) newGateway(oracle receipt.AssuranceValidityOracle) *receipt.ExecutionGateway {
	return receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://skrun-invariant-cluster",
		TrustedIssuers: map[string][]string{
			"skgate://authority": {e.issuerKeyID},
		},
		TrustedPublicKeys: map[string]string{
			e.issuerKeyID: base64.StdEncoding.EncodeToString(e.issuerPub),
		},
		AssuranceOracle:  oracle,
		RevokedDigests:   map[string]string{},
		RevokedDecisions: map[string]string{},
		Nonces:           receipt.NewNonceLedger(),
		Now:              func() time.Time { return e.now },
	})
}

func (e invariantEnv) validRequestAndAuth() (receipt.ProtectedOperationRequest, receipt.ExecutionAuthorization) {
	args := map[string]any{"command": "git status"}
	argDigest, _ := receipt.CanonicalArgumentDigest(args)
	opID := receipt.CanonicalOperationID("commands.execute", "Bash", "git status")

	req := receipt.ProtectedOperationRequest{
		ExecutionID:        "exec-inv-001",
		SubjectID:          "skill://sec-agent@1.0.0",
		SubjectDigest:      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		AgentID:            "agent://orchestrator",
		SessionID:          "sess-inv-01",
		ToolOrServerID:     "Bash",
		Capability:         "commands.execute",
		Target:             "git status",
		CommandText:        "git status",
		Arguments:          args,
		ActivePolicyID:     "policy://prod-v1",
		ActivePolicyDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}

	auth := receipt.ExecutionAuthorization{
		AuthorizationID:         "auth-inv-001",
		SubjectID:               req.SubjectID,
		SubjectDigest:           req.SubjectDigest,
		AgentID:                 req.AgentID,
		SessionID:               req.SessionID,
		ToolOrServerID:          req.ToolOrServerID,
		RequestedCapability:     req.Capability,
		EffectiveScope:          []string{"Bash(git:*)"},
		AllowedTargets:          []string{"git status"},
		OperationID:             opID,
		ArgumentDigest:          argDigest,
		PolicyID:                req.ActivePolicyID,
		PolicyDigest:            req.ActivePolicyDigest,
		DecisionID:              "dec-inv-001",
		AssuranceState:          skil.AssuranceSafe,
		AssuranceEvidenceDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		IssuerID:                "skgate://authority",
		AudienceID:              "runtime://skrun-invariant-cluster",
		IssuedAt:                e.now.Add(-1 * time.Minute),
		ExpiresAt:               e.now.Add(5 * time.Minute),
		Nonce:                   "nonce-inv-001",
		SingleUse:               true,
	}
	return req, auth
}

// Invariant 1: An invalid authorization never permits execution.
func TestInvariant01_InvalidAuthorizationNeverPermitsExecution(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	// Leave authorization unsigned / forged
	var executed atomic.Int32
	rec, err := gw.AuthorizeAndExecute(
		context.Background(),
		auth,
		req,
		env.runtimePriv,
		env.rtKeyID,
		func(_ context.Context, _ receipt.ProtectedOperationRequest) (receipt.OperationExecutionResult, error) {
			executed.Add(1)
			return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
		},
	)
	if err == nil {
		t.Fatal("Invariant 1 violated: unsigned authorization permitted execution")
	}
	if executed.Load() != 0 {
		t.Fatalf("Invariant 1 violated: operation callback ran %d times on invalid authorization", executed.Load())
	}
	if rec.ExecutionOutcome != receipt.OutcomeDenied {
		t.Fatalf("Invariant 1 violated: expected DENIED outcome, got %s", rec.ExecutionOutcome)
	}
}

// Invariant 2: Expired or revoked authorization cannot be reused.
func TestInvariant02_ExpiredOrRevokedAuthorizationCannotBeReused(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	if err := auth.Sign(env.issuerPriv, env.issuerKeyID); err != nil {
		t.Fatal(err)
	}

	// Concurrent replay race: 16 goroutines attempting to use the same single-use authorization
	const workers = 16
	var allowed atomic.Int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if err := gw.ValidateAuthorization(auth, req); err == nil {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 1 {
		t.Fatalf("Invariant 2 violated: single-use authorization succeeded %d times concurrently (want 1)", allowed.Load())
	}

	// Revoked decision cannot be used even with fresh nonce
	req2, auth2 := env.validRequestAndAuth()
	auth2.Nonce = "nonce-inv-002"
	_ = auth2.Sign(env.issuerPriv, env.issuerKeyID)
	gwRevoked := receipt.NewExecutionGateway(receipt.ExecutionGatewayConfig{
		RuntimeAudienceID: "runtime://skrun-invariant-cluster",
		TrustedIssuers:    map[string][]string{"skgate://authority": {env.issuerKeyID}},
		TrustedPublicKeys: map[string]string{env.issuerKeyID: base64.StdEncoding.EncodeToString(env.issuerPub)},
		RevokedDecisions:  map[string]string{auth2.DecisionID: "security incident revocation"},
		Nonces:            receipt.NewNonceLedger(),
		Now:               func() time.Time { return env.now },
	})
	if err := gwRevoked.ValidateAuthorization(auth2, req2); err == nil {
		t.Fatal("Invariant 2 violated: revoked decision permitted execution")
	}
}

// Invariant 3: A changed operation digest invalidates its authorization.
func TestInvariant03_ChangedOperationDigestInvalidatesAuthorization(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	_ = auth.Sign(env.issuerPriv, env.issuerKeyID)

	prop := func(mutatedArg string) bool {
		if mutatedArg == "" || mutatedArg == "git status" {
			return true
		}
		mutReq := req
		mutReq.Arguments = map[string]any{"command": mutatedArg}
		return gw.ValidateAuthorization(auth, mutReq) != nil
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 100}); err != nil {
		t.Fatalf("Invariant 3 violated under property-based check: %v", err)
	}
}

// Invariant 4: Capability escalation invalidates existing authorization.
func TestInvariant04_CapabilityEscalationInvalidatesAuthorization(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	_ = auth.Sign(env.issuerPriv, env.issuerKeyID)

	req.Capability = "network.outbound"
	if err := gw.ValidateAuthorization(auth, req); err == nil {
		t.Fatal("Invariant 4 violated: capability escalation from commands.execute to network.outbound was permitted")
	}
}

// Invariant 5 & 6: Runtime drift invalidates affected assurance evidence and propagates to dependent policy decisions.
func TestInvariant05And06_RuntimeDriftInvalidatesEvidenceAndPropagatesToDecisions(t *testing.T) {
	env := setupInvariantEnv(t)
	eng := continuous.NewEngine(func() time.Time { return env.now })
	gw := env.newGateway(eng)
	req, auth := env.validRequestAndAuth()
	_ = auth.Sign(env.issuerPriv, env.issuerKeyID)

	stages := []skil.AssuranceStage{skil.StageExpected, skil.StageEvidenceCommitted, skil.StageProofPersisted}
	ctrl := skil.ControlProof{
		ControlID:      "ctrl-mcp-schema",
		Analyzer:       "mcp",
		SubjectDigest:  req.SubjectDigest,
		RequiredStages: stages,
		Evidence: []skil.AssuranceEvidence{
			{Stage: skil.StageExpected, EvidenceID: "e1", Digest: "sha256:11", Timestamp: env.now},
			{Stage: skil.StageEvidenceCommitted, EvidenceID: "e2", Digest: "sha256:22", Timestamp: env.now},
			{Stage: skil.StageProofPersisted, EvidenceID: "e3", Digest: "sha256:33", Timestamp: env.now},
		},
		Required: true,
		Complete: true,
	}
	val := continuous.AssuranceValidityConditions{
		SubjectID:             req.SubjectID,
		SubjectSource:         "git://repo",
		SubjectDigest:         req.SubjectDigest,
		PolicyID:              req.ActivePolicyID,
		PolicyDigest:          req.ActivePolicyDigest,
		VerificationEnvDigest: "sha256:env1",
		ToolSchemaDigests:     map[string]string{"Bash": "sha256:schema-v1"},
		RequiredEvidenceIDs:   []string{"ev-1"},
		IssuedAt:              env.now.Add(-5 * time.Minute),
		ExpiresAt:             env.now.Add(1 * time.Hour),
	}
	if _, err := eng.RegisterAssurance(val, auth.AssuranceEvidenceDigest, []skil.ControlProof{ctrl}, []string{auth.DecisionID}, nil); err != nil {
		t.Fatal(err)
	}

	// Drift occurs on tool schema
	eng.IngestDriftEvent(continuous.DriftEvent{
		EventID:    "drift-inv-5",
		Kind:       continuous.DepToolSchema,
		SubjectID:  req.SubjectID,
		Identity:   "Bash",
		NewDigest:  "sha256:schema-v2-mutated",
		OccurredAt: env.now,
	})

	// Invariant 5: Assurance evidence is invalidated
	if ok, _ := eng.IsAssuranceValid(req.SubjectDigest, auth.AssuranceEvidenceDigest, req.ActivePolicyDigest, auth.DecisionID); ok {
		t.Fatal("Invariant 5 violated: runtime drift did not invalidate affected assurance evidence")
	}
	// Invariant 6: Dependent policy decision is invalidated at ExecutionGateway
	if err := gw.ValidateAuthorization(auth, req); err == nil {
		t.Fatal("Invariant 6 violated: invalidated policy decision still authorized execution at gateway")
	}
}

// Invariant 7: Unverified attack paths cannot be labeled verified.
func TestInvariant07_UnverifiedAttackPathsCannotBeLabeledVerified(t *testing.T) {
	path := attackpath.MultiAgentAttackPath{
		PathID:       "path-inv-7",
		ScenarioKind: attackpath.ScenarioAgentToAgentPropagation,
		Nodes: []attackpath.GraphNode{
			{ID: "agent:a", Type: attackpath.NodeAgent},
			{ID: "subagent:b", Type: attackpath.NodeSubagent},
		},
		Edges: []attackpath.GraphEdge{
			{From: "agent:a", To: "subagent:b", Type: attackpath.EdgeCanDelegate},
		},
		StaticEvidenceIDs: []string{"finding:1"},
		LLMProposed:       true,
		VerificationEvidence: &attackpath.AttackVerificationEvidence{
			LLMReasoningOnly: true,
			ActualOutcome:    attackpath.AttackOutcomeExploitSucceeded,
			Complete:         true,
		},
	}
	conf, _ := attackpath.EvaluatePathConfidence(path)
	if conf == attackpath.ConfidenceVerifiedExploitable || conf == attackpath.ConfidenceVerifiedBlocked {
		t.Fatalf("Invariant 7 violated: unverified/LLM-only attack path labeled %s", conf)
	}
}

// Invariant 8: Inconclusive attack tests cannot become successful verification.
func TestInvariant08_InconclusiveAttackTestsCannotBecomeSuccessfulVerification(t *testing.T) {
	path := attackpath.MultiAgentAttackPath{
		PathID:       "path-inv-8",
		ScenarioKind: attackpath.ScenarioMemoryPoisoning,
		Nodes: []attackpath.GraphNode{
			{ID: "agent:a", Type: attackpath.NodeAgent},
			{ID: "mem:m", Type: attackpath.NodeMemoryStore},
		},
		Edges: []attackpath.GraphEdge{
			{From: "agent:a", To: "mem:m", Type: attackpath.EdgeCanWrite},
		},
		VerificationEvidence: &attackpath.AttackVerificationEvidence{
			IsolationIdentity: "sandbox-1",
			ActualOutcome:     attackpath.AttackOutcomeInconclusive,
			Complete:          true,
			RuntimeObservations: []eval.RuntimeObservation{
				{ID: "obs-1", ExternallyObserved: true, ObserverDigest: "sha256:obs", Occurred: true},
			},
		},
	}
	conf, _ := attackpath.EvaluatePathConfidence(path)
	if conf != attackpath.ConfidenceInconclusive {
		t.Fatalf("Invariant 8 violated: inconclusive attack test produced confidence %s instead of INCONCLUSIVE", conf)
	}
}

// Invariant 9: A valid cryptographic signature does not imply SAFE.
func TestInvariant09_ValidCryptographicSignatureDoesNotImplySafe(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := signing.KeyID(pub)
	now := time.Now().UTC().Truncate(time.Second)
	subjDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	stmt, err := evidence.NewPortableAssuranceStatementV1(evidence.PortableCertificatePredicateV1{
		SchemaVersion: evidence.PortableCertificateSchemaVersion,
		Subject: evidence.PortableSubjectIdentity{
			SubjectID:    "skill:unsafe-skill",
			Name:         "unsafe-skill",
			Digest:       subjDigest,
			ArtifactType: "skill",
		},
		Producer: evidence.PortableProducerIdentity{ProducerID: "skil-ci", Name: "skil", Version: "2.5.0"},
		Scanner: evidence.PortableScannerIdentity{
			ScannerID:      "skil",
			ScannerVersion: "2.5.0",
			RulePackDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
		Policy: evidence.PortablePolicyBinding{
			PolicyID:     "prod",
			PolicyDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
		AssuranceState:   skil.AssuranceUnsafe,
		AssuranceOutcome: skil.OutcomeFailed,
		OutcomeProof: skil.AssuranceOutcomeProof{
			Outcome:    skil.OutcomeFailed,
			Evidence:   []string{"ev-1"},
			Unresolved: []string{"critical-rce"},
		},
		EvidenceManifest: []evidence.PortableEvidenceManifestEntry{
			{
				EvidenceID:        "ev-1",
				EvidenceType:      "static",
				SubjectDigest:     subjDigest,
				Digest:            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
				VerificationClass: "VERIFIED",
				Required:          true,
			},
		},
		CoverageSummary:     evidence.PortableCoverageSummary{CompletionRatio: 1.0, Complete: true},
		VerificationMethods: []string{"static-ast"},
		ValidityConditions: evidence.PortableValidityConditions{
			ValidFrom:           now.Add(-1 * time.Minute),
			ValidUntil:          now.Add(1 * time.Hour),
			RequiredEvidenceIDs: []string{"ev-1"},
			ProofValid:          true,
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := evidence.SignPortableCertificate(stmt, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := evidence.VerifyPortableCertificateOffline(signed, evidence.OfflineCertificateVerifyOptions{
		ExpectedArtifactDigest: subjDigest,
		TrustedPublicKeys:      map[string]ed25519.PublicKey{keyID: pub},
		VerifyTime:             now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.CryptographicallyValid || report.SubjectSafe || report.PolicyAccepted {
		t.Fatalf("Invariant 9 violated: valid signature on UNSAFE subject produced %+v", report)
	}
}

// Invariant 10: Missing evidence cannot increase assurance.
func TestInvariant10_MissingEvidenceCannotIncreaseAssurance(t *testing.T) {
	proof := skil.ControlProof{
		ControlID:      "ctrl-1",
		Analyzer:       "ast",
		SubjectDigest:  "sha256:1111",
		RequiredStages: skil.DefaultAssuranceStages,
		Evidence:       nil, // missing evidence
		Required:       true,
	}
	if err := proof.Validate(); err == nil {
		t.Fatal("Invariant 10 violated: ControlProof with missing evidence validated as complete")
	}
}

// Invariant 11: Failed verification cannot produce COMPLETE.
func TestInvariant11_FailedVerificationCannotProduceComplete(t *testing.T) {
	proof := skil.AssuranceOutcomeProof{
		Outcome:    skil.OutcomeComplete,
		Evidence:   []string{"ev-1"},
		Unresolved: []string{"failed-verification-control-01"},
	}
	if err := proof.Validate(); err == nil {
		t.Fatal("Invariant 11 violated: failed/unresolved verification validated as OutcomeComplete")
	}
}

// Invariant 12: A denied operation cannot receive a successful execution receipt.
func TestInvariant12_DeniedOperationCannotReceiveSuccessfulExecutionReceipt(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	// Corrupt signature so operation is denied
	auth.Signatures = nil

	rec, _ := gw.AuthorizeAndExecute(
		context.Background(),
		auth,
		req,
		env.runtimePriv,
		env.rtKeyID,
		func(_ context.Context, _ receipt.ProtectedOperationRequest) (receipt.OperationExecutionResult, error) {
			return receipt.OperationExecutionResult{Accepted: true, Enforced: true}, nil
		},
	)
	if rec.ExecutionOutcome == receipt.OutcomeExecuted || rec.ExecutionOutcome == receipt.OutcomeAccepted {
		t.Fatalf("Invariant 12 violated: denied operation received execution outcome %s", rec.ExecutionOutcome)
	}
	rtTrusted := map[string]string{env.rtKeyID: base64.StdEncoding.EncodeToString(env.runtimePub)}
	if err := receipt.VerifyOperationReceipt(rec, auth, rtTrusted, true); err == nil {
		t.Fatal("Invariant 12 violated: VerifyOperationReceipt with requireExecuted=true accepted a DENIED receipt")
	}
}

// Invariant 13: Evidence from one subject cannot be reused for another incompatible subject.
func TestInvariant13_EvidenceFromOneSubjectCannotBeReusedForIncompatibleSubject(t *testing.T) {
	now := time.Now().UTC()
	eng := continuous.NewEngine(func() time.Time { return now })
	valA := continuous.AssuranceValidityConditions{
		SubjectID:             "skill://subject-A",
		SubjectSource:         "repo://a",
		SubjectDigest:         "sha256:aaaa",
		PolicyID:              "pol-1",
		PolicyDigest:          "sha256:p1",
		VerificationEnvDigest: "sha256:env1",
		RequiredEvidenceIDs:   []string{"ev-a"},
		IssuedAt:              now.Add(-1 * time.Minute),
		ExpiresAt:             now.Add(1 * time.Hour),
	}
	stages := []skil.AssuranceStage{skil.StageExpected}
	ctrlA := skil.ControlProof{
		ControlID:      "ctrl-1",
		Analyzer:       "ast",
		SubjectDigest:  "sha256:aaaa",
		RequiredStages: stages,
		Evidence:       []skil.AssuranceEvidence{{Stage: skil.StageExpected, EvidenceID: "e1", Digest: "sha256:1", Timestamp: now}},
		Required:       true,
		Complete:       true,
	}
	if _, err := eng.RegisterAssurance(valA, "sha256:ev-a", []skil.ControlProof{ctrlA}, nil, nil); err != nil {
		t.Fatal(err)
	}

	valB := valA
	valB.SubjectID = "skill://subject-B"
	valB.SubjectDigest = "sha256:bbbb"
	plan := eng.PlanSelectiveReAssurance("sha256:aaaa", valB, nil)
	if len(plan.ReusableControls) != 0 || !plan.FullRescanRequired {
		t.Fatalf("Invariant 13 violated: evidence from subject A reused for incompatible subject B: %+v", plan)
	}
}

// Invariant 14: Generated tests cannot escape their authorized evaluation environment.
func TestInvariant14_GeneratedTestsCannotEscapeAuthorizedEvaluationEnvironment(t *testing.T) {
	cand := redteam.GenerateCandidateTests([]redteam.AdaptiveTriggerInput{
		{Kind: redteam.TriggerNewFinding, SourceID: "SKIL-SH-001", SubjectDigest: "sha256:sub1"},
	})[0]
	// Attempt to disable isolation or add external target
	cand.RequireIsolation = false
	if err := redteam.ValidateCandidateTest(cand); err == nil {
		t.Fatal("Invariant 14 violated: candidate test without isolation passed validation")
	}
}

// Invariant 15: Stale attestations cannot silently authorize new operations.
func TestInvariant15_StaleAttestationsCannotSilentlyAuthorizeNewOperations(t *testing.T) {
	env := setupInvariantEnv(t)
	current := env.now
	eng := continuous.NewEngine(func() time.Time { return current })
	gw := env.newGateway(eng)
	req, auth := env.validRequestAndAuth()
	auth.ExpiresAt = env.now.Add(2 * time.Hour)
	_ = auth.Sign(env.issuerPriv, env.issuerKeyID)

	stages := []skil.AssuranceStage{skil.StageExpected}
	ctrl := skil.ControlProof{
		ControlID:      "ctrl-1",
		Analyzer:       "ast",
		SubjectDigest:  req.SubjectDigest,
		RequiredStages: stages,
		Evidence:       []skil.AssuranceEvidence{{Stage: skil.StageExpected, EvidenceID: "e1", Digest: "sha256:1", Timestamp: current}},
		Required:       true,
		Complete:       true,
	}
	val := continuous.AssuranceValidityConditions{
		SubjectID:                 req.SubjectID,
		SubjectSource:             "repo://a",
		SubjectDigest:             req.SubjectDigest,
		PolicyID:                  req.ActivePolicyID,
		PolicyDigest:              req.ActivePolicyDigest,
		VerificationEnvDigest:     "sha256:env1",
		RequiredEvidenceIDs:       []string{"ev-1"},
		IssuedAt:                  current.Add(-1 * time.Minute),
		ExpiresAt:                 current.Add(2 * time.Hour),
		MaxReconciliationInterval: 5 * time.Minute,
	}
	if _, err := eng.RegisterAssurance(val, auth.AssuranceEvidenceDigest, []skil.ControlProof{ctrl}, []string{auth.DecisionID}, nil); err != nil {
		t.Fatal(err)
	}

	// Advance clock past MaxReconciliationInterval without reconciliation
	current = current.Add(15 * time.Minute)
	if ok, _ := eng.IsAssuranceValid(req.SubjectDigest, auth.AssuranceEvidenceDigest, req.ActivePolicyDigest, auth.DecisionID); ok {
		t.Fatal("Invariant 15 violated: stale un-reconciled assurance remained valid")
	}
	if err := gw.ValidateAuthorization(auth, req); err == nil {
		t.Fatal("Invariant 15 violated: stale attestation authorized new operation")
	}
}

// Invariant 16: Runtime observations cannot overwrite contradictory deterministic evidence.
func TestInvariant16_RuntimeObservationsCannotOverwriteContradictoryDeterministicEvidence(t *testing.T) {
	// A path with deterministic static evidence that fails dynamic verification remains STATICALLY_SUPPORTED or INCONCLUSIVE,
	// never erasing the static evidence IDs.
	path := attackpath.MultiAgentAttackPath{
		PathID:            "path-inv-16",
		ScenarioKind:      attackpath.ScenarioSensitiveDataFlow,
		StaticEvidenceIDs: []string{"finding:SKIL-TAINT-001"},
		Nodes: []attackpath.GraphNode{
			{ID: "agent:a", Type: attackpath.NodeAgent},
			{ID: "ext:e", Type: attackpath.NodeExternalEndpoint},
		},
		Edges: []attackpath.GraphEdge{
			{From: "agent:a", To: "ext:e", Type: attackpath.EdgeFlowsTo},
		},
	}
	conf, _ := attackpath.EvaluatePathConfidence(path)
	if conf != attackpath.ConfidenceStaticallySupported {
		t.Fatalf("Invariant 16 violated: deterministic static evidence lost, got %s", conf)
	}
}

// Invariant 17: A parent agent's authorization does not automatically authorize a child agent.
func TestInvariant17_ParentAgentAuthorizationDoesNotAuthorizeChildAgent(t *testing.T) {
	env := setupInvariantEnv(t)
	gw := env.newGateway(nil)
	req, auth := env.validRequestAndAuth()
	_ = auth.Sign(env.issuerPriv, env.issuerKeyID)

	// Child subagent attempts to use parent's authorization token
	childReq := req
	childReq.AgentID = "subagent://child-worker-1"
	childReq.ParentAgentID = req.AgentID
	if err := gw.ValidateAuthorization(auth, childReq); err == nil {
		t.Fatal("Invariant 17 violated: parent agent's authorization permitted child subagent execution")
	}
}

// Invariant 18: All security-critical state transitions must be auditable.
func TestInvariant18_AllSecurityCriticalStateTransitionsAreAuditable(t *testing.T) {
	now := time.Now().UTC()
	eng := continuous.NewEngine(func() time.Time { return now })
	stages := []skil.AssuranceStage{skil.StageExpected}
	ctrl := skil.ControlProof{
		ControlID:      "ctrl-1",
		Analyzer:       "ast",
		SubjectDigest:  "sha256:audit1",
		RequiredStages: stages,
		Evidence:       []skil.AssuranceEvidence{{Stage: skil.StageExpected, EvidenceID: "e1", Digest: "sha256:1", Timestamp: now}},
		Required:       true,
		Complete:       true,
	}
	val := continuous.AssuranceValidityConditions{
		SubjectID:             "skill://audit-subj",
		SubjectSource:         "repo://audit",
		SubjectDigest:         "sha256:audit1",
		PolicyID:              "pol-1",
		PolicyDigest:          "sha256:p1",
		VerificationEnvDigest: "sha256:env1",
		RequiredEvidenceIDs:   []string{"ev-1"},
		IssuedAt:              now.Add(-1 * time.Minute),
		ExpiresAt:             now.Add(1 * time.Hour),
	}
	if _, err := eng.RegisterAssurance(val, "sha256:ev-audit", []skil.ControlProof{ctrl}, []string{"dec-audit"}, nil); err != nil {
		t.Fatal(err)
	}
	eng.IngestDriftEvent(continuous.DriftEvent{
		EventID:    "drift-audit-1",
		Kind:       continuous.DepSkillContentDigest,
		SubjectID:  "skill://audit-subj",
		Identity:   "skill://audit-subj",
		NewDigest:  "sha256:audit2",
		OccurredAt: now,
	})
	logs := eng.AuditLog()
	if len(logs) < 2 {
		t.Fatalf("Invariant 18 violated: expected at least 2 audit transitions (registration + invalidation), got %d", len(logs))
	}
	if logs[0].NewState != continuous.ProofValid || logs[1].NewState != continuous.ProofInvalidated {
		t.Fatalf("Invariant 18 violated: unexpected audit transition states: %+v", logs)
	}
}

// FuzzCanonicalOperationAndArgumentDigestInvariance fuzzes operation and argument canonicalization.
func FuzzCanonicalOperationAndArgumentDigestInvariance(f *testing.F) {
	f.Add("commands.execute", "Bash", "git status", "key1", "val1", "key2", "val2")
	f.Fuzz(func(t *testing.T, capName, toolID, target, k1, v1, k2, v2 string) {
		if k1 == "" || k2 == "" || k1 == k2 {
			return
		}
		m1 := map[string]any{k1: v1, k2: v2}
		m2 := map[string]any{k2: v2, k1: v1}
		d1, err1 := receipt.CanonicalArgumentDigest(m1)
		d2, err2 := receipt.CanonicalArgumentDigest(m2)
		if err1 != nil || err2 != nil {
			t.Fatalf("unexpected error computing canonical digest: %v / %v", err1, err2)
		}
		if d1 != d2 {
			t.Fatalf("canonical argument digest depends on map insertion order: %s != %s", d1, d2)
		}
		op1 := receipt.CanonicalOperationID(capName, toolID, target)
		op2 := receipt.CanonicalOperationID(capName, toolID, target)
		if op1 != op2 {
			t.Fatalf("non-deterministic operation ID: %s != %s", op1, op2)
		}
	})
}
