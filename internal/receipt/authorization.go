package receipt

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domehahn/skil/internal/signing"
	"github.com/domehahn/skil/internal/toolgrants"
	"github.com/domehahn/skil/pkg/skil"
)

const (
	AuthorizationSchemaV1      = "1.0"
	PayloadTypeAuthorizationV1 = "application/vnd.skil.execution-authorization.v1+json"
	OperationReceiptSchemaV1   = "1.0"
	PayloadTypeOpReceiptV1     = "application/vnd.skil.operation-receipt.v1+json"
)

var credentialValuePattern = regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----|bearer\s+[a-zA-Z0-9_\-\.]{16,}|(?:api_key|secret|password|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{8,})`)

// FileIdentityBinding binds a file operation to the exact canonical path and
// observed file state at authorization time to prevent TOCTOU swaps.
type FileIdentityBinding struct {
	WorkspaceRoot       string `json:"workspace_root"`
	CanonicalRelPath    string `json:"canonical_rel_path"`
	ExistsAtCheck       bool   `json:"exists_at_check"`
	ContentSHA256       string `json:"content_sha256,omitempty"`
	SizeBytes           int64  `json:"size_bytes,omitempty"`
	ModePerm            uint32 `json:"mode_perm,omitempty"`
	SymlinkFreeVerified bool   `json:"symlink_free_verified"`
	AtomicHandleBound   bool   `json:"atomic_handle_bound"`
	ResidualRisk        string `json:"residual_risk,omitempty"`
}

// MCPInvocationBinding binds an MCP tool invocation to the exact server,
// negotiated schema digest, and canonical argument digest.
type MCPInvocationBinding struct {
	ServerID               string `json:"server_id"`
	ToolName               string `json:"tool_name"`
	NegotiatedSchemaDigest string `json:"negotiated_schema_digest"`
	ArgumentDigest         string `json:"argument_digest"`
}

// ExecutionAuthorization is a proof-carrying, operation-bound authorization
// artifact signed using Ed25519 DSSE. It never embeds raw credentials or
// sensitive argument payloads.
type ExecutionAuthorization struct {
	SchemaVersion           string                `json:"schema_version"`
	AuthorizationID         string                `json:"authorization_id"`
	SubjectID               string                `json:"subject_id"`
	SubjectDigest           string                `json:"subject_digest"`
	AgentID                 string                `json:"agent_id"`
	SessionID               string                `json:"session_id"`
	ParentAgentID           string                `json:"parent_agent_id,omitempty"`
	ToolOrServerID          string                `json:"tool_or_server_id"`
	RequestedCapability     string                `json:"requested_capability"`
	EffectiveScope          []string              `json:"effective_scope"`
	AllowedTargets          []string              `json:"allowed_targets,omitempty"`
	OperationID             string                `json:"operation_id"`
	ArgumentDigest          string                `json:"argument_digest"`
	PolicyID                string                `json:"policy_id"`
	PolicyDigest            string                `json:"policy_digest"`
	DecisionID              string                `json:"decision_id"`
	AssuranceState          skil.AssuranceState   `json:"assurance_state"`
	AssuranceEvidenceDigest string                `json:"assurance_evidence_digest"`
	IssuerID                string                `json:"issuer_id"`
	AudienceID              string                `json:"audience_id"`
	IssuedAt                time.Time             `json:"issued_at"`
	ExpiresAt               time.Time             `json:"expires_at"`
	Nonce                   string                `json:"nonce"`
	SingleUse               bool                  `json:"single_use"`
	FileBinding             *FileIdentityBinding  `json:"file_binding,omitempty"`
	MCPBinding              *MCPInvocationBinding `json:"mcp_binding,omitempty"`
	AuthorizationDigest     string                `json:"authorization_digest"`
	Signatures              []skil.DSSESignature  `json:"signatures,omitempty"`
}

// CanonicalOperationID derives a deterministic operation identity from the
// capability, tool/MCP server identity, and canonical target.
func CanonicalOperationID(capability, toolOrServerID, target string) string {
	payload := strings.Join([]string{
		strings.TrimSpace(capability),
		strings.TrimSpace(toolOrServerID),
		strings.TrimSpace(target),
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return "op:sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalArgumentDigest hashes canonicalized JSON arguments so key-order
// variations produce identical digests while any value or type mutation
// changes the digest.
func CanonicalArgumentDigest(arguments map[string]any) (string, error) {
	if len(arguments) == 0 {
		sum := sha256.Sum256([]byte("{}"))
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	}
	canon, err := signing.CanonicalJSON(arguments)
	if err != nil {
		return "", fmt.Errorf("canonicalize arguments: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalSchemaDigest computes the canonical SHA-256 digest of a tool schema.
func CanonicalSchemaDigest(schema any) (string, error) {
	if schema == nil {
		return "", errors.New("tool schema is nil")
	}
	canon, err := signing.CanonicalJSON(schema)
	if err != nil {
		return "", fmt.Errorf("canonicalize tool schema: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ContainsSensitiveCredentialMaterial detects accidental inclusion of raw
// credentials or secrets inside authorization metadata fields.
func ContainsSensitiveCredentialMaterial(s string) bool {
	return credentialValuePattern.MatchString(s)
}

func (a ExecutionAuthorization) validateStructure() error {
	required := map[string]string{
		"authorization_id":          a.AuthorizationID,
		"subject_id":                a.SubjectID,
		"subject_digest":            a.SubjectDigest,
		"agent_id":                  a.AgentID,
		"session_id":                a.SessionID,
		"tool_or_server_id":         a.ToolOrServerID,
		"requested_capability":      a.RequestedCapability,
		"operation_id":              a.OperationID,
		"argument_digest":           a.ArgumentDigest,
		"policy_id":                 a.PolicyID,
		"policy_digest":             a.PolicyDigest,
		"decision_id":               a.DecisionID,
		"assurance_evidence_digest": a.AssuranceEvidenceDigest,
		"issuer_id":                 a.IssuerID,
		"audience_id":               a.AudienceID,
		"nonce":                     a.Nonce,
	}
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			return fmt.Errorf("execution authorization missing required field %s", name)
		}
		if ContainsSensitiveCredentialMaterial(val) {
			return fmt.Errorf("execution authorization field %s contains forbidden credential material", name)
		}
	}
	if len(a.EffectiveScope) == 0 {
		return errors.New("execution authorization requires non-empty effective_scope")
	}
	for _, scope := range a.EffectiveScope {
		if strings.TrimSpace(scope) == "" {
			return errors.New("execution authorization contains empty scope entry")
		}
		if ContainsSensitiveCredentialMaterial(scope) {
			return errors.New("execution authorization effective_scope contains forbidden credential material")
		}
	}
	for _, target := range a.AllowedTargets {
		if ContainsSensitiveCredentialMaterial(target) {
			return errors.New("execution authorization allowed_targets contains forbidden credential material")
		}
	}
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return errors.New("execution authorization requires valid issued_at and expires_at window")
	}
	if a.AssuranceState != skil.AssuranceSafe {
		return fmt.Errorf("execution authorization cannot be issued for assurance state %q (must be SAFE)", a.AssuranceState)
	}
	return nil
}

// ComputeDigest computes the canonical SHA-256 digest of the authorization
// excluding its digest and signature fields.
func (a ExecutionAuthorization) ComputeDigest() (string, error) {
	copyAuth := a
	copyAuth.SchemaVersion = AuthorizationSchemaV1
	copyAuth.AuthorizationDigest = ""
	copyAuth.Signatures = nil
	copyAuth.EffectiveScope = append([]string(nil), a.EffectiveScope...)
	sort.Strings(copyAuth.EffectiveScope)
	if len(a.AllowedTargets) > 0 {
		copyAuth.AllowedTargets = append([]string(nil), a.AllowedTargets...)
		sort.Strings(copyAuth.AllowedTargets)
	}
	canon, err := signing.CanonicalJSON(copyAuth)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Sign validates and signs the ExecutionAuthorization using Ed25519 DSSE PAE.
func (a *ExecutionAuthorization) Sign(privKey ed25519.PrivateKey, keyID string) error {
	if a == nil {
		return errors.New("execution authorization is nil")
	}
	if privKey == nil {
		return errors.New("private key is required to sign execution authorization")
	}
	if a.SchemaVersion == "" {
		a.SchemaVersion = AuthorizationSchemaV1
	}
	a.EffectiveScope = append([]string(nil), a.EffectiveScope...)
	sort.Strings(a.EffectiveScope)
	if len(a.AllowedTargets) > 0 {
		a.AllowedTargets = append([]string(nil), a.AllowedTargets...)
		sort.Strings(a.AllowedTargets)
	}
	if err := a.validateStructure(); err != nil {
		return err
	}
	digest, err := a.ComputeDigest()
	if err != nil {
		return err
	}
	a.AuthorizationDigest = digest
	if keyID == "" {
		keyID = signing.KeyID(privKey.Public().(ed25519.PublicKey))
	}
	pae := signing.DSSEPAE(PayloadTypeAuthorizationV1, []byte(digest))
	sig := ed25519.Sign(privKey, pae)
	a.Signatures = []skil.DSSESignature{
		{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		},
	}
	return nil
}

// CaptureFileIdentity inspects a confined workspace file prior to operation
// authorization/execution and returns a FileIdentityBinding.
func CaptureFileIdentity(workspaceRoot, relativePath string, atomicHandleSupported bool) (FileIdentityBinding, error) {
	if strings.TrimSpace(workspaceRoot) == "" || !filepath.IsAbs(workspaceRoot) {
		return FileIdentityBinding{}, errors.New("workspace root must be an absolute path")
	}
	if relativePath == "" || strings.ContainsRune(relativePath, 0) || filepath.IsAbs(relativePath) ||
		strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, "\\") {
		return FileIdentityBinding{}, errors.New("file path must be a non-empty relative path")
	}
	cleaned := filepath.ToSlash(filepath.Clean(relativePath))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != relativePath {
		return FileIdentityBinding{}, errors.New("file path must be canonical and traversal-free")
	}
	rootClean := filepath.Clean(workspaceRoot)
	target := filepath.Join(rootClean, filepath.FromSlash(cleaned))
	rel, err := filepath.Rel(rootClean, target)
	if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return FileIdentityBinding{}, errors.New("file path escapes workspace root")
	}

	// Verify no ancestor directory is a symlink
	current := rootClean
	for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(cleaned)), "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(part))
		info, lerr := os.Lstat(current)
		if errors.Is(lerr, os.ErrNotExist) {
			break
		}
		if lerr != nil {
			return FileIdentityBinding{}, lerr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return FileIdentityBinding{}, fmt.Errorf("ancestor component %q is a symlink", part)
		}
	}

	binding := FileIdentityBinding{
		WorkspaceRoot:       rootClean,
		CanonicalRelPath:    cleaned,
		SymlinkFreeVerified: true,
		AtomicHandleBound:   atomicHandleSupported,
	}
	if !atomicHandleSupported {
		binding.ResidualRisk = "userspace_pre_post_stat_digest_verification_without_kernel_openat2"
	}

	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		binding.ExistsAtCheck = false
		return binding, nil
	}
	if err != nil {
		return FileIdentityBinding{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return FileIdentityBinding{}, errors.New("target path is a symlink")
	}
	if !info.Mode().IsRegular() {
		return FileIdentityBinding{}, errors.New("target path is not a regular file")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return FileIdentityBinding{}, err
	}
	sum := sha256.Sum256(data)
	binding.ExistsAtCheck = true
	binding.ContentSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	binding.SizeBytes = info.Size()
	binding.ModePerm = uint32(info.Mode().Perm())
	return binding, nil
}

// VerifyFileIdentityAtUse re-evaluates the physical path immediately before use
// and rejects any symlink swap, unexpected creation/deletion, or content mutation.
func VerifyFileIdentityAtUse(expected FileIdentityBinding) error {
	if !expected.SymlinkFreeVerified || expected.WorkspaceRoot == "" || expected.CanonicalRelPath == "" {
		return errors.New("file identity binding is incomplete")
	}
	actual, err := CaptureFileIdentity(expected.WorkspaceRoot, expected.CanonicalRelPath, expected.AtomicHandleBound)
	if err != nil {
		return fmt.Errorf("TOCTOU file verification failed: %w", err)
	}
	if actual.ExistsAtCheck != expected.ExistsAtCheck {
		return fmt.Errorf("TOCTOU violation: file existence changed from %v to %v for %q",
			expected.ExistsAtCheck, actual.ExistsAtCheck, expected.CanonicalRelPath)
	}
	if expected.ExistsAtCheck {
		if actual.ContentSHA256 != expected.ContentSHA256 || actual.SizeBytes != expected.SizeBytes {
			return fmt.Errorf("TOCTOU violation: file content or size changed for %q (expected %s, got %s)",
				expected.CanonicalRelPath, expected.ContentSHA256, actual.ContentSHA256)
		}
	}
	return nil
}

// NonceLedger provides thread-safe replay tracking for single-use and bounded
// execution authorizations.
type NonceLedger struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonceLedger() *NonceLedger {
	return &NonceLedger{seen: make(map[string]time.Time)}
}

// Consume atomically records a nonce if it has not been used before.
func (l *NonceLedger) Consume(authID, nonce string, usedAt time.Time) error {
	if l == nil {
		return errors.New("nonce ledger is required for replay protection")
	}
	if strings.TrimSpace(authID) == "" || strings.TrimSpace(nonce) == "" {
		return errors.New("authorization ID and nonce are required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := authID + "\x00" + nonce
	if prior, exists := l.seen[key]; exists {
		return fmt.Errorf("replay attack detected: authorization %q nonce %q already consumed at %s",
			authID, nonce, prior.Format(time.RFC3339Nano))
	}
	l.seen[key] = usedAt.UTC()
	return nil
}

// AssuranceValidityOracle allows the gateway to query Continuous Re-Assurance
// and revocation state before permitting an operation.
type AssuranceValidityOracle interface {
	IsAssuranceValid(subjectDigest, assuranceEvidenceDigest, policyDigest, decisionID string) (bool, string)
}

// ProtectedOperationRequest represents the actual runtime operation about to be
// executed by the gateway.
type ProtectedOperationRequest struct {
	ExecutionID          string
	SubjectID            string
	SubjectDigest        string
	AgentID              string
	SessionID            string
	ParentAgentID        string
	ToolOrServerID       string
	Capability           string
	Target               string
	CommandText          string
	Arguments            map[string]any
	NegotiatedToolSchema any
	ActivePolicyID       string
	ActivePolicyDigest   string
}

// ExecutionGatewayConfig holds the trust roots, runtime identity, and validity
// dependencies required to validate proof-carrying execution authorizations.
type ExecutionGatewayConfig struct {
	RuntimeAudienceID string
	TrustedIssuers    map[string][]string     // IssuerID -> allowed KeyIDs
	TrustedPublicKeys map[string]string       // KeyID -> base64 Ed25519 public key
	AssuranceOracle   AssuranceValidityOracle // optional live re-assurance/revocation oracle
	RevokedDigests    map[string]string       // digest -> reason
	RevokedDecisions  map[string]string       // decisionID -> reason
	Nonces            *NonceLedger
	Now               func() time.Time
}

// ExecutionGateway enforces mandatory 10-point proof-carrying authorization
// validation, TOCTOU protection, and signed enforcement receipt generation.
type ExecutionGateway struct {
	cfg ExecutionGatewayConfig
}

func NewExecutionGateway(cfg ExecutionGatewayConfig) *ExecutionGateway {
	if cfg.Nonces == nil {
		cfg.Nonces = NewNonceLedger()
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &ExecutionGateway{cfg: cfg}
}

// ValidateAuthorization performs the mandatory 10-point security verification
// against the concrete ProtectedOperationRequest.
func (g *ExecutionGateway) ValidateAuthorization(auth ExecutionAuthorization, req ProtectedOperationRequest) error {
	now := g.cfg.Now().UTC()

	// 1. Structural & cryptographic authenticity check
	if err := auth.validateStructure(); err != nil {
		return fmt.Errorf("invalid authorization structure: %w", err)
	}
	if len(auth.Signatures) == 0 {
		return errors.New("authorization is unsigned")
	}
	expectedDigest, err := auth.ComputeDigest()
	if err != nil || expectedDigest != auth.AuthorizationDigest {
		return errors.New("authorization digest mismatch")
	}
	pae := signing.DSSEPAE(PayloadTypeAuthorizationV1, []byte(expectedDigest))
	verifiedKeyID := ""
	for _, sig := range auth.Signatures {
		pubB64, ok := g.cfg.TrustedPublicKeys[sig.KeyID]
		if !ok {
			continue
		}
		pubBytes, decErr := base64.StdEncoding.DecodeString(pubB64)
		if decErr != nil || len(pubBytes) != ed25519.PublicKeySize {
			continue
		}
		sigBytes, sigErr := base64.StdEncoding.DecodeString(sig.Sig)
		if sigErr != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
			verifiedKeyID = sig.KeyID
			break
		}
	}
	if verifiedKeyID == "" {
		return errors.New("authorization signature verification failed")
	}

	// 2. Trusted issuer check for the verified key
	allowedKeys, issuerTrusted := g.cfg.TrustedIssuers[auth.IssuerID]
	if !issuerTrusted || !containsString(allowedKeys, verifiedKeyID) {
		return fmt.Errorf("issuer %q with key %q is not trusted for runtime authorization", auth.IssuerID, verifiedKeyID)
	}

	// 3. Validity period check
	if now.Before(auth.IssuedAt) {
		return errors.New("authorization is not yet valid (issued_at is in the future)")
	}
	if !now.Before(auth.ExpiresAt) {
		return errors.New("authorization has expired")
	}

	// 4. Audience check
	if g.cfg.RuntimeAudienceID == "" || auth.AudienceID != g.cfg.RuntimeAudienceID {
		return fmt.Errorf("authorization audience %q does not match runtime %q", auth.AudienceID, g.cfg.RuntimeAudienceID)
	}

	// 5. Subject, Agent, Session, and Parent/Child delegation boundary check.
	// A parent agent's authorization NEVER automatically authorizes a child agent.
	if auth.SubjectID != req.SubjectID || auth.SubjectDigest != req.SubjectDigest {
		return fmt.Errorf("subject mismatch: authorized (%s, %s) != requested (%s, %s)",
			auth.SubjectID, auth.SubjectDigest, req.SubjectID, req.SubjectDigest)
	}
	if auth.AgentID != req.AgentID {
		return fmt.Errorf("agent mismatch: authorization for agent %q cannot be used by agent %q (parent/child privilege escalation denied)",
			auth.AgentID, req.AgentID)
	}
	if auth.SessionID != req.SessionID {
		return fmt.Errorf("session mismatch: authorized %q != requested %q", auth.SessionID, req.SessionID)
	}
	if auth.ParentAgentID != req.ParentAgentID {
		return fmt.Errorf("parent agent lineage mismatch: authorized %q != requested %q", auth.ParentAgentID, req.ParentAgentID)
	}

	// 6. Canonical operation and argument digest binding
	wantOpID := CanonicalOperationID(req.Capability, req.ToolOrServerID, req.Target)
	if auth.OperationID != wantOpID || auth.ToolOrServerID != req.ToolOrServerID {
		return fmt.Errorf("operation mismatch: authorized (%s, %s) != effective (%s, %s)",
			auth.OperationID, auth.ToolOrServerID, wantOpID, req.ToolOrServerID)
	}
	actualArgDigest, err := CanonicalArgumentDigest(req.Arguments)
	if err != nil {
		return fmt.Errorf("failed to compute argument digest: %w", err)
	}
	if auth.ArgumentDigest != actualArgDigest {
		return fmt.Errorf("argument digest mismatch: authorized %s != effective %s", auth.ArgumentDigest, actualArgDigest)
	}

	// 7. Requested capability & scope check
	if auth.RequestedCapability != req.Capability {
		return fmt.Errorf("capability mismatch: authorized %q != requested %q", auth.RequestedCapability, req.Capability)
	}
	if !scopePermitsOperation(auth.EffectiveScope, auth.AllowedTargets, req) {
		return fmt.Errorf("requested operation (%s on %q) is outside authorized effective_scope", req.Capability, req.Target)
	}

	// 8. Policy decision validity check
	if req.ActivePolicyID != "" && auth.PolicyID != req.ActivePolicyID {
		return fmt.Errorf("policy ID changed: authorized under %q, active is %q", auth.PolicyID, req.ActivePolicyID)
	}
	if req.ActivePolicyDigest != "" && auth.PolicyDigest != req.ActivePolicyDigest {
		return fmt.Errorf("policy digest changed: authorized under %s, active is %s", auth.PolicyDigest, req.ActivePolicyDigest)
	}
	if reason, revoked := g.cfg.RevokedDecisions[auth.DecisionID]; revoked {
		return fmt.Errorf("policy decision %q has been invalidated: %s", auth.DecisionID, reason)
	}

	// 9. Underlying assurance evidence validity & revocation check
	if reason, revoked := g.cfg.RevokedDigests[auth.SubjectDigest]; revoked {
		return fmt.Errorf("subject digest %s is revoked: %s", auth.SubjectDigest, reason)
	}
	if reason, revoked := g.cfg.RevokedDigests[auth.AssuranceEvidenceDigest]; revoked {
		return fmt.Errorf("assurance evidence %s is revoked: %s", auth.AssuranceEvidenceDigest, reason)
	}
	if g.cfg.AssuranceOracle != nil {
		valid, reason := g.cfg.AssuranceOracle.IsAssuranceValid(
			auth.SubjectDigest, auth.AssuranceEvidenceDigest, auth.PolicyDigest, auth.DecisionID,
		)
		if !valid {
			return fmt.Errorf("underlying assurance is no longer valid: %s", reason)
		}
	}

	// 10. TOCTOU checks for file and MCP operations before consuming nonce
	if strings.HasPrefix(req.Capability, "filesystem.") {
		if auth.FileBinding == nil {
			return errors.New("filesystem operation requires FileIdentityBinding for TOCTOU protection")
		}
		if auth.FileBinding.CanonicalRelPath != req.Target {
			return fmt.Errorf("file binding path %q does not match requested target %q", auth.FileBinding.CanonicalRelPath, req.Target)
		}
		if err := VerifyFileIdentityAtUse(*auth.FileBinding); err != nil {
			return err
		}
	}
	if strings.HasPrefix(req.Capability, "mcp.") {
		if auth.MCPBinding == nil {
			return errors.New("MCP operation requires MCPInvocationBinding for TOCTOU/schema protection")
		}
		if auth.MCPBinding.ServerID != req.ToolOrServerID || auth.MCPBinding.ArgumentDigest != actualArgDigest {
			return errors.New("MCP invocation binding server or argument digest mismatch")
		}
		if req.NegotiatedToolSchema == nil {
			return errors.New("MCP operation requires negotiated tool schema at execution time")
		}
		actualSchemaDigest, err := CanonicalSchemaDigest(req.NegotiatedToolSchema)
		if err != nil {
			return err
		}
		if actualSchemaDigest != auth.MCPBinding.NegotiatedSchemaDigest {
			return fmt.Errorf("MCP tool schema drift detected: authorized %s != negotiated %s",
				auth.MCPBinding.NegotiatedSchemaDigest, actualSchemaDigest)
		}
	}

	// 11. Single-use / replay protection (consumed only after all validation checks pass)
	if auth.SingleUse {
		if err := g.cfg.Nonces.Consume(auth.AuthorizationID, auth.Nonce, now); err != nil {
			return err
		}
	}

	return nil
}

func scopePermitsOperation(scopes, allowedTargets []string, req ProtectedOperationRequest) bool {
	if len(allowedTargets) > 0 && req.Target != "" {
		matched := false
		for _, allowed := range allowedTargets {
			if allowed == req.Target || allowed == "*" {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	decl := strings.Join(scopes, " ")
	grants, err := toolgrants.Parse(decl)
	if err == nil && len(grants) > 0 {
		argText := req.CommandText
		if argText == "" {
			argText = req.Target
		}
		for _, g := range grants {
			if g.Allows(req.Capability, argText) || g.Allows(req.ToolOrServerID, argText) {
				return true
			}
		}
	}

	for _, s := range scopes {
		if s == req.Capability || s == req.Capability+":"+req.Target {
			return true
		}
	}
	return false
}

// ExecutionOutcome distinguishes authorization from actual execution and failure states.
type ExecutionOutcome string

const (
	OutcomeAuthorized ExecutionOutcome = "AUTHORIZED"
	OutcomeAttempted  ExecutionOutcome = "ATTEMPTED"
	OutcomeAccepted   ExecutionOutcome = "ACCEPTED"
	OutcomeExecuted   ExecutionOutcome = "EXECUTED"
	OutcomeDenied     ExecutionOutcome = "DENIED"
	OutcomeFailed     ExecutionOutcome = "FAILED"
	OutcomeTimedOut   ExecutionOutcome = "TIMED_OUT"
	OutcomeUnknown    ExecutionOutcome = "UNKNOWN"
)

// EnforcementOutcome records whether runtime security controls were upheld.
type EnforcementOutcome string

const (
	EnforcementVerified EnforcementOutcome = "ENFORCED"
	EnforcementDenied   EnforcementOutcome = "DENIED_BY_GATEWAY"
	EnforcementFailed   EnforcementOutcome = "ENFORCEMENT_FAILED"
	EnforcementUnknown  EnforcementOutcome = "UNKNOWN"
)

// OperationExecutionResult is returned by the isolated operation handler.
type OperationExecutionResult struct {
	Accepted             bool
	Enforced             bool
	TransportStatus      int
	OutputBytes          []byte
	ObservedCapabilities []string
}

// OperationEnforcementReceipt is a cryptographically signed proof of what
// actually happened at runtime for a specific authorization and operation.
type OperationEnforcementReceipt struct {
	SchemaVersion        string               `json:"schema_version"`
	ReceiptID            string               `json:"receipt_id"`
	AuthorizationID      string               `json:"authorization_id"`
	AuthorizationDigest  string               `json:"authorization_digest"`
	EffectiveOperationID string               `json:"effective_operation_id"`
	ExecutionID          string               `json:"execution_id"`
	RuntimeIdentity      string               `json:"runtime_identity"`
	SubjectDigest        string               `json:"subject_digest"`
	PolicyDigest         string               `json:"policy_digest"`
	ObservedCapabilities []string             `json:"observed_capabilities,omitempty"`
	StartedAt            time.Time            `json:"started_at"`
	CompletedAt          time.Time            `json:"completed_at"`
	ExecutionOutcome     ExecutionOutcome     `json:"execution_outcome"`
	EnforcementOutcome   EnforcementOutcome   `json:"enforcement_outcome"`
	OutputDigest         string               `json:"output_digest,omitempty"`
	EvidenceID           string               `json:"evidence_id"`
	DenyReason           string               `json:"deny_reason,omitempty"`
	ResidualRisk         string               `json:"residual_risk,omitempty"`
	ReceiptDigest        string               `json:"receipt_digest"`
	Signatures           []skil.DSSESignature `json:"signatures,omitempty"`
}

func (r OperationEnforcementReceipt) ComputeDigest() (string, error) {
	copyRec := r
	copyRec.SchemaVersion = OperationReceiptSchemaV1
	copyRec.ReceiptDigest = ""
	copyRec.Signatures = nil
	copyRec.ObservedCapabilities = append([]string(nil), r.ObservedCapabilities...)
	sort.Strings(copyRec.ObservedCapabilities)
	canon, err := signing.CanonicalJSON(copyRec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (r *OperationEnforcementReceipt) Sign(privKey ed25519.PrivateKey, keyID string) error {
	if r == nil {
		return errors.New("operation receipt is nil")
	}
	if privKey == nil {
		return errors.New("private key is required to sign operation receipt")
	}
	if r.SchemaVersion == "" {
		r.SchemaVersion = OperationReceiptSchemaV1
	}
	if r.ExecutionOutcome == OutcomeDenied && r.EnforcementOutcome == EnforcementVerified {
		return errors.New("denied operation cannot claim ENFORCED execution success")
	}
	digest, err := r.ComputeDigest()
	if err != nil {
		return err
	}
	r.ReceiptDigest = digest
	if keyID == "" {
		keyID = signing.KeyID(privKey.Public().(ed25519.PublicKey))
	}
	pae := signing.DSSEPAE(PayloadTypeOpReceiptV1, []byte(digest))
	sig := ed25519.Sign(privKey, pae)
	r.Signatures = []skil.DSSESignature{
		{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		},
	}
	return nil
}

// AuthorizeAndExecute validates the proof-carrying authorization, executes fn
// only if validation succeeds, and emits a signed OperationEnforcementReceipt
// that truthfully distinguishes DENIED, FAILED, TIMED_OUT, ACCEPTED, and EXECUTED.
func (g *ExecutionGateway) AuthorizeAndExecute(
	ctx context.Context,
	auth ExecutionAuthorization,
	req ProtectedOperationRequest,
	runtimeSignKey ed25519.PrivateKey,
	runtimeKeyID string,
	fn func(context.Context, ProtectedOperationRequest) (OperationExecutionResult, error),
) (OperationEnforcementReceipt, error) {
	started := g.cfg.Now().UTC()
	effectiveOpID := CanonicalOperationID(req.Capability, req.ToolOrServerID, req.Target)
	receiptID := "rcpt:" + req.ExecutionID
	evidenceID := "ev:exec:" + req.ExecutionID

	rec := OperationEnforcementReceipt{
		SchemaVersion:        OperationReceiptSchemaV1,
		ReceiptID:            receiptID,
		AuthorizationID:      auth.AuthorizationID,
		AuthorizationDigest:  auth.AuthorizationDigest,
		EffectiveOperationID: effectiveOpID,
		ExecutionID:          req.ExecutionID,
		RuntimeIdentity:      g.cfg.RuntimeAudienceID,
		SubjectDigest:        req.SubjectDigest,
		PolicyDigest:         auth.PolicyDigest,
		StartedAt:            started,
		EvidenceID:           evidenceID,
	}
	if auth.FileBinding != nil && auth.FileBinding.ResidualRisk != "" {
		rec.ResidualRisk = auth.FileBinding.ResidualRisk
	}

	if err := g.ValidateAuthorization(auth, req); err != nil {
		rec.CompletedAt = g.cfg.Now().UTC()
		rec.ExecutionOutcome = OutcomeDenied
		rec.EnforcementOutcome = EnforcementDenied
		rec.DenyReason = err.Error()
		if runtimeSignKey != nil {
			_ = rec.Sign(runtimeSignKey, runtimeKeyID)
		}
		return rec, err
	}

	if fn == nil {
		rec.CompletedAt = g.cfg.Now().UTC()
		rec.ExecutionOutcome = OutcomeAuthorized
		rec.EnforcementOutcome = EnforcementUnknown
		if runtimeSignKey != nil {
			_ = rec.Sign(runtimeSignKey, runtimeKeyID)
		}
		return rec, nil
	}

	execRes, execErr := fn(ctx, req)
	rec.CompletedAt = g.cfg.Now().UTC()
	rec.ObservedCapabilities = append([]string(nil), execRes.ObservedCapabilities...)
	sort.Strings(rec.ObservedCapabilities)

	if len(execRes.OutputBytes) > 0 {
		outSum := sha256.Sum256(execRes.OutputBytes)
		rec.OutputDigest = "sha256:" + hex.EncodeToString(outSum[:])
	}

	switch {
	case errors.Is(execErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		rec.ExecutionOutcome = OutcomeTimedOut
		rec.EnforcementOutcome = EnforcementFailed
		rec.DenyReason = "operation timed out"
	case execErr != nil:
		rec.ExecutionOutcome = OutcomeFailed
		rec.EnforcementOutcome = EnforcementFailed
		rec.DenyReason = execErr.Error()
	case !execRes.Accepted:
		// A transport response (even HTTP 200) without protocol-level Accepted
		// is only ATTEMPTED, never ACCEPTED or EXECUTED.
		rec.ExecutionOutcome = OutcomeAttempted
		rec.EnforcementOutcome = EnforcementUnknown
	case execRes.Accepted && !execRes.Enforced:
		rec.ExecutionOutcome = OutcomeAccepted
		rec.EnforcementOutcome = EnforcementUnknown
	default:
		rec.ExecutionOutcome = OutcomeExecuted
		rec.EnforcementOutcome = EnforcementVerified
	}

	if runtimeSignKey != nil {
		if signErr := rec.Sign(runtimeSignKey, runtimeKeyID); signErr != nil {
			return rec, signErr
		}
	}
	return rec, execErr
}

// VerifyOperationReceipt verifies the cryptographic integrity and semantic
// consistency of an OperationEnforcementReceipt. Calling code can distinguish
// whether the operation actually executed with verified enforcement vs merely
// being authorized, attempted, or denied.
func VerifyOperationReceipt(
	rec OperationEnforcementReceipt,
	wantAuth ExecutionAuthorization,
	trustedRuntimeKeys map[string]string,
	requireExecutedAndEnforced bool,
) error {
	if rec.ReceiptID == "" || rec.ExecutionID == "" || rec.EvidenceID == "" {
		return errors.New("operation receipt is missing required identity fields")
	}
	if rec.AuthorizationID != wantAuth.AuthorizationID || rec.AuthorizationDigest != wantAuth.AuthorizationDigest {
		return errors.New("operation receipt is not bound to the expected authorization")
	}
	if rec.EffectiveOperationID != wantAuth.OperationID {
		return errors.New("operation receipt operation ID does not match authorized operation")
	}
	if rec.SubjectDigest != wantAuth.SubjectDigest || rec.PolicyDigest != wantAuth.PolicyDigest {
		return errors.New("operation receipt subject or policy digest mismatch")
	}
	if rec.RuntimeIdentity != wantAuth.AudienceID {
		return errors.New("operation receipt runtime identity does not match authorized audience")
	}
	if rec.CompletedAt.Before(rec.StartedAt) {
		return errors.New("operation receipt has invalid timestamps")
	}
	if rec.ExecutionOutcome == OutcomeDenied && rec.OutputDigest != "" {
		return errors.New("denied operation receipt cannot claim execution output")
	}
	if len(rec.Signatures) == 0 {
		return errors.New("operation receipt is unsigned")
	}
	expectedDigest, err := rec.ComputeDigest()
	if err != nil || expectedDigest != rec.ReceiptDigest {
		return errors.New("operation receipt digest mismatch")
	}
	pae := signing.DSSEPAE(PayloadTypeOpReceiptV1, []byte(expectedDigest))
	verified := false
	for _, sig := range rec.Signatures {
		pubB64, ok := trustedRuntimeKeys[sig.KeyID]
		if !ok {
			continue
		}
		pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return errors.New("operation receipt signature verification failed")
	}
	if requireExecutedAndEnforced {
		if rec.ExecutionOutcome != OutcomeExecuted || rec.EnforcementOutcome != EnforcementVerified {
			return fmt.Errorf("receipt does not prove enforced execution (outcome=%s, enforcement=%s)",
				rec.ExecutionOutcome, rec.EnforcementOutcome)
		}
	}
	return nil
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
