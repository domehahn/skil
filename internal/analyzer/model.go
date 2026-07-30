package analyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

// ModelArtifact analyzes ML model files a skill bundles or references:
// pickle-family serialization formats (.pkl/.pickle/.joblib/.pt/.pth/.bin),
// Keras model containers, and Python code that acquires executable
// behavior transitively through a model reference (trust_remote_code,
// custom modeling/configuration/tokenization loaders). It never
// deserializes, imports, or executes any scanned content — pickle streams
// are disassembled by scanPickleOpcodes (pure opcode/argument parsing),
// and zip-based containers (.pt/.pth new format, .keras) are only listed
// and their member bytes read, never extracted to disk or unmarshalled
// into live objects beyond plain JSON for config inspection.
type ModelArtifact struct{}

func NewModelArtifact() *ModelArtifact { return &ModelArtifact{} }

func (m *ModelArtifact) Metadata() skil.AnalyzerMetadata {
	return skil.AnalyzerMetadata{
		ID: "builtin.model-artifact", Version: "1.0.0",
		Domain: "model", Subdomain: "unsafe-serialization",
		Categories:    []string{"model-supply-chain", "dynamic-execution"},
		AnalysisTypes: []string{"model"},
		SupportedTypes: []string{
			"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt", "keras", "h5", "safetensors", "py",
		},
	}
}

func (m *ModelArtifact) Rules() []skil.Rule {
	return []skil.Rule{
		{ID: "SKIL-MODEL-PICKLE-001", Title: "Dangerous pickle opcode reference", Category: "model-supply-chain",
			Severity: skil.SeverityCritical, Analysis: "model", AppliesTo: []string{"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt"},
			Description: "A pickle-based model file references a callable capable of process execution, network access, or dynamic code execution during deserialization.",
			Remediation: "Re-export the model in a non-executable format (safetensors) or obtain it only from a source whose exact digest has been reviewed."},
		{ID: "SKIL-MODEL-PICKLE-002", Title: "Dynamic callable reconstruction in pickle stream", Category: "model-supply-chain",
			Severity: skil.SeverityCritical, Analysis: "model", AppliesTo: []string{"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt"},
			Description: "A pickle stream contains a REDUCE opcode referencing a dangerous callable, meaning the payload actively invokes the callable during deserialization rather than only referencing it.",
			Remediation: "Re-export the model in a non-executable format (safetensors) or obtain it only from a source whose exact digest has been reviewed and confirmed free of executable payloads."},
		{ID: "SKIL-MODEL-PICKLE-003", Title: "Unexpected module imported in pickle stream", Category: "model-supply-chain",
			Severity: skil.SeverityHigh, Analysis: "model", AppliesTo: []string{"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt"},
			Description: "A pickle stream references a module from an unexpected namespace that has no legitimate role in model weight serialization.",
			Remediation: "Re-export the model in a non-executable format (safetensors) and verify the model's origin."},
		{ID: "SKIL-MODEL-FORMAT-POLICY", Title: "Executable model serialization format", Category: "model-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "model", AppliesTo: []string{"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt", "h5", "keras"},
			Description: "The model is stored in a format whose deserialization can execute arbitrary code, rather than an inert tensor format.",
			Remediation: "Prefer safetensors or another non-executable serialization format for model weights."},
		{ID: "SKIL-MODEL-KERAS-001", Title: "Executable Keras Lambda/custom layer", Category: "model-supply-chain",
			Severity: skil.SeverityHigh, Analysis: "model", AppliesTo: []string{"keras", "h5"},
			Description: "A Keras model configuration includes a Lambda layer or custom object, which can embed arbitrary executable Python.",
			Remediation: "Replace Lambda layers with named, reviewable layer implementations."},
		{ID: "SKIL-MODEL-SIGNATURE-MISSING", Title: "Unsigned model file", Category: "model-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "model", AppliesTo: []string{"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt", "keras", "h5", "safetensors"},
			Description: "The model file is not accompanied by a cryptographic signature that can verify its origin.",
			Remediation: "Sign model files with an approved signing key and verify the signature before loading."},
		{ID: "SKIL-MODEL-REMOTE-CODE", Title: "Remote model code execution enabled", Category: "model-supply-chain",
			Severity: skil.SeverityHigh, Analysis: "model", AppliesTo: []string{"py"},
			Description: "Code enables trust_remote_code, which executes Python shipped alongside a model repository rather than only its weights.",
			Remediation: "Pin and review the exact remote code revision, or avoid trust_remote_code entirely."},
		{ID: "SKIL-MODEL-CUSTOM-LOADER", Title: "Custom model loader code", Category: "model-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "model", AppliesTo: []string{"py"},
			Description: "The artifact bundles custom modeling/configuration/tokenizer Python that executes as part of loading a model, expanding the trust boundary beyond the model weights themselves.",
			Remediation: "Review custom model-loading code with the same scrutiny as the skill's own code."},
		{ID: "SKIL-MODEL-UNPINNED", Title: "Unpinned model reference", Category: "model-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "model", AppliesTo: []string{"py"},
			Description: "Code loads a model by name without pinning an exact revision, so the resolved weights and any bundled code can change without review.",
			Remediation: "Pin an exact revision (commit hash) when loading the model."},
		{ID: "SKIL-MODEL-MUTABLE-REF", Title: "Mutable model revision reference", Category: "model-supply-chain",
			Severity: skil.SeverityMedium, Analysis: "model", AppliesTo: []string{"py"},
			Description: "Code pins a model revision to a mutable branch name (main/master/latest) rather than an immutable commit hash.",
			Remediation: "Pin an exact immutable revision (commit hash) instead of a mutable branch name."},
		{ID: "SKIL-MODEL-TYPOSQUAT", Title: "Suspicious model repository name", Category: "model-supply-chain",
			Severity: skil.SeverityHigh, Analysis: "model", AppliesTo: []string{"py"},
			Description: "A model repository's organization/namespace is edit-distance close to a well-known publisher, a common typosquatting technique.",
			Remediation: "Verify the model publisher's identity before loading; use the exact, verified organization name."},
	}
}

// dangerousPickleCallables are exact (module, name) references that are
// unambiguous process-execution, network, or dynamic-code-execution
// primitives if invoked during unpickling (typically via REDUCE
// immediately following the GLOBAL/STACK_GLOBAL reference).
var dangerousPickleCallables = map[string]map[string]bool{
	"os":          {"system": true, "popen": true, "execl": true, "execle": true, "execlp": true, "execv": true, "execve": true, "execvp": true, "fork": true, "spawnl": true, "spawnv": true, "remove": true, "unlink": true, "rmdir": true},
	"posix":       {"system": true, "popen": true},
	"nt":          {"system": true},
	"subprocess":  {"Popen": true, "call": true, "run": true, "check_call": true, "check_output": true},
	"builtins":    {"eval": true, "exec": true, "compile": true, "__import__": true},
	"__builtin__": {"eval": true, "exec": true, "compile": true, "__import__": true},
	"socket":      {"socket": true, "create_connection": true},
	"ctypes":      {"CDLL": true, "cdll": true, "windll": true, "PyDLL": true},
	"shutil":      {"rmtree": true},
	"pty":         {"spawn": true},
	"webbrowser":  {"open": true},
	"runpy":       {"_run_code": true, "run_path": true, "run_module": true},
	"importlib":   {"import_module": true},
	"requests":    {"get": true, "post": true, "put": true},
	"urllib":      {"urlopen": true},
	"http.client": {"HTTPConnection": true},
}

// dangerousPickleModulePrefixes flags a reference to any attribute of these
// modules as suspicious even when the specific attribute name isn't in
// dangerousPickleCallables above — these modules exist almost entirely to
// provide process, network, or native-code capability, so a model weight
// file has no legitimate reason to reference them at all.
var dangerousPickleModulePrefixes = []string{"socket", "subprocess", "ctypes", "webbrowser", "pty", "requests", "urllib", "http.client", "smtplib", "ftplib"}

func isDangerousPickleGlobal(g pickleGlobal) bool {
	if names, ok := dangerousPickleCallables[g.Module]; ok && names[g.Name] {
		return true
	}
	for _, prefix := range dangerousPickleModulePrefixes {
		if g.Module == prefix || strings.HasPrefix(g.Module, prefix+".") {
			return true
		}
	}
	return false
}

// isUnexpectedPickleModule returns true when a pickle stream references a
// module that has no legitimate role in model weight serialization. These
// are modules from unexpected namespaces like obfuscation, sandboxing, or
// system administration tools that should never appear in a model file.
func isUnexpectedPickleModule(g pickleGlobal) bool {
	unexpectedPrefixes := []string{
		"ctypes", "inspect", "ast", "compileall", "py_compile",
		"pdb", "trace", "tracemalloc", "coverage",
		"encodings", "importlib", "pkgutil", "runpy",
		"venv", "ensurepip", "http.server", "socketserver",
		"xmlrpc", "telnetlib", "ftplib", "imaplib", "poplib", "smtplib",
		"antigravity", "this", "turtle", "tkinter",
	}
	for _, prefix := range unexpectedPrefixes {
		if g.Module == prefix || strings.HasPrefix(g.Module, prefix+".") {
			return true
		}
	}
	return false
}

var trustRemoteCodePattern = regexp.MustCompile(`(?i)\btrust_remote_code\s*=\s*True\b`)

func isCustomLoaderFile(base string) bool {
	for _, prefix := range []string{"modeling_", "configuration_", "tokenization_"} {
		if strings.HasPrefix(base, prefix) && strings.HasSuffix(base, ".py") {
			return true
		}
	}
	return false
}

func (m *ModelArtifact) Analyze(_ context.Context, ac skil.AnalysisContext) ([]skil.Finding, error) {
	var out []skil.Finding
	for _, file := range ac.Artifact.Files {
		ext := strings.ToLower(extension(file.Path))
		base := baseName(file.Path)
		switch ext {
		case "pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt":
			out = append(out, m.scanPickleFile(file)...)
		case "keras":
			out = append(out, m.scanKerasZip(file)...)
		case "h5":
			out = append(out, formatPolicyFinding(file, "HDF5", skil.SeverityMedium))
		case "py":
			if trustRemoteCodePattern.Match(file.Data) {
				out = append(out, makeFinding(RulePattern{Rule: m.ruleByID("SKIL-MODEL-REMOTE-CODE"), Confidence: .95},
					file, lineOf(file.Data, trustRemoteCodePattern), "trust_remote_code=True"))
			}
			if isCustomLoaderFile(base) {
				out = append(out, makeFinding(RulePattern{Rule: m.ruleByID("SKIL-MODEL-CUSTOM-LOADER"), Confidence: .8},
					file, 1, base))
			}
			out = append(out, m.scanModelReferences(file)...)
		}
	}
	return out, nil
}

// modelReferencePattern matches a Hugging-Face-style "org/model" repository
// identifier passed as the first string argument to a model-loading call
// (from_pretrained, hf_hub_download, snapshot_download, or the
// transformers pipeline() helper's model= keyword), capturing the
// reference and up to 200 trailing characters on the same line to look for
// a revision= pin without needing a full multi-line parser.
var modelReferencePattern = regexp.MustCompile(`(?:from_pretrained|hf_hub_download|snapshot_download)\s*\(\s*(?:repo_id\s*=\s*)?["']([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)["'](.{0,200})|pipeline\s*\([^)]*model\s*=\s*["']([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)["'](.{0,200})`)
var revisionKwarg = regexp.MustCompile(`revision\s*=\s*["']([^"']+)["']`)

func (m *ModelArtifact) scanModelReferences(file skil.File) []skil.Finding {
	var out []skil.Finding
	for lineNumber, text := range lines(file.Data) {
		match := modelReferencePattern.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		ref, trailing := match[1], match[2]
		if ref == "" {
			ref, trailing = match[3], match[4]
		}
		org := ref
		if idx := strings.Index(ref, "/"); idx >= 0 {
			org = ref[:idx]
		}
		if target, distance := typosquatTarget("HuggingFace", org); target != "" {
			finding := makeFinding(RulePattern{Rule: m.ruleByID("SKIL-MODEL-TYPOSQUAT"), Confidence: .8},
				file, lineNumber+1, text)
			finding.Evidence["model_reference"] = ref
			finding.Evidence["resembles_publisher"] = target
			finding.Evidence["edit_distance"] = distance
			out = append(out, finding)
		}
		revision := revisionKwarg.FindStringSubmatch(trailing)
		switch {
		case revision == nil:
			finding := makeFinding(RulePattern{Rule: m.ruleByID("SKIL-MODEL-UNPINNED"), Confidence: .75}, file, lineNumber+1, text)
			finding.Evidence["model_reference"] = ref
			out = append(out, finding)
		case revision[1] == "main" || revision[1] == "master" || revision[1] == "latest" || revision[1] == "HEAD":
			finding := makeFinding(RulePattern{Rule: m.ruleByID("SKIL-MODEL-MUTABLE-REF"), Confidence: .85}, file, lineNumber+1, text)
			finding.Evidence["model_reference"] = ref
			finding.Evidence["revision"] = revision[1]
			out = append(out, finding)
		}
	}
	return out
}

func (m *ModelArtifact) ruleByID(id string) skil.Rule {
	for _, r := range m.Rules() {
		if r.ID == id {
			return r
		}
	}
	return skil.Rule{ID: id}
}

func formatPolicyFinding(file skil.File, format string, severity skil.Severity) skil.Finding {
	rule := RulePattern{Rule: skil.Rule{
		ID: "SKIL-MODEL-FORMAT-POLICY", Title: "Executable model serialization format", Category: "model-supply-chain",
		Severity: severity, Analysis: "model",
		Description: "The model is stored as " + format + ", a format whose loader can execute embedded code, rather than an inert tensor format (safetensors).",
		Remediation: "Prefer safetensors or another non-executable serialization format for model weights.",
	}, Confidence: .8}
	return makeFinding(rule, file, 1, file.Path)
}

// scanPickleFile handles both a raw pickle/joblib stream and a zip-wrapped
// PyTorch checkpoint (the format PyTorch has used by default since 1.6,
// containing one or more "*/data.pkl" members). It reads member bytes only
// — it never calls torch.load, pickle.load, or any other deserializer.
func (m *ModelArtifact) scanPickleFile(file skil.File) []skil.Finding {
	var out []skil.Finding
	format := "Pickle"
	streams := [][]byte{file.Data}
	if looksLikeZip(file.Data) {
		format = "zip-wrapped Pickle (PyTorch checkpoint container)"
		members, err := readBoundedZipMembers(file.Data, "data.pkl")
		if err == nil && len(members) > 0 {
			streams = members
		}
	}
	seenGlobal := map[string]bool{}
	seenUnexpected := map[string]bool{}
	for _, stream := range streams {
		for _, g := range scanPickleOpcodes(stream) {
			key := g.Module + "." + g.Name
			if seenGlobal[key] {
				continue
			}
			if isDangerousPickleGlobal(g) {
				seenGlobal[key] = true
				ruleID := "SKIL-MODEL-PICKLE-001"
				if g.Reduced {
					ruleID = "SKIL-MODEL-PICKLE-002"
				}
				rule := RulePattern{Rule: m.ruleByID(ruleID), Confidence: .95}
				finding := makeFinding(rule, file, 1, key)
				finding.Evidence["pickle_global"] = key
				if g.Reduced {
					finding.Evidence["opcode"] = "REDUCE"
				}
				out = append(out, finding)
			} else if isUnexpectedPickleModule(g) {
				ukey := g.Module
				if seenUnexpected[ukey] {
					continue
				}
				seenUnexpected[ukey] = true
				rule := RulePattern{Rule: m.ruleByID("SKIL-MODEL-PICKLE-003"), Confidence: .85}
				finding := makeFinding(rule, file, 1, key)
				finding.Evidence["pickle_module"] = g.Module
				out = append(out, finding)
			}
		}
	}
	out = append(out, formatPolicyFinding(file, format, skil.SeverityMedium))
	return out
}

// kerasConfigLambda is a minimal structural probe for a Lambda (or other
// custom-callable) layer inside a Keras model config, without importing or
// constructing any layer.
var kerasLambdaClassName = regexp.MustCompile(`(?i)"class_name"\s*:\s*"(?:Lambda|TFOpLambda)"`)

// scanKerasZip inspects a .keras file (a zip container holding
// config.json/metadata.json/weights, the Keras 3 native format) for a
// Lambda layer, which can carry an arbitrary serialized Python callable.
func (m *ModelArtifact) scanKerasZip(file skil.File) []skil.Finding {
	var out []skil.Finding
	if looksLikeZip(file.Data) {
		members, err := readBoundedZipMembers(file.Data, "config.json")
		if err == nil {
			for _, member := range members {
				if kerasLambdaClassName.Match(member) {
					rule := RulePattern{Rule: m.ruleByID("SKIL-MODEL-KERAS-001"), Confidence: .85}
					out = append(out, makeFinding(rule, file, 1, "Lambda layer in model config"))
					break
				}
			}
		}
	}
	out = append(out, formatPolicyFinding(file, "Keras", skil.SeverityLow))
	return out
}

func looksLikeZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04
}

// readBoundedZipMembers reads every zip member whose name ends with
// nameSuffix, bounded to prevent decompression-bomb abuse: at most 64
// members inspected and 64MB decompressed in total. It never writes to
// disk and never interprets member contents beyond returning raw bytes (or,
// for config.json in scanKerasZip's caller, a plain-text regex match).
func readBoundedZipMembers(data []byte, nameSuffix string) ([][]byte, error) {
	const maxMembers = 64
	const maxTotalBytes = 64 << 20
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	total := 0
	checked := 0
	for _, entry := range reader.File {
		if checked >= maxMembers {
			break
		}
		checked++
		if !strings.HasSuffix(entry.Name, nameSuffix) {
			continue
		}
		if int64(entry.UncompressedSize64) > maxTotalBytes {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			continue
		}
		limited := io.LimitReader(rc, maxTotalBytes-int64(total)+1)
		content, err := io.ReadAll(limited)
		rc.Close()
		if err != nil {
			continue
		}
		total += len(content)
		out = append(out, content)
		if total >= maxTotalBytes {
			break
		}
	}
	return out, nil
}

func baseName(path string) string {
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func lineOf(data []byte, pattern *regexp.Regexp) int {
	loc := pattern.FindIndex(data)
	if loc == nil {
		return 1
	}
	return 1 + strings.Count(string(data[:loc[0]]), "\n")
}
