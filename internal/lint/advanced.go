package lint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/domehahn/skil/pkg/skil"
	"github.com/domehahn/skil/schemas"
	"gopkg.in/yaml.v3"
)

var (
	headingPattern = regexp.MustCompile(`(?m)^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$`)
	jsImport       = regexp.MustCompile(`(?m)(?:from[ \t]+|require\([ \t]*)["'](\.{1,2}/[^"']+)["']`)
	pyImport       = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.+[A-Za-z0-9_.]*)[ \t]+import\b`)
	shellSource    = regexp.MustCompile(`(?m)^[ \t]*(?:source|\.)[ \t]+["']?([^"' \t;]+)`)
	exactVersion   = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	commitVersion  = regexp.MustCompile(`(?i)(?:#|/)[0-9a-f]{40}$`)
)

func lintAdvanced(result *Result, artifact skil.Artifact, contract *skil.SkillContract, profile Profile) {
	files := fileIndex(artifact.Files)
	lintFileHygiene(result, artifact.Files)
	lintMarkdownStructure(result, artifact.Files)
	lintDependencyConsistency(result, files)
	lintMCPDocuments(result, artifact.Files, contract)
	lintEvalDocuments(result, artifact.Files, contract)
	lintEntrypointsAndImports(result, artifact.Files, files, contract)
	if contract != nil {
		lintCapabilitySyntax(result, contract.Capabilities, findContractPath(artifact.Files))
	}
	if profile == ProfilePublish {
		lintPublishReadiness(result, files, contract)
	}
}

func lintFileHygiene(result *Result, files []skil.File) {
	for _, file := range files {
		lower := strings.ToLower(file.Path)
		if isTextFile(lower) && !utf8.Valid(file.Data) {
			add(result, "SKIL-LINT-UTF8", LevelError, "Invalid UTF-8",
				"Text metadata contains invalid UTF-8.", file.Path, 1,
				"Encode authoring and configuration files as UTF-8.")
		}
		if isTextFile(lower) && bytes.Contains(file.Data, []byte("\r\n")) {
			add(result, "SKIL-LINT-LINE-ENDINGS", LevelWarning, "Non-portable line endings",
				"Text file uses CRLF line endings.", file.Path, 1,
				"Use LF line endings for reproducible cross-platform packages.")
		}
		if len(file.Data) >= 3 && bytes.Equal(file.Data[:3], []byte{0xef, 0xbb, 0xbf}) {
			add(result, "SKIL-LINT-BOM", LevelWarning, "UTF-8 byte-order mark",
				"File begins with a UTF-8 BOM.", file.Path, 1,
				"Remove the BOM to avoid parser differences.")
		}
		if temporaryArtifact(lower) {
			add(result, "SKIL-LINT-TEMPORARY-FILE", LevelWarning, "Temporary or generated artifact",
				"Package contains an editor, operating-system, or scanner output artifact.", file.Path, 1,
				"Remove generated and temporary files from the skill package.")
		}
		for _, component := range strings.Split(filepath.ToSlash(file.Path), "/") {
			trimmed := strings.TrimRight(component, ". ")
			base := strings.ToUpper(strings.SplitN(trimmed, ".", 2)[0])
			if trimmed != component || windowsReservedName(base) {
				add(result, "SKIL-LINT-FILENAME-PORTABILITY", LevelWarning, "Non-portable filename",
					fmt.Sprintf("Path component %q is not portable across supported filesystems.", component),
					file.Path, 1, "Rename the file to a portable, non-reserved name.")
				break
			}
		}
	}
}

func lintMarkdownStructure(result *Result, files []skil.File) {
	for _, file := range files {
		if !strings.HasSuffix(strings.ToLower(file.Path), ".md") {
			continue
		}
		fence, fenceLine := "", 0
		for index, line := range strings.Split(strings.ReplaceAll(string(file.Data), "\r\n", "\n"), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			current := fencePrefix(trimmed)
			if current == "" {
				continue
			}
			if fence == "" {
				fence, fenceLine = current, index+1
			} else if current[0] == fence[0] && len(current) >= len(fence) {
				fence, fenceLine = "", 0
			}
		}
		if fence != "" {
			add(result, "SKIL-LINT-CODE-FENCE", LevelError, "Unclosed Markdown code fence",
				fmt.Sprintf("Code fence opened on line %d is not closed.", fenceLine), file.Path, fenceLine,
				"Close the Markdown code fence with the same marker.")
		}
		seen := map[string]int{}
		for _, match := range headingPattern.FindAllSubmatchIndex(file.Data, -1) {
			title := string(file.Data[match[4]:match[5]])
			anchor := markdownAnchor(title)
			if prior, exists := seen[anchor]; exists {
				add(result, "SKIL-LINT-ANCHOR-DUPLICATE", LevelWarning, "Duplicate Markdown anchor",
					fmt.Sprintf("Heading generates duplicate anchor %q; first generated on line %d.", anchor, prior),
					file.Path, lineAt(file.Data, match[0]), "Rename one heading so local anchors remain unambiguous.")
			} else {
				seen[anchor] = lineAt(file.Data, match[0])
			}
		}
		lintMarkdownAnchors(result, file, files)
	}
}

func lintMarkdownAnchors(result *Result, source skil.File, files []skil.File) {
	index := fileIndex(files)
	for _, match := range localLink.FindAllSubmatchIndex(source.Data, -1) {
		raw := string(source.Data[match[2]:match[3]])
		if strings.Contains(raw, "://") || strings.HasPrefix(strings.ToLower(raw), "mailto:") {
			continue
		}
		parts := strings.SplitN(raw, "#", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		targetPath := parts[0]
		if targetPath == "" {
			targetPath = source.Path
		} else {
			targetPath = path.Clean(path.Join(path.Dir(filepath.ToSlash(source.Path)), targetPath))
		}
		target, exists := index[strings.ToLower(targetPath)]
		if !exists || !strings.HasSuffix(strings.ToLower(target.Path), ".md") {
			continue
		}
		anchors := markdownAnchors(target.Data)
		if !anchors[strings.ToLower(parts[1])] {
			add(result, "SKIL-LINT-ANCHOR-BROKEN", LevelWarning, "Broken Markdown anchor",
				fmt.Sprintf("Anchor %q does not exist in %s.", parts[1], target.Path),
				source.Path, lineAt(source.Data, match[0]), "Correct the anchor or add the referenced heading.")
		}
	}
}

func lintDependencyConsistency(result *Result, files map[string]skil.File) {
	families := []struct {
		manifest string
		locks    []string
	}{
		{"package.json", []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}},
		{"pyproject.toml", []string{"poetry.lock", "uv.lock", "pdm.lock"}},
		{"go.mod", []string{"go.sum"}},
		{"cargo.toml", []string{"cargo.lock"}},
		{"gemfile", []string{"gemfile.lock"}},
	}
	for _, family := range families {
		var present []string
		for _, lock := range family.locks {
			if _, exists := files[lock]; exists {
				present = append(present, lock)
			}
		}
		if len(present) > 1 {
			add(result, "SKIL-LINT-LOCKFILE-CONFLICT", LevelWarning, "Competing dependency lockfiles",
				fmt.Sprintf("%s has multiple lockfiles: %s.", family.manifest, strings.Join(present, ", ")),
				family.manifest, 1, "Keep the single lockfile used by the declared package manager.")
		}
		if _, manifestExists := files[family.manifest]; !manifestExists {
			for _, lock := range present {
				add(result, "SKIL-LINT-LOCKFILE-ORPHAN", LevelWarning, "Orphan dependency lockfile",
					fmt.Sprintf("%s exists without %s.", lock, family.manifest), lock, 1,
					"Include the matching manifest or remove the stale lockfile.")
			}
		}
	}
	if packageFile, exists := files["package.json"]; exists && json.Valid(packageFile.Data) {
		var document map[string]any
		if json.Unmarshal(packageFile.Data, &document) == nil {
			for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
				dependencies, _ := document[section].(map[string]any)
				for name, raw := range dependencies {
					version, _ := raw.(string)
					if !deterministicDependency(version) {
						add(result, "SKIL-LINT-DEPENDENCY-RANGE", LevelWarning, "Non-deterministic dependency version",
							fmt.Sprintf("%s dependency %q uses non-exact version %q.", section, name, version),
							packageFile.Path, 1, "Pin an exact version and commit the matching lockfile.")
					}
				}
			}
			if lockFile, locked := files["package-lock.json"]; locked && json.Valid(lockFile.Data) {
				lintNPMLockDrift(result, packageFile, lockFile, document)
			}
		}
	}
}

func lintNPMLockDrift(result *Result, manifest, lock skil.File, packageDocument map[string]any) {
	var lockDocument map[string]any
	if json.Unmarshal(lock.Data, &lockDocument) != nil {
		return
	}
	packages, _ := lockDocument["packages"].(map[string]any)
	root, _ := packages[""].(map[string]any)
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		expected, _ := packageDocument[section].(map[string]any)
		observed, _ := root[section].(map[string]any)
		for name, value := range expected {
			if observed[name] != value {
				add(result, "SKIL-LINT-LOCKFILE-DRIFT", LevelWarning, "Dependency manifest and lockfile drift",
					fmt.Sprintf("%s dependency %q differs between package.json and package-lock.json.", section, name),
					lock.Path, 1, "Regenerate the lockfile from the reviewed manifest.")
			}
		}
		for name := range observed {
			if _, exists := expected[name]; !exists {
				add(result, "SKIL-LINT-LOCKFILE-DRIFT", LevelWarning, "Dependency manifest and lockfile drift",
					fmt.Sprintf("%s dependency %q exists only in package-lock.json.", section, name),
					lock.Path, 1, "Regenerate the lockfile from the reviewed manifest.")
			}
		}
	}
}

func lintMCPDocuments(result *Result, files []skil.File, contract *skil.SkillContract) {
	configuredServers := map[string]bool{}
	configuredTools := map[string]bool{}
	for _, file := range files {
		lower := strings.ToLower(filepath.ToSlash(file.Path))
		if lower == ".skil/mcp-tools.lock.json" {
			if err := schemas.ValidateYAML("mcp-tools-lock-v1.schema.json", file.Data); err != nil {
				add(result, "SKIL-LINT-MCP-LOCK", LevelError, "Invalid MCP metadata lock",
					err.Error(), file.Path, 1, "Correct the MCP lock schema and SHA-256 digests.")
			}
			continue
		}
		if !strings.Contains(lower, "mcp") || !strings.HasSuffix(lower, ".json") || !json.Valid(file.Data) {
			continue
		}
		duplicates, err := duplicateJSONKeys(file.Data)
		if err == nil {
			for _, key := range duplicates {
				add(result, "SKIL-LINT-JSON-DUPLICATE-KEY", LevelError, "Duplicate JSON key",
					fmt.Sprintf("JSON object repeats key %q.", key), file.Path, 1,
					"Keep one unambiguous value for each JSON object key.")
			}
		}
		var document map[string]any
		if json.Unmarshal(file.Data, &document) != nil {
			continue
		}
		for _, key := range []string{"servers", "mcpServers"} {
			servers, _ := document[key].(map[string]any)
			for name := range servers {
				configuredServers[name] = true
			}
		}
		tools, _ := document["tools"].([]any)
		names := map[string]bool{}
		for _, rawTool := range tools {
			tool, _ := rawTool.(map[string]any)
			name, _ := tool["name"].(string)
			if strings.TrimSpace(name) == "" {
				add(result, "SKIL-LINT-MCP-TOOL-NAME", LevelError, "Missing MCP tool name",
					"MCP tool entry has no non-empty name.", file.Path, 1, "Give every MCP tool a stable unique name.")
			} else if names[name] {
				add(result, "SKIL-LINT-MCP-TOOL-DUPLICATE", LevelError, "Duplicate MCP tool name",
					fmt.Sprintf("MCP tool name %q is declared more than once.", name), file.Path, 1,
					"Use a unique stable name for each tool.")
			}
			names[name] = true
			if name != "" {
				configuredTools[name] = true
			}
			if schema, exists := tool["inputSchema"]; exists {
				object, ok := schema.(map[string]any)
				schemaType, _ := object["type"].(string)
				if !ok || (schemaType != "" && schemaType != "object") {
					add(result, "SKIL-LINT-MCP-INPUT-SCHEMA", LevelError, "Invalid MCP input schema",
						fmt.Sprintf("Tool %q inputSchema must be a JSON object schema.", name), file.Path, 1,
						"Declare inputSchema as an object with bounded properties.")
				}
			}
		}
	}
	if contract == nil {
		return
	}
	declaredServers := stringSet(contract.Capabilities.MCP.Servers)
	declaredTools := stringSet(contract.Capabilities.MCP.Tools)
	for name := range configuredServers {
		if !declaredServers[name] && !declaredServers["*"] {
			add(result, "SKIL-LINT-MCP-UNDECLARED", LevelWarning, "MCP server missing from contract",
				fmt.Sprintf("Configured MCP server %q is not declared in capabilities.mcp.servers.", name),
				findContractPath(files), 1, "Declare the server or remove the unused configuration.")
		}
	}
	for name := range configuredTools {
		if !declaredTools[name] && !declaredTools["*"] {
			add(result, "SKIL-LINT-MCP-UNDECLARED", LevelWarning, "MCP tool missing from contract",
				fmt.Sprintf("Configured MCP tool %q is not declared in capabilities.mcp.tools.", name),
				findContractPath(files), 1, "Declare the tool or remove the unused definition.")
		}
	}
	for name := range declaredServers {
		if name != "*" && !configuredServers[name] {
			add(result, "SKIL-LINT-MCP-REFERENCE", LevelWarning, "Unknown declared MCP server",
				fmt.Sprintf("Contract declares MCP server %q but no matching configuration exists.", name),
				findContractPath(files), 1, "Add the reviewed server configuration or remove the stale capability.")
		}
	}
	for name := range declaredTools {
		if name != "*" && !configuredTools[name] {
			add(result, "SKIL-LINT-MCP-REFERENCE", LevelWarning, "Unknown declared MCP tool",
				fmt.Sprintf("Contract declares MCP tool %q but no matching definition exists.", name),
				findContractPath(files), 1, "Add the reviewed tool definition or remove the stale capability.")
		}
	}
}

func lintEvalDocuments(result *Result, files []skil.File, contract *skil.SkillContract) {
	names := map[string]string{}
	for _, file := range files {
		lower := strings.ToLower(filepath.ToSlash(file.Path))
		base := filepath.Base(lower)
		if !(strings.Contains(base, "eval") || strings.Contains(base, "behavior")) ||
			!(strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")) {
			continue
		}
		if err := schemas.ValidateYAML("eval-v1.schema.json", file.Data); err != nil {
			add(result, "SKIL-LINT-EVAL-SCHEMA", LevelError, "Invalid evaluation specification",
				err.Error(), file.Path, 1, "Correct the eval-v1 schema before behavioral testing.")
			continue
		}
		var spec skil.EvalSpec
		if yaml.Unmarshal(file.Data, &spec) != nil {
			continue
		}
		if prior, exists := names[spec.Name]; exists {
			add(result, "SKIL-LINT-EVAL-NAME-DUPLICATE", LevelError, "Duplicate evaluation name",
				fmt.Sprintf("Evaluation name %q is already used by %s.", spec.Name, prior), file.Path, 1,
				"Give each evaluation a unique stable name.")
		}
		names[spec.Name] = file.Path
		if len(spec.Expect.Required)+len(spec.Expect.Forbidden)+len(spec.Expect.ForbiddenCapabilities)+
			len(spec.Expect.OutputProperties)+len(spec.Expect.Assertions) == 0 {
			add(result, "SKIL-LINT-EVAL-ASSERTIONS", LevelWarning, "Evaluation has no assertions",
				fmt.Sprintf("Evaluation %q does not define a verifiable expectation.", spec.Name), file.Path, 1,
				"Add required, forbidden, output property, or policy assertions.")
		}
		if spec.Type == "adversarial" && spec.Attack == nil {
			add(result, "SKIL-LINT-EVAL-ATTACK", LevelWarning, "Adversarial evaluation lacks attack metadata",
				fmt.Sprintf("Adversarial evaluation %q has no attack category.", spec.Name), file.Path, 1,
				"Declare the tested attack category.")
		}
		if contract != nil {
			allowed := stringSet(contract.Capabilities.Tools.Allow)
			for _, tool := range spec.Tools.Available {
				if len(allowed) > 0 && !allowed[tool] {
					add(result, "SKIL-LINT-EVAL-TOOL", LevelWarning, "Evaluation uses undeclared tool",
						fmt.Sprintf("Evaluation %q exposes tool %q not allowed by the contract.", spec.Name, tool),
						file.Path, 1, "Align evaluation tools with the contract capability allowlist.")
				}
			}
		}
	}
}

func lintEntrypointsAndImports(result *Result, files []skil.File, index map[string]skil.File, contract *skil.SkillContract) {
	if contract != nil {
		entrypoint := contract.Entrypoint
		if entrypoint == "" {
			entrypoint = "SKILL.md"
		}
		if file, exists := index[strings.ToLower(filepath.ToSlash(entrypoint))]; exists && isScript(file.Path) {
			if !file.Executable {
				add(result, "SKIL-LINT-ENTRYPOINT-MODE", LevelWarning, "Script entrypoint is not executable",
					fmt.Sprintf("Entrypoint %q has no executable mode.", entrypoint), file.Path, 1,
					"Mark a directly executed script entrypoint executable.")
				lintShebang(result, file)
			}
		}
	}
	for _, file := range files {
		lower := strings.ToLower(file.Path)
		if file.Executable && isScript(lower) {
			lintShebang(result, file)
		}
		switch filepath.Ext(lower) {
		case ".js", ".mjs", ".cjs", ".ts", ".tsx":
			for _, match := range jsImport.FindAllSubmatchIndex(file.Data, -1) {
				target := string(file.Data[match[2]:match[3]])
				if !resolvesLocalImport(file.Path, target, index, []string{"", ".js", ".mjs", ".cjs", ".ts", ".tsx", "/index.js", "/index.ts"}) {
					addMissingImport(result, file, target, match[0])
				}
			}
		case ".py":
			for _, match := range pyImport.FindAllSubmatchIndex(file.Data, -1) {
				target := string(file.Data[match[2]:match[3]])
				dots := len(target) - len(strings.TrimLeft(target, "."))
				module := strings.ReplaceAll(strings.TrimLeft(target, "."), ".", "/")
				base := path.Dir(filepath.ToSlash(file.Path))
				for count := 1; count < dots; count++ {
					base = path.Dir(base)
				}
				resolved := path.Join(base, module)
				if !existsCandidate(index, resolved, []string{".py", "/__init__.py"}) {
					addMissingImport(result, file, target, match[0])
				}
			}
		case ".sh", ".bash":
			for _, match := range shellSource.FindAllSubmatchIndex(file.Data, -1) {
				target := string(file.Data[match[2]:match[3]])
				if strings.Contains(target, "$") || filepath.IsAbs(target) {
					continue
				}
				if !resolvesLocalImport(file.Path, target, index, []string{""}) {
					addMissingImport(result, file, target, match[0])
				}
			}
		}
	}
}

func lintCapabilitySyntax(result *Result, capabilities skil.Capabilities, contractPath string) {
	lists := []struct {
		name   string
		values []string
	}{
		{"filesystem.read", capabilities.Filesystem.Read},
		{"filesystem.write", capabilities.Filesystem.Write},
		{"filesystem.delete", capabilities.Filesystem.Delete},
		{"tools.allow", capabilities.Tools.Allow},
		{"tools.deny", capabilities.Tools.Deny},
	}
	for _, list := range lists {
		for _, value := range list.values {
			if _, err := path.Match(value, "lint/probe.txt"); err != nil {
				add(result, "SKIL-LINT-GLOB", LevelError, "Invalid capability glob",
					fmt.Sprintf("%s contains invalid glob %q: %v.", list.name, value, err), contractPath, 1,
					"Correct the glob syntax.")
			}
		}
	}
	for _, allowed := range capabilities.Tools.Allow {
		for _, denied := range capabilities.Tools.Deny {
			matched, _ := path.Match(denied, allowed)
			if matched && denied != allowed {
				add(result, "SKIL-LINT-TOOL-SHADOWED", LevelWarning, "Allowed tool shadowed by deny pattern",
					fmt.Sprintf("Allowed tool %q is matched by deny pattern %q.", allowed, denied), contractPath, 1,
					"Remove the contradiction or narrow the deny pattern.")
			}
		}
	}
	limits := capabilities.Resources
	if limits.MaxRuntimeSeconds > 86_400 || limits.MaxMemoryMB > 32_768 ||
		limits.MaxToolCalls > 10_000 || limits.MaxNetworkBytes > 10<<30 {
		add(result, "SKIL-LINT-RESOURCE-BOUNDS", LevelWarning, "Excessive resource limit",
			"One or more declared resource limits exceed conservative authoring bounds.", contractPath, 1,
			"Review and reduce the runtime, memory, network, or tool-call budget.")
	}
}

func lintPublishReadiness(result *Result, files map[string]skil.File, contract *skil.SkillContract) {
	if _, license := files["license"]; !license {
		if _, licenseMD := files["license.md"]; !licenseMD {
			if _, licenseTXT := files["license.txt"]; !licenseTXT {
				add(result, "SKIL-LINT-LICENSE-MISSING", LevelWarning, "Missing license file",
					"Publish profile requires a packaged license file.", "", 0,
					"Add LICENSE, LICENSE.md, or LICENSE.txt.")
			}
		}
	}
	if contract != nil && contract.Skill.Version != "" {
		if changelog, exists := files["changelog.md"]; exists &&
			!strings.Contains(string(changelog.Data), contract.Skill.Version) {
			add(result, "SKIL-LINT-CHANGELOG-VERSION", LevelError, "Version absent from changelog",
				fmt.Sprintf("CHANGELOG.md does not mention version %s.", contract.Skill.Version),
				changelog.Path, 1, "Document the release version in CHANGELOG.md.")
		}
	}
}

func duplicateJSONKeys(data []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var duplicates []string
	if err := walkJSONValue(decoder, "$", &duplicates); err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing token %v", token)
		}
		return nil, err
	}
	return duplicates, nil
}

func walkJSONValue(decoder *json.Decoder, location string, duplicates *[]string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("non-string JSON object key")
			}
			keyLocation := location + "." + key
			if seen[key] {
				*duplicates = append(*duplicates, keyLocation)
			}
			seen[key] = true
			if err := walkJSONValue(decoder, keyLocation, duplicates); err != nil {
				return err
			}
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSONValue(decoder, fmt.Sprintf("%s[%d]", location, index), duplicates); err != nil {
				return err
			}
			index++
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	_, err = decoder.Token()
	return err
}

func lintShebang(result *Result, file skil.File) {
	first, _, _ := bytes.Cut(file.Data, []byte("\n"))
	if !bytes.HasPrefix(first, []byte("#!")) {
		add(result, "SKIL-LINT-SHEBANG-MISSING", LevelWarning, "Executable script lacks shebang",
			"Executable script has no interpreter shebang.", file.Path, 1,
			"Declare a portable interpreter using /usr/bin/env.")
		return
	}
	line := strings.ToLower(string(first))
	extension := strings.ToLower(filepath.Ext(file.Path))
	valid := extension == ".py" && strings.Contains(line, "python") ||
		(extension == ".sh" || extension == ".bash") && strings.Contains(line, "sh") ||
		(extension == ".js" || extension == ".mjs" || extension == ".cjs") &&
			(strings.Contains(line, "node") || strings.Contains(line, "deno") || strings.Contains(line, "bun"))
	if !valid {
		add(result, "SKIL-LINT-SHEBANG-MISMATCH", LevelWarning, "Shebang conflicts with file type",
			fmt.Sprintf("Interpreter %q does not match %s.", string(first), extension), file.Path, 1,
			"Use an interpreter consistent with the script language.")
	}
}

func resolvesLocalImport(source, target string, files map[string]skil.File, suffixes []string) bool {
	resolved := path.Clean(path.Join(path.Dir(filepath.ToSlash(source)), target))
	return existsCandidate(files, resolved, suffixes)
}

func existsCandidate(files map[string]skil.File, base string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if _, exists := files[strings.ToLower(base+suffix)]; exists {
			return true
		}
	}
	return false
}

func addMissingImport(result *Result, file skil.File, target string, offset int) {
	add(result, "SKIL-LINT-IMPORT-BROKEN", LevelWarning, "Unresolved local import",
		fmt.Sprintf("Local import %q does not resolve to a packaged file.", target),
		file.Path, lineAt(file.Data, offset), "Correct the import or include the referenced file.")
}

func markdownAnchors(data []byte) map[string]bool {
	anchors := map[string]bool{}
	for _, match := range headingPattern.FindAllSubmatch(data, -1) {
		anchors[markdownAnchor(string(match[2]))] = true
	}
	return anchors
}

func markdownAnchor(title string) string {
	title = strings.ToLower(strings.TrimSpace(title))
	var out strings.Builder
	lastHyphen := false
	for _, char := range title {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char >= 0x80:
			out.WriteRune(char)
			lastHyphen = false
		case char == ' ' || char == '-' || char == '_':
			if out.Len() > 0 && !lastHyphen {
				out.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	return strings.Trim(out.String(), "-")
}

func fencePrefix(line string) string {
	if strings.HasPrefix(line, "```") {
		return line[:countPrefix(line, '`')]
	}
	if strings.HasPrefix(line, "~~~") {
		return line[:countPrefix(line, '~')]
	}
	return ""
}

func countPrefix(value string, char byte) int {
	count := 0
	for count < len(value) && value[count] == char {
		count++
	}
	return count
}

func deterministicDependency(version string) bool {
	version = strings.TrimSpace(version)
	return exactVersion.MatchString(version) || commitVersion.MatchString(version)
}

func isTextFile(name string) bool {
	switch filepath.Ext(name) {
	case ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".lock", ".mod", ".sum", ".sh", ".bash", ".py", ".js", ".ts", ".tsx":
		return true
	default:
		return filepath.Base(name) == "version" || strings.HasPrefix(filepath.Base(name), "license")
	}
}

func temporaryArtifact(name string) bool {
	base := filepath.Base(name)
	return base == ".ds_store" || base == "thumbs.db" || strings.HasSuffix(base, ".swp") ||
		strings.HasSuffix(base, ".tmp") || strings.HasSuffix(base, ".sarif") ||
		strings.HasSuffix(base, ".orig") || strings.HasSuffix(base, "~")
}

func windowsReservedName(name string) bool {
	switch name {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

func isScript(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sh", ".bash", ".py", ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func findContractPath(files []skil.File) string {
	paths := findContractPaths(files)
	if len(paths) == 1 {
		return paths[0]
	}
	return ""
}
