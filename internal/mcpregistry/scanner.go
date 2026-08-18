// Package mcpregistry performs deterministic security-posture checks on MCP
// Registry v0.1 responses and publisher server.json documents.
package mcpregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion    = "1.0.0"
	MaxDocumentBytes = 16 << 20
	OfficialBaseURL  = "https://registry.modelcontextprotocol.io"
)

type Options struct {
	Official             bool
	LatestEndpoint       bool
	ExpectedRecordSHA256 string
	ReviewedClosure      map[string]string
	BaselineRepositories map[string]string
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Source        string         `json:"source"`
	SourceSHA256  string         `json:"source_sha256"`
	Records       []RecordReport `json:"records"`
	Findings      []Finding      `json:"findings"`
	Summary       Summary        `json:"summary"`
}

type Summary struct {
	Records  int  `json:"records"`
	Findings int  `json:"findings"`
	Passed   bool `json:"passed"`
}

type RecordReport struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Status       string    `json:"status,omitempty"`
	IsLatest     *bool     `json:"is_latest,omitempty"`
	ServerSHA256 string    `json:"server_sha256"`
	RecordSHA256 string    `json:"record_sha256"`
	Findings     []Finding `json:"findings,omitempty"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Record   string `json:"record,omitempty"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`
}

type Entry struct {
	Server Server `json:"server"`
	Meta   Meta   `json:"_meta"`
}

type Server struct {
	Schema      string      `json:"$schema"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Version     string      `json:"version"`
	Repository  *Repository `json:"repository,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	Remotes     []Remote    `json:"remotes,omitempty"`
}

type Repository struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

type Package struct {
	RegistryType string `json:"registryType"`
	Identifier   string `json:"identifier"`
	Version      string `json:"version,omitempty"`
	FileSHA256   string `json:"fileSha256,omitempty"`
}

type Remote struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Meta struct {
	Official *OfficialMeta `json:"io.modelcontextprotocol.registry/official,omitempty"`
}

type OfficialMeta struct {
	Status   string `json:"status"`
	IsLatest *bool  `json:"isLatest"`
}

type decodedDocument struct {
	Entries       []decodedEntry
	DeclaredCount *int
}

type decodedEntry struct {
	Entry     Entry
	RawEntry  json.RawMessage
	RawServer json.RawMessage
}

func Scan(source string, data []byte, options Options) (Report, error) {
	if len(data) == 0 {
		return Report{}, errors.New("MCP registry document is empty")
	}
	if len(data) > MaxDocumentBytes {
		return Report{}, fmt.Errorf("MCP registry document exceeds %d bytes", MaxDocumentBytes)
	}
	if err := validateJSON(data); err != nil {
		return Report{}, fmt.Errorf("parse MCP registry document: %w", err)
	}
	document, err := decodeDocument(data)
	if err != nil {
		return Report{}, err
	}
	if len(document.Entries) == 0 {
		return Report{}, errors.New("MCP registry document contains no server records")
	}
	if options.ExpectedRecordSHA256 != "" && len(document.Entries) != 1 {
		return Report{}, errors.New("expected record digest requires exactly one server record")
	}
	if options.ExpectedRecordSHA256 != "" && !validSHA256(options.ExpectedRecordSHA256) {
		return Report{}, errors.New("expected record digest must be 64 hexadecimal characters")
	}

	report := Report{SchemaVersion: SchemaVersion, Source: source, SourceSHA256: digest(data)}
	for _, item := range document.Entries {
		record := scanRecord(item, options)
		report.Records = append(report.Records, record)
		report.Findings = append(report.Findings, record.Findings...)
	}
	if document.DeclaredCount != nil && *document.DeclaredCount != len(document.Entries) {
		report.Findings = append(report.Findings, Finding{
			Code: "MCP-REG-010", Severity: "MEDIUM", Field: "metadata.count",
			Message: fmt.Sprintf("registry metadata count %d does not match %d records", *document.DeclaredCount, len(document.Entries)),
		})
	}
	report.Findings = append(report.Findings, latestConsistencyFindings(document.Entries)...)
	sortFindings(report.Findings)
	report.Summary = Summary{Records: len(report.Records), Findings: len(report.Findings), Passed: len(report.Findings) == 0}
	return report, nil
}

func scanRecord(item decodedEntry, options Options) RecordReport {
	server := item.Entry.Server
	record := RecordReport{
		Name: server.Name, Version: server.Version,
		ServerSHA256: digestCanonical(item.RawServer), RecordSHA256: digestCanonical(item.RawEntry),
	}
	if item.Entry.Meta.Official != nil {
		record.Status = item.Entry.Meta.Official.Status
		record.IsLatest = item.Entry.Meta.Official.IsLatest
	}
	add := func(code, severity, field, message string) {
		record.Findings = append(record.Findings, Finding{Code: code, Severity: severity, Record: server.Name, Field: field, Message: message})
	}
	if server.Schema == "" || server.Name == "" || server.Version == "" {
		add("MCP-REG-001", "HIGH", "server", "server record must declare $schema, name, and version")
	}
	if server.Schema != "" && !officialSchemaURL(server.Schema) {
		add("MCP-REG-018", "HIGH", "server.$schema", "server schema must use the official HTTPS server.schema.json URI")
	}
	if mutableVersion(server.Version) {
		add("MCP-REG-002", "HIGH", "server.version", "server version is empty, ranged, or mutable")
	}
	if len(server.Packages) == 0 && len(server.Remotes) == 0 {
		add("MCP-REG-003", "HIGH", "server", "server declares neither a package nor a remote endpoint")
	}
	if server.Repository == nil || strings.TrimSpace(server.Repository.URL) == "" {
		add("MCP-REG-004", "MEDIUM", "server.repository", "server does not declare a source repository")
	} else {
		if !secureURL(server.Repository.URL) {
			add("MCP-REG-005", "HIGH", "server.repository.url", "repository URL must use HTTPS without embedded credentials")
		}
		if previous := options.BaselineRepositories[server.Name]; previous != "" && normalizeRepository(previous) != normalizeRepository(server.Repository.URL) {
			add("MCP-REG-011", "HIGH", "server.repository.url", "repository ownership changed relative to the baseline snapshot")
		}
		if !publisherMatchesRepository(server.Name, server.Repository.URL) {
			add("MCP-REG-012", "HIGH", "server.repository.url", "GitHub namespace owner does not match the declared repository owner")
		}
	}
	for index, pkg := range server.Packages {
		field := fmt.Sprintf("server.packages[%d]", index)
		if pkg.RegistryType == "" || pkg.Identifier == "" {
			add("MCP-REG-001", "HIGH", field, "package requires registryType and identifier")
		}
		kind := strings.ToLower(pkg.RegistryType)
		if kind != "oci" && kind != "mcpb" && mutableVersion(pkg.Version) {
			add("MCP-REG-002", "HIGH", field+".version", "package version is empty, ranged, or mutable")
		}
		if kind == "oci" && mutableOCIIdentifier(pkg.Identifier) {
			add("MCP-REG-002", "HIGH", field+".identifier", "OCI package identifier is unversioned or uses a mutable latest tag")
		}
		if kind == "mcpb" && pkg.FileSHA256 == "" {
			add("MCP-REG-006", "HIGH", field+".fileSha256", "MCPB package requires fileSha256")
		} else if pkg.FileSHA256 != "" && !validSHA256(pkg.FileSHA256) {
			add("MCP-REG-007", "HIGH", field+".fileSha256", "fileSha256 must contain exactly 64 hexadecimal characters")
		}
		if options.ReviewedClosure != nil {
			expected, exists := options.ReviewedClosure[pkg.Identifier]
			if !exists {
				add("MCP-REG-013", "HIGH", field+".identifier", "package is absent from the reviewed execution closure")
			} else if pkg.FileSHA256 == "" {
				add("MCP-REG-013", "HIGH", field+".fileSha256", "reviewed-closure comparison requires a package digest")
			} else if !strings.EqualFold(expected, pkg.FileSHA256) {
				add("MCP-REG-014", "CRITICAL", field+".fileSha256", "package digest does not match the reviewed execution closure")
			}
		}
	}
	for index, remote := range server.Remotes {
		if !secureURL(remote.URL) {
			add("MCP-REG-008", "HIGH", fmt.Sprintf("server.remotes[%d].url", index), "remote MCP endpoint must use HTTPS without embedded credentials")
		}
	}
	if options.Official {
		official := item.Entry.Meta.Official
		if official == nil {
			add("MCP-REG-009", "HIGH", "_meta", "official registry record lacks official registry metadata")
		} else {
			if official.Status != "active" {
				add("MCP-REG-009", "HIGH", "_meta.status", "official registry status is not active")
			}
			if options.LatestEndpoint && (official.IsLatest == nil || !*official.IsLatest) {
				add("MCP-REG-009", "HIGH", "_meta.isLatest", "official latest endpoint did not return a latest record")
			}
		}
	}
	if options.ExpectedRecordSHA256 != "" && !strings.EqualFold(options.ExpectedRecordSHA256, record.RecordSHA256) {
		add("MCP-REG-015", "CRITICAL", "record_sha256", "normalized record digest does not match the expected digest")
	}
	sortFindings(record.Findings)
	return record
}

func decodeDocument(data []byte) (decodedDocument, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return decodedDocument{}, err
	}
	if rawServers, exists := root["servers"]; exists {
		var records []json.RawMessage
		if err := json.Unmarshal(rawServers, &records); err != nil {
			return decodedDocument{}, errors.New("servers must be an array")
		}
		document := decodedDocument{}
		if rawMetadata, ok := root["metadata"]; ok {
			var metadata struct {
				Count *int `json:"count"`
			}
			if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
				return decodedDocument{}, errors.New("metadata must be an object")
			}
			document.DeclaredCount = metadata.Count
		}
		for _, raw := range records {
			entry, err := decodeEntry(raw)
			if err != nil {
				return decodedDocument{}, err
			}
			document.Entries = append(document.Entries, entry)
		}
		return document, nil
	}
	if _, exists := root["server"]; exists {
		entry, err := decodeEntry(data)
		return decodedDocument{Entries: []decodedEntry{entry}}, err
	}
	serverRaw := json.RawMessage(append([]byte(nil), data...))
	entryRaw, err := json.Marshal(map[string]json.RawMessage{"server": serverRaw})
	if err != nil {
		return decodedDocument{}, err
	}
	entry, err := decodeEntry(entryRaw)
	return decodedDocument{Entries: []decodedEntry{entry}}, err
}

func decodeEntry(raw json.RawMessage) (decodedEntry, error) {
	var envelope struct {
		Server json.RawMessage `json:"server"`
		Meta   Meta            `json:"_meta"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Server) == 0 {
		return decodedEntry{}, errors.New("registry entry must contain a server object")
	}
	var server Server
	if err := json.Unmarshal(envelope.Server, &server); err != nil {
		return decodedEntry{}, errors.New("registry entry contains an invalid server object")
	}
	return decodedEntry{Entry: Entry{Server: server, Meta: envelope.Meta}, RawEntry: raw, RawServer: envelope.Server}, nil
}

func validateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = true
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func latestConsistencyFindings(entries []decodedEntry) []Finding {
	byName := map[string][]decodedEntry{}
	seenVersion := map[string]bool{}
	var findings []Finding
	for _, entry := range entries {
		key := entry.Entry.Server.Name + "\x00" + entry.Entry.Server.Version
		if seenVersion[key] {
			findings = append(findings, Finding{Code: "MCP-REG-016", Severity: "HIGH", Record: entry.Entry.Server.Name,
				Field: "server.version", Message: "registry contains a duplicate name/version record"})
		}
		seenVersion[key] = true
		byName[entry.Entry.Server.Name] = append(byName[entry.Entry.Server.Name], entry)
	}
	for name, versions := range byName {
		if len(versions) < 2 {
			continue
		}
		latestCount := 0
		latestVersion := ""
		for _, entry := range versions {
			if entry.Entry.Meta.Official != nil && entry.Entry.Meta.Official.IsLatest != nil && *entry.Entry.Meta.Official.IsLatest {
				latestCount++
				latestVersion = entry.Entry.Server.Version
			}
		}
		if latestCount != 1 {
			findings = append(findings, Finding{Code: "MCP-REG-017", Severity: "HIGH", Record: name,
				Field: "_meta.isLatest", Message: "multiple-version registry set must mark exactly one record as latest"})
		} else if highest, ok := highestSemanticVersion(versions); ok && compareSemanticVersions(latestVersion, highest) != 0 {
			findings = append(findings, Finding{Code: "MCP-REG-019", Severity: "HIGH", Record: name,
				Field: "_meta.isLatest", Message: fmt.Sprintf("record %s is marked latest but %s is the highest semantic version", latestVersion, highest)})
		}
	}
	sortFindings(findings)
	return findings
}

var semanticVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

type semanticVersion struct {
	major, minor, patch int
	prerelease          []string
}

func highestSemanticVersion(entries []decodedEntry) (string, bool) {
	highest := ""
	for _, entry := range entries {
		version := entry.Entry.Server.Version
		if _, ok := parseSemanticVersion(version); !ok {
			return "", false
		}
		if highest == "" || compareSemanticVersions(version, highest) > 0 {
			highest = version
		}
	}
	return highest, highest != ""
}

func compareSemanticVersions(left, right string) int {
	a, aOK := parseSemanticVersion(left)
	b, bOK := parseSemanticVersion(right)
	if !aOK || !bOK {
		return strings.Compare(left, right)
	}
	for _, pair := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(a.prerelease) == 0 || len(b.prerelease) == 0 {
		if len(a.prerelease) == len(b.prerelease) {
			return 0
		}
		if len(a.prerelease) == 0 {
			return 1
		}
		return -1
	}
	for index := 0; index < len(a.prerelease) && index < len(b.prerelease); index++ {
		if comparison := comparePrereleaseIdentifier(a.prerelease[index], b.prerelease[index]); comparison != 0 {
			return comparison
		}
	}
	if len(a.prerelease) < len(b.prerelease) {
		return -1
	}
	if len(a.prerelease) > len(b.prerelease) {
		return 1
	}
	return 0
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	matches := semanticVersionPattern.FindStringSubmatch(value)
	if matches == nil {
		return semanticVersion{}, false
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	version := semanticVersion{major: major, minor: minor, patch: patch}
	if matches[4] != "" {
		version.prerelease = strings.Split(matches[4], ".")
	}
	return version, true
}

func comparePrereleaseIdentifier(left, right string) int {
	leftNumber, leftErr := strconv.Atoi(left)
	rightNumber, rightErr := strconv.Atoi(right)
	if leftErr == nil && rightErr == nil {
		if leftNumber < rightNumber {
			return -1
		}
		if leftNumber > rightNumber {
			return 1
		}
		return 0
	}
	if leftErr == nil {
		return -1
	}
	if rightErr == nil {
		return 1
	}
	return strings.Compare(left, right)
}

func mutableVersion(version string) bool {
	value := strings.TrimSpace(strings.ToLower(version))
	if value == "" || value == "latest" || value == "main" || value == "master" || value == "*" {
		return true
	}
	return strings.ContainsAny(value, "*^~<>=| ") || strings.HasSuffix(value, ".x")
}

func mutableOCIIdentifier(identifier string) bool {
	value := strings.TrimSpace(strings.ToLower(identifier))
	if value == "" || strings.HasSuffix(value, ":latest") {
		return true
	}
	if strings.Contains(value, "@sha256:") {
		parts := strings.Split(value, "@sha256:")
		return len(parts) != 2 || !validSHA256(parts[1])
	}
	lastSlash := strings.LastIndex(value, "/")
	return !strings.Contains(value[lastSlash+1:], ":")
}

func secureURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil
}

func officialSchemaURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.User == nil &&
		strings.EqualFold(parsed.Hostname(), "static.modelcontextprotocol.io") &&
		strings.HasPrefix(parsed.EscapedPath(), "/schemas/") && strings.HasSuffix(parsed.EscapedPath(), "/server.schema.json") &&
		parsed.RawQuery == "" && parsed.Fragment == ""
}

func publisherMatchesRepository(name, repository string) bool {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || !strings.HasPrefix(strings.ToLower(parts[0]), "io.github.") {
		return true
	}
	expectedOwner := strings.TrimPrefix(strings.ToLower(parts[0]), "io.github.")
	parsed, err := url.Parse(repository)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "github.com") {
		return true
	}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	return len(pathParts) >= 2 && strings.EqualFold(expectedOwner, pathParts[0])
}

func normalizeRepository(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return strings.TrimSuffix(strings.ToLower(value), ".git")
	}
	return strings.ToLower(parsed.Hostname() + "/" + strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git"))
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digestCanonical(raw json.RawMessage) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	canonical, _ := json.Marshal(value)
	return digest(canonical)
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		return left.Record+"\x00"+left.Code+"\x00"+left.Field < right.Record+"\x00"+right.Code+"\x00"+right.Field
	})
}

func ParseReviewedClosure(data []byte) (map[string]string, error) {
	var document struct {
		ReviewedClosure []struct {
			Identifier string `json:"identifier"`
			SHA256     string `json:"sha256"`
		} `json:"reviewed_closure"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	closure := map[string]string{}
	for _, item := range document.ReviewedClosure {
		if item.Identifier == "" || !validSHA256(item.SHA256) {
			return nil, errors.New("reviewed closure entries require an identifier and valid sha256")
		}
		if _, exists := closure[item.Identifier]; exists {
			return nil, fmt.Errorf("reviewed closure contains duplicate identifier %q", item.Identifier)
		}
		closure[item.Identifier] = strings.ToLower(item.SHA256)
	}
	return closure, nil
}

func BaselineRepositories(data []byte) (map[string]string, error) {
	if err := validateJSON(data); err != nil {
		return nil, err
	}
	document, err := decodeDocument(data)
	if err != nil {
		return nil, err
	}
	repositories := map[string]string{}
	for _, entry := range document.Entries {
		if _, exists := repositories[entry.Entry.Server.Name]; exists {
			return nil, fmt.Errorf("baseline contains duplicate server %q", entry.Entry.Server.Name)
		}
		if entry.Entry.Server.Repository != nil {
			repositories[entry.Entry.Server.Name] = entry.Entry.Server.Repository.URL
		}
	}
	return repositories, nil
}

func NewOfficialHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("MCP registry redirects are disabled") }}
}
