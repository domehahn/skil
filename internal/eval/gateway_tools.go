package eval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/pkg/skil"
)

// ArtifactReadTool exposes the canonical, immutable artifact view. It never
// opens an adapter-supplied host path.
type ArtifactReadTool struct {
	files map[string][]byte
}

type WorkspaceTool struct {
	root  string
	write bool
}

func NewWorkspaceReadTool(root string) *WorkspaceTool {
	return &WorkspaceTool{root: root}
}

func NewWorkspaceWriteTool(root string) *WorkspaceTool {
	return &WorkspaceTool{root: root, write: true}
}

func (t *WorkspaceTool) Operation(arguments map[string]any) (skil.Operation, error) {
	path, _, err := workspaceArguments(arguments, t.write)
	if err != nil {
		return skil.Operation{}, err
	}
	capability := "filesystem.read"
	if t.write {
		capability = "filesystem.write"
	}
	return skil.Operation{Capability: capability, Target: path}, nil
}

func (t *WorkspaceTool) Execute(_ context.Context, arguments map[string]any) (any, error) {
	path, content, err := workspaceArguments(arguments, t.write)
	if err != nil {
		return nil, err
	}
	target, err := confinedWorkspacePath(t.root, path)
	if err != nil {
		return nil, err
	}
	if !t.write {
		data, err := os.ReadFile(target)
		if err != nil {
			return nil, err
		}
		if len(data) > 1<<20 {
			return nil, errors.New("workspace.read file exceeds 1 MiB")
		}
		return map[string]any{"path": path, "content": string(data)}, nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("workspace.write refuses symlink targets")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"path": path, "bytes_written": len(content)}, nil
}

func workspaceArguments(arguments map[string]any, write bool) (string, string, error) {
	expected := 1
	if write {
		expected = 2
	}
	if len(arguments) != expected {
		return "", "", errors.New("workspace tool received an unexpected argument count")
	}
	pathValue, ok := arguments["path"].(string)
	if !ok {
		return "", "", errors.New("workspace path must be a string")
	}
	path, err := canonicalRelativePath(pathValue)
	if err != nil {
		return "", "", err
	}
	content := ""
	if write {
		content, ok = arguments["content"].(string)
		if !ok || len(content) > 1<<20 {
			return "", "", errors.New("workspace.write content must be a string up to 1 MiB")
		}
	}
	return path, content, nil
}

func confinedWorkspacePath(root, relative string) (string, error) {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return "", errors.New("workspace root must be absolute")
	}
	target := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return "", errors.New("workspace path escapes the trusted root")
	}
	current := root
	for _, component := range strings.Split(filepath.ToSlash(filepath.Dir(relative)), "/") {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(component))
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("workspace path traverses a symlink")
		}
	}
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("workspace path resolves to a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return target, nil
}

func canonicalRelativePath(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, 0) || filepath.IsAbs(value) {
		return "", errors.New("path must be a non-empty relative string")
	}
	path := filepath.ToSlash(filepath.Clean(value))
	if path == "." || path == ".." || strings.HasPrefix(path, "../") || path != value {
		return "", errors.New("path must be canonical and traversal-free")
	}
	return path, nil
}

type IsolatedCommandTool struct {
	isolation IsolationProvider
	maxOutput int64
}

func NewIsolatedCommandTool(isolation IsolationProvider, maxOutput int64) *IsolatedCommandTool {
	return &IsolatedCommandTool{isolation: isolation, maxOutput: maxOutput}
}

func (t *IsolatedCommandTool) Operation(arguments map[string]any) (skil.Operation, error) {
	argv, err := commandArguments(arguments)
	if err != nil {
		return skil.Operation{}, err
	}
	return skil.Operation{Capability: "commands.execute", Command: argv}, nil
}

func (t *IsolatedCommandTool) Execute(ctx context.Context, arguments map[string]any) (any, error) {
	if t.isolation == nil {
		return nil, errors.New("command tool requires native isolation")
	}
	argv, err := commandArguments(arguments)
	if err != nil {
		return nil, err
	}
	limit := t.maxOutput
	if limit <= 0 || limit > 1<<20 {
		limit = 1 << 20
	}
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = limit, limit
	err = t.isolation.Run(ctx, IsolationRequest{
		Executable: argv[0], Args: argv[1:], Environment: []string{"PATH=/usr/bin:/bin"},
	}, &stdout, &stderr)
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("isolated command output limit exceeded")
	}
	if err != nil {
		return nil, fmt.Errorf("isolated command failed: %w", err)
	}
	return map[string]any{"stdout": stdout.String(), "stderr": stderr.String()}, nil
}

func commandArguments(arguments map[string]any) ([]string, error) {
	if len(arguments) != 1 {
		return nil, errors.New("command.run requires exactly one argv argument")
	}
	raw, ok := arguments["argv"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 64 {
		return nil, errors.New("command.run argv must contain between 1 and 64 strings")
	}
	argv := make([]string, len(raw))
	for index, value := range raw {
		text, ok := value.(string)
		if !ok || text == "" || len(text) > 4096 || strings.ContainsAny(text, "\x00\r\n") {
			return nil, errors.New("command.run argv contains an invalid argument")
		}
		argv[index] = text
	}
	switch strings.ToLower(filepath.Base(argv[0])) {
	case "sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh":
		return nil, errors.New("command.run does not permit shell executables")
	}
	return argv, nil
}

type ipResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type NetworkGetTool struct {
	resolver    ipResolver
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func NewNetworkGetTool() *NetworkGetTool {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &NetworkGetTool{resolver: net.DefaultResolver, dialContext: dialer.DialContext}
}

func (*NetworkGetTool) Operation(arguments map[string]any) (skil.Operation, error) {
	parsed, maximum, err := networkArguments(arguments)
	if err != nil {
		return skil.Operation{}, err
	}
	return skil.Operation{
		Capability: "network.outbound", Target: parsed.Hostname(),
		NetworkBytes: maximum, External: true,
	}, nil
}

func (t *NetworkGetTool) Execute(ctx context.Context, arguments map[string]any) (any, error) {
	parsed, maximum, err := networkArguments(arguments)
	if err != nil {
		return nil, err
	}
	resolver, dial := t.networkDependencies()
	if _, err := resolvePublicHost(ctx, resolver, parsed.Hostname()); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(parsed.Hostname(), ".")) {
			return nil, errors.New("network.get destination changed during dialing")
		}
		ips, err := resolvePublicHost(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		return dial(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	client := &http.Client{
		Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("network.get redirects are disabled")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, errors.New("network.get response exceeds max_bytes")
	}
	return map[string]any{"status": response.StatusCode, "body": string(body)}, nil
}

func networkArguments(arguments map[string]any) (*url.URL, int64, error) {
	if len(arguments) < 1 || len(arguments) > 2 {
		return nil, 0, errors.New("network.get requires url and optional max_bytes")
	}
	for key := range arguments {
		if key != "url" && key != "max_bytes" {
			return nil, 0, errors.New("network.get received an unexpected argument")
		}
	}
	rawURL, ok := arguments["url"].(string)
	if !ok || len(rawURL) > 4096 {
		return nil, 0, errors.New("network.get url must be a bounded string")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return nil, 0, errors.New("network.get requires an HTTPS URL without credentials or fragment")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return nil, 0, errors.New("network.get permits only HTTPS port 443")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && !publicIP(ip) {
		return nil, 0, errors.New("network.get rejects non-public IP destinations")
	}
	maximum := int64(1 << 20)
	if value, exists := arguments["max_bytes"]; exists {
		number, ok := value.(float64)
		if !ok || number < 1 || number > 1<<20 || number != float64(int64(number)) {
			return nil, 0, errors.New("network.get max_bytes must be an integer between 1 and 1 MiB")
		}
		maximum = int64(number)
	}
	return parsed, maximum, nil
}

func (t *NetworkGetTool) networkDependencies() (ipResolver, func(context.Context, string, string) (net.Conn, error)) {
	resolver := t.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := t.dialContext
	if dial == nil {
		netDialer := &net.Dialer{Timeout: 10 * time.Second}
		dial = netDialer.DialContext
	}
	return resolver, dial
}

func resolvePublicHost(ctx context.Context, resolver ipResolver, host string) ([]net.IP, error) {
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("network.get destination resolution failed")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, errors.New("network.get resolved to a non-public address")
		}
	}
	return ips, nil
}

func publicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, blocked := range blockedNetworkPrefixes {
		if blocked.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

var blockedNetworkPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func NewArtifactReadTool(artifact skil.Artifact) *ArtifactReadTool {
	files := make(map[string][]byte, len(artifact.Files))
	for _, file := range artifact.Files {
		files[file.Path] = append([]byte(nil), file.Data...)
	}
	return &ArtifactReadTool{files: files}
}

func (t *ArtifactReadTool) Operation(arguments map[string]any) (skil.Operation, error) {
	path, err := canonicalArtifactPath(arguments)
	if err != nil {
		return skil.Operation{}, err
	}
	if _, exists := t.files[path]; !exists {
		return skil.Operation{}, fmt.Errorf("artifact file %q does not exist", path)
	}
	return skil.Operation{Capability: "filesystem.read", Target: path}, nil
}

func (t *ArtifactReadTool) Execute(_ context.Context, arguments map[string]any) (any, error) {
	path, err := canonicalArtifactPath(arguments)
	if err != nil {
		return nil, err
	}
	data, exists := t.files[path]
	if !exists {
		return nil, fmt.Errorf("artifact file %q does not exist", path)
	}
	return map[string]any{"path": path, "content": string(data)}, nil
}

func canonicalArtifactPath(arguments map[string]any) (string, error) {
	if len(arguments) != 1 {
		return "", errors.New("artifact.read requires exactly one path argument")
	}
	value, ok := arguments["path"].(string)
	if !ok || value == "" || strings.ContainsRune(value, 0) || filepath.IsAbs(value) {
		return "", errors.New("artifact.read path must be a non-empty relative string")
	}
	path := filepath.ToSlash(filepath.Clean(value))
	if path == "." || path == ".." || strings.HasPrefix(path, "../") || path != value {
		return "", errors.New("artifact.read path must be canonical and traversal-free")
	}
	return path, nil
}
