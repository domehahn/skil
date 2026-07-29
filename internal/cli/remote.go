package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/artifact"
)

func stageRemoteSource(ctx context.Context, source string, allowed bool) (string, func(), error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" {
		return source, func() {}, nil
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme == "http" || parsed.Scheme == "git" || parsed.Scheme == "ssh" || parsed.Scheme == "file" {
			return "", func() {}, errors.New("remote sources require public HTTPS")
		}
		return source, func() {}, nil
	}
	if !allowed {
		return "", func() {}, errors.New("remote source requires explicit --allow-remote")
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return "", func() {}, errors.New("remote source URL must not contain credentials or a fragment")
	}
	if err := validatePublicRemoteHost(ctx, parsed.Hostname()); err != nil {
		return "", func() {}, err
	}
	tempRoot, err := os.MkdirTemp("", "skil-remote-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tempRoot) }
	if remoteArchive(parsed.Path) {
		path, err := downloadRemoteArchive(ctx, parsed, tempRoot)
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		return path, cleanup, nil
	}
	if parsed.RawQuery != "" {
		cleanup()
		return "", func() {}, errors.New("remote Git URL must not contain a query")
	}
	path := filepath.Join(tempRoot, "repository")
	runContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	command := exec.CommandContext(runContext, "git",
		"-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
		"-c", "credential.helper=", "-c", "http.followRedirects=false",
		"clone", "--depth", "1", "--filter=blob:limit=4194304", "--no-tags", "--no-recurse-submodules", source, path)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	output := &boundedCommandOutput{limit: 1 << 20}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("clone remote source: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return path, cleanup, nil
}

func remoteArchive(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz")
}

func validatePublicRemoteHost(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return errors.New("remote source host did not resolve")
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("remote source resolves to prohibited address %s", ip)
		}
	}
	return nil
}

func downloadRemoteArchive(ctx context.Context, parsed *url.URL, root string) (string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("remote archive host did not resolve")
		}
		for _, ip := range ips {
			if err := validateResolvedIP(ip); err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("remote source redirects are disabled") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download remote source: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote source returned HTTP %d", response.StatusCode)
	}
	suffix := ".zip"
	if strings.HasSuffix(strings.ToLower(parsed.Path), ".tgz") {
		suffix = ".tgz"
	} else if strings.HasSuffix(strings.ToLower(parsed.Path), ".tar.gz") {
		suffix = ".tar.gz"
	}
	file, err := os.CreateTemp(root, "source-*"+suffix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, artifact.MaxArchiveRaw+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	if written > artifact.MaxArchiveRaw {
		return "", errors.New("remote archive exceeds compressed size limit")
	}
	return path, nil
}

func validateResolvedIP(ip net.IP) error {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("remote source resolved to prohibited address %s", ip)
	}
	return nil
}

type boundedCommandOutput struct {
	data  []byte
	limit int
}

func (b *boundedCommandOutput) Write(value []byte) (int, error) {
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		b.data = append(b.data, value[:min(remaining, len(value))]...)
	}
	return len(value), nil
}
func (b *boundedCommandOutput) String() string { return string(b.data) }
