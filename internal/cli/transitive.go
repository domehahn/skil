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
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/transitive"
)

// maxSingleReferenceBytes bounds one reference fetch independently of the
// traversal's overall shared byte budget — a defense-in-depth cap so a
// single reference can never itself claim the entire remaining budget in
// one request regardless of how much budget happens to be left.
const maxSingleReferenceBytes int64 = 2 << 20

// httpsReferenceFetcher builds a transitive.Fetcher with the same
// DNS-rebinding-resistant, redirect-disabled, private/loopback-address-
// rejecting security boundary internal/cli/remote.go's remote-source
// downloader already uses — deliberately a new, small, standalone
// function rather than a refactor of that existing, already-relied-upon
// code path, to avoid any regression risk there.
func httpsReferenceFetcher() transitive.Fetcher {
	return func(ctx context.Context, rawURL string, remainingBudget int64) (transitive.FetchResult, error) {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return transitive.FetchResult{}, fmt.Errorf("parse reference URL: %w", err)
		}
		if parsed.Scheme != "https" {
			return transitive.FetchResult{}, errors.New("transitive references require https")
		}
		if parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
			return transitive.FetchResult{}, errors.New("reference URL must not contain credentials or a fragment")
		}
		limit := remainingBudget
		if limit > maxSingleReferenceBytes {
			limit = maxSingleReferenceBytes
		}
		if limit <= 0 {
			return transitive.FetchResult{}, errors.New("no download budget remaining")
		}

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
				return nil, errors.New("reference host did not resolve")
			}
			for _, ip := range ips {
				if err := validateResolvedIP(ip); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		}
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("reference redirects are disabled") }}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return transitive.FetchResult{}, err
		}
		response, err := client.Do(request)
		if err != nil {
			return transitive.FetchResult{}, fmt.Errorf("fetch reference: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return transitive.FetchResult{}, fmt.Errorf("reference returned HTTP %d", response.StatusCode)
		}

		file, err := os.CreateTemp("", "skil-reference-*"+referenceSuffix(parsed.Path))
		if err != nil {
			return transitive.FetchResult{}, err
		}
		path := file.Name()
		cleanup := func() { _ = os.Remove(path) }
		written, copyErr := io.Copy(file, io.LimitReader(response.Body, limit+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			cleanup()
			return transitive.FetchResult{}, errors.Join(copyErr, closeErr)
		}
		if written > limit {
			cleanup()
			return transitive.FetchResult{}, fmt.Errorf("reference exceeds %d-byte limit", limit)
		}
		return transitive.FetchResult{Path: path, BytesUsed: written, Cleanup: cleanup}, nil
	}
}

// referenceSuffix keeps a recognizable extension (so artifact.Load's own
// extension-based dispatch — e.g. .zip/.tgz archive handling — still
// applies to a fetched reference) when the URL path has one, and falls
// back to a generic suffix otherwise.
func referenceSuffix(path string) string {
	ext := filepath.Ext(path)
	if ext == "" || strings.ContainsAny(ext, "/\\") {
		return ".ref"
	}
	return ext
}
