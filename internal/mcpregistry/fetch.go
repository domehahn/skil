package mcpregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func FetchOfficial(ctx context.Context, serverName string, client *http.Client) ([]byte, string, bool, error) {
	if client == nil {
		client = NewOfficialHTTPClient()
	}
	endpoint := OfficialBaseURL + "/v0.1/servers"
	latest := false
	if serverName != "" {
		if !validServerName(serverName) {
			return nil, "", false, errors.New("official MCP server name must use namespace/name syntax")
		}
		endpoint += "/" + url.PathEscape(serverName) + "/versions/latest"
		latest = true
	} else {
		data, err := fetchOfficialList(ctx, client, endpoint)
		return data, endpoint, false, err
	}
	data, err := fetch(ctx, client, endpoint)
	return data, endpoint, latest, err
}

func fetchOfficialList(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	const maxPages = 1000
	var records []json.RawMessage
	totalBytes := 0
	cursor := ""
	for page := 0; page < maxPages; page++ {
		query := url.Values{"limit": {"100"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		data, err := fetch(ctx, client, endpoint+"?"+query.Encode())
		if err != nil {
			return nil, err
		}
		if err := validateJSON(data); err != nil {
			return nil, fmt.Errorf("parse MCP registry page: %w", err)
		}
		var pageDocument struct {
			Servers  []json.RawMessage `json:"servers"`
			Metadata struct {
				NextCursor string `json:"nextCursor"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(data, &pageDocument); err != nil {
			return nil, fmt.Errorf("parse MCP registry page: %w", err)
		}
		for _, record := range pageDocument.Servers {
			totalBytes += len(record)
			if totalBytes > MaxDocumentBytes {
				return nil, fmt.Errorf("aggregated MCP registry response exceeds %d bytes", MaxDocumentBytes)
			}
		}
		records = append(records, pageDocument.Servers...)
		if pageDocument.Metadata.NextCursor == "" {
			var result bytes.Buffer
			encoder := json.NewEncoder(&result)
			if err := encoder.Encode(struct {
				Metadata map[string]int    `json:"metadata"`
				Servers  []json.RawMessage `json:"servers"`
			}{Metadata: map[string]int{"count": len(records)}, Servers: records}); err != nil {
				return nil, err
			}
			if result.Len() > MaxDocumentBytes {
				return nil, fmt.Errorf("aggregated MCP registry response exceeds %d bytes", MaxDocumentBytes)
			}
			return result.Bytes(), nil
		}
		if pageDocument.Metadata.NextCursor == cursor {
			return nil, errors.New("MCP registry pagination cursor did not advance")
		}
		cursor = pageDocument.Metadata.NextCursor
	}
	return nil, errors.New("MCP registry pagination exceeded 1000 pages")
}

func fetch(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "skil-mcp-registry/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch MCP registry: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MCP registry returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("MCP registry response exceeds %d bytes", MaxDocumentBytes)
	}
	return data, nil
}

func validServerName(value string) bool {
	if strings.Count(value, "/") != 1 || strings.ContainsAny(value, "?#\\\x00") {
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != "" && value == strings.TrimSpace(value)
}
