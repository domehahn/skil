package ci

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const githubWorkflowTemplate = `name: SKIL Security Assurance & Gatekeeper

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  skil-security-scan:
    name: SKIL AI Agent Security Scan & Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Install SKIL
        run: go install github.com/domehahn/skil/cmd/skil@latest

      - name: Run SKIL Security Scan & SARIF Export
        run: skil scan . --format sarif --output skil-results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skil-results.sarif

      - name: Generate CycloneDX SBOAC
        run: skil sbom . --format cyclonedx --output skil-sbom.json

      - name: Generate Attestation
        run: skil attest . --output attestation.json

      - name: SKIL Admission Gatekeeper Check
        run: skil gate check --artifact . --attestation attestation.json --policy %s
`

const gitlabCITemplate = `stages:
  - security

skil_security_scan:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/domehahn/skil/cmd/skil@latest
    - skil scan . --format sarif --output skil-results.sarif
    - skil sbom . --format cyclonedx --output skil-sbom.json
    - skil attest . --output attestation.json
    - skil gate check --artifact . --attestation attestation.json --policy %s
  artifacts:
    reports:
      sast: skil-results.sarif
    paths:
      - skil-sbom.json
      - attestation.json
`

func InitCI(workspaceRoot, platform, policyPath string) (string, error) {
	cleanRoot := filepath.Clean(workspaceRoot)
	if policyPath == "" {
		policyPath = ".skil/policy.yaml"
	}

	platform = strings.ToLower(platform)
	if platform == "" || platform == "github" {
		targetDir := filepath.Join(cleanRoot, ".github", "workflows")
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return "", fmt.Errorf("create github workflows directory: %w", err)
		}
		targetFile := filepath.Join(targetDir, "skil-security.yml")
		content := fmt.Sprintf(githubWorkflowTemplate, policyPath)
		if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
			return "", fmt.Errorf("write github workflow file: %w", err)
		}
		return targetFile, nil
	} else if platform == "gitlab" {
		targetFile := filepath.Join(cleanRoot, ".gitlab-ci.yml")
		content := fmt.Sprintf(gitlabCITemplate, policyPath)
		if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
			return "", fmt.Errorf("write gitlab-ci file: %w", err)
		}
		return targetFile, nil
	}

	return "", fmt.Errorf("unsupported CI platform %q (supported: github, gitlab)", platform)
}
