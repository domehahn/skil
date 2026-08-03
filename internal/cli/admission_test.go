package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func waitForAdmissionServer(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("admission server never became reachable at %s", address)
}

func postAdmission(t *testing.T, address, token, path string) admissionResponse {
	t.Helper()
	body, err := json.Marshal(admissionRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/v1/admission", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var decoded admissionResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAdmissionServeAllowsCleanSkill(t *testing.T) {
	rootDir := filepath.Dir(fixture(t, "clean-skill"))
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: CRITICAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	t.Setenv("SKIL_ADMISSION_TOKEN", token)
	address := freeLoopbackAddress(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	done := make(chan int, 1)
	go func() {
		done <- app.Run(ctx, []string{"admission", "serve", "--root", rootDir, "--listen", address, "--policy", policyPath})
	}()
	waitForAdmissionServer(t, address)

	response := postAdmission(t, address, token, "clean-skill")
	if response.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW for clean-skill, got %#v", response)
	}

	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("admission serve exited with code %d: %s", code, errOut.String())
	}
}

func TestAdmissionServeDeniesPolicyViolation(t *testing.T) {
	rootDir := filepath.Dir(fixture(t, "malicious-skill"))
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: LOW\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	t.Setenv("SKIL_ADMISSION_TOKEN", token)
	address := freeLoopbackAddress(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	done := make(chan int, 1)
	go func() {
		done <- app.Run(ctx, []string{"admission", "serve", "--root", rootDir, "--listen", address, "--policy", policyPath})
	}()
	waitForAdmissionServer(t, address)

	response := postAdmission(t, address, token, "malicious-skill")
	if response.Decision != "DENY" {
		t.Fatalf("expected DENY for a skill exceeding the policy's maximum severity, got %#v", response)
	}

	cancel()
	<-done
}

func TestAdmissionServeDeniesUnauthenticatedRequest(t *testing.T) {
	rootDir := filepath.Dir(fixture(t, "clean-skill"))
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: CRITICAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKIL_ADMISSION_TOKEN", strings.Repeat("a", 32))
	address := freeLoopbackAddress(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	done := make(chan int, 1)
	go func() {
		done <- app.Run(ctx, []string{"admission", "serve", "--root", rootDir, "--listen", address, "--policy", policyPath})
	}()
	waitForAdmissionServer(t, address)

	body, err := json.Marshal(admissionRequest{Path: "clean-skill"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/v1/admission", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer wrong-token-that-is-long-enough-1234")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a wrong token, got %d", response.StatusCode)
	}

	cancel()
	<-done
}

func TestAdmissionServeRejectsPathEscapingRoot(t *testing.T) {
	rootDir := filepath.Dir(fixture(t, "clean-skill"))
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nmaximum_severity: CRITICAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	t.Setenv("SKIL_ADMISSION_TOKEN", token)
	address := freeLoopbackAddress(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	done := make(chan int, 1)
	go func() {
		done <- app.Run(ctx, []string{"admission", "serve", "--root", rootDir, "--listen", address, "--policy", policyPath})
	}()
	waitForAdmissionServer(t, address)

	response := postAdmission(t, address, token, "../../../etc")
	if response.Decision != "ERROR" || response.Error == "" {
		t.Fatalf("expected a path-escape error, got %#v", response)
	}

	cancel()
	<-done
}

func TestAdmissionRejectsMissingFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	app := New(&out, &errOut)
	if code := app.Run(context.Background(), []string{"admission", "serve"}); code != ExitInput {
		t.Fatalf("expected missing flags to be an input error, got code=%d: %s", code, errOut.String())
	}
}
