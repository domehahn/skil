package cli

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domehahn/skil/internal/policy"
	"github.com/domehahn/skil/pkg/skil"
)

const maxAdmissionRequestBytes = 1 << 20

// admission implements the "trust boundary before agentic code runs"
// pattern the roadmap calls an admission controller: a registry, marketplace,
// or agent host can call this instead of shelling out to the CLI, getting
// back a single ALLOW/DENY decision backed by the same scan and policy
// engine `skil scan` / `skil policy check` use.
func (a *App) admission(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] != "serve" {
		return a.inputError(errors.New("usage: skil admission serve --root dir --listen host:port --policy file [--token-env VAR]"))
	}
	fs := newFlags("admission serve", a.Err)
	listen := fs.String("listen", "", "serve the admission API on a loopback address")
	tokenEnv := fs.String("token-env", "SKIL_ADMISSION_TOKEN", "environment variable containing the HTTP bearer token")
	root := fs.String("root", "", "only permit scans below this directory")
	policyPath := fs.String("policy", "", "policy file each admitted artifact is evaluated against")
	if code := parse(fs, args[1:], 0); code != ExitOK {
		return code
	}
	if *listen == "" || *root == "" || *policyPath == "" {
		return a.inputError(errors.New("admission serve requires --root, --listen, and --policy"))
	}
	info, err := os.Lstat(*root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return a.inputError(errors.New("admission root must be a non-symlink directory"))
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		return a.inputError(err)
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		return a.inputError(err)
	}
	token := os.Getenv(*tokenEnv)
	if len(token) < 32 {
		return a.inputError(fmt.Errorf("%s must contain at least 32 characters", *tokenEnv))
	}
	if err := a.serveAdmissionHTTP(ctx, absoluteRoot, *listen, token, pol); err != nil {
		return a.inputError(err)
	}
	return ExitOK
}

func (a *App) serveAdmissionHTTP(ctx context.Context, root, address, token string, pol policy.Policy) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("--listen must be a host:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("admission HTTP currently permits only explicit loopback addresses")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for admission HTTP: %w", err)
	}
	server := &http.Server{
		Handler:           a.admissionHTTPHandler(ctx, root, token, pol),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type admissionRequest struct {
	Path string `json:"path"`
}

type admissionResponse struct {
	Decision        string             `json:"decision"`
	RiskScore       int                `json:"risk_score,omitempty"`
	MaximumSeverity skil.Severity      `json:"maximum_severity,omitempty"`
	Violations      []policy.Violation `json:"violations,omitempty"`
	Error           string             `json:"error,omitempty"`
}

func (a *App) admissionHTTPHandler(ctx context.Context, root, token string, pol policy.Policy) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodPost || request.URL.Path != "/v1/admission" {
			http.NotFound(writer, request)
			return
		}
		supplied := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		if len(supplied) != len(token) || subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxAdmissionRequestBytes)
		var req admissionRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil || req.Path == "" {
			writeAdmissionResult(writer, http.StatusBadRequest, admissionResponse{Decision: "ERROR", Error: "invalid admission request: a non-empty path is required"})
			return
		}
		target, err := confinedMCPPath(root, req.Path)
		if err != nil {
			writeAdmissionResult(writer, http.StatusBadRequest, admissionResponse{Decision: "ERROR", Error: err.Error()})
			return
		}
		scan, contract, err := a.performScan(ctx, target, "")
		if err != nil {
			writeAdmissionResult(writer, http.StatusUnprocessableEntity, admissionResponse{Decision: "ERROR", Error: err.Error()})
			return
		}
		result := policy.Check(pol, policy.Input{Scan: scan, Contract: contract})
		status := http.StatusOK
		if result.Decision != "ALLOW" {
			status = http.StatusForbidden
		}
		writeAdmissionResult(writer, status, admissionResponse{
			Decision: result.Decision, RiskScore: scan.RiskScore, MaximumSeverity: scan.Maximum, Violations: result.Violations,
		})
	})
}

func writeAdmissionResult(writer http.ResponseWriter, status int, response admissionResponse) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(response)
}
