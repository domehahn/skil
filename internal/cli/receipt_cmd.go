package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/domehahn/skil/internal/receipt"
	"gopkg.in/yaml.v3"
)

// RunReceipt executes the `skil receipt verify <receipt-file>` command.
func RunReceipt(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: skil receipt verify <receipt-file> [options]")
		return ExitInput
	}

	subCmd := args[0]
	if subCmd != "verify" {
		fmt.Fprintf(errOut, "unknown receipt subcommand %q, expected 'verify'\n", subCmd)
		return ExitInput
	}

	fs := newFlags("receipt verify", errOut)
	expectedSubject := fs.String("subject", "", "expected artifact subject digest (sha256:...)")
	expectedPolicy := fs.String("policy", "", "expected policy digest (sha256:...)")
	requireIsolation := fs.Bool("require-native-isolation", false, "require native isolation active state")
	format := fs.String("format", "terminal", "output format: terminal, json, or yaml")
	outputFile := fs.String("output", "", "output file path")

	if code := parse(fs, args[1:], 1); code != ExitOK {
		return code
	}

	receiptFile := fs.Arg(0)
	if receiptFile == "" {
		fmt.Fprintln(errOut, "error: missing required <receipt-file> argument")
		return ExitInput
	}

	data, err := os.ReadFile(receiptFile)
	if err != nil {
		fmt.Fprintf(errOut, "error reading receipt file %s: %v\n", receiptFile, err)
		return ExitInput
	}

	var rec receipt.SKRunReceiptV1
	if err := json.Unmarshal(data, &rec); err != nil {
		fmt.Fprintf(errOut, "error parsing receipt JSON: %v\n", err)
		return ExitInput
	}

	opts := receipt.VerificationOptions{
		ExpectedSubjectDigest:  *expectedSubject,
		ExpectedPolicyDigest:   *expectedPolicy,
		RequireNativeIsolation: *requireIsolation,
		TrustedKeys:            map[string]string{}, // Can be populated via trusted key parameters
	}

	res := receipt.VerifyReceipt(&rec, opts)

	writer := out
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(errOut, "error creating output file %s: %v\n", *outputFile, err)
			return ExitInput
		}
		defer f.Close()
		writer = f
	}

	switch *format {
	case "json":
		outData, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(writer, string(outData))
	case "yaml":
		outData, _ := yaml.Marshal(res)
		fmt.Fprintln(writer, string(outData))
	default:
		if res.Valid {
			fmt.Fprintf(writer, "VALID skrun Execution Receipt\n")
			fmt.Fprintf(writer, "Execution ID:    %s\n", res.ExecutionID)
			fmt.Fprintf(writer, "Subject Digest:  %s\n", res.SubjectDigest)
			fmt.Fprintf(writer, "Runtime Backend: %s\n", res.RuntimeBackend)
			fmt.Fprintf(writer, "Reason:          %s\n", res.Reason)
		} else {
			fmt.Fprintf(writer, "INVALID skrun Execution Receipt\n")
			fmt.Fprintf(writer, "Reason:          %s\n", res.Reason)
		}
	}

	if !res.Valid {
		return ExitGateFail
	}
	return ExitOK
}
