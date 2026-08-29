package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/domehahn/skil/internal/stego"
)

func (a *App) stego(args []string) int {
	if len(args) == 0 {
		return a.inputError(errors.New("stego requires a subcommand: scan"))
	}

	switch args[0] {
	case "scan":
		return a.stegoScan(args[1:])
	default:
		return a.inputError(fmt.Errorf("unknown stego subcommand %q", args[0]))
	}
}

func (a *App) stegoScan(args []string) int {
	fs := newFlags("stego scan", a.Err)
	format := fs.String("format", "terminal", "terminal or json")

	if code := parse(fs, args, 1); code != ExitOK {
		return code
	}

	targetPath := fs.Arg(0)
	res, err := stego.ScanStego(targetPath)
	if err != nil {
		return a.inputError(err)
	}

	if *format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(a.Out, string(data))
		return ExitOK
	}

	if res.IsClean {
		fmt.Fprintf(a.Out, "[skil] STEGANOGRAPHY SCAN PASSED for target %q: No hidden covert channels detected.\n", res.Target)
		return ExitOK
	}

	fmt.Fprintf(a.Err, "[skil] STEGANOGRAPHY SCAN FAILED for target %q: Detected %d covert steganographic findings.\n", res.Target, len(res.Findings))
	for _, f := range res.Findings {
		fmt.Fprintf(a.Err, "  - %s:%d [%s] %s\n", f.File, f.Line, f.ChannelType, f.Snippet)
	}
	return ExitGateFail
}
