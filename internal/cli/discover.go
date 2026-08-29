package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/domehahn/skil/internal/discover"
)

func (a *App) discover(args []string) int {
	fs := newFlags("discover", a.Err)
	home := fs.String("home", "", "home/profile directory to probe (default: the current user's home directory)")
	workspace := fs.String("workspace", "", "workspace directory to probe for local agent configs")
	infra := fs.Bool("infra", false, "probe local AI execution runtimes and server infrastructure")
	format := fs.String("format", "terminal", "terminal or json")
	output := fs.String("output", "", "discovery result output")
	if code := parse(fs, args, 0); code != ExitOK {
		return code
	}
	if *format != "terminal" && *format != "json" {
		return a.inputError(errors.New("discover supports terminal or json output"))
	}

	var components []discover.Component
	var scanErrs []error
	homeDir := *home

	if *infra {
		wsDir := *workspace
		if wsDir == "" {
			wsDir = "."
		}
		infraComponents, err := discover.DiscoverInfra(wsDir)
		if err != nil {
			return a.inputError(fmt.Errorf("infra discovery: %w", err))
		}
		for _, ic := range infraComponents {
			components = append(components, discover.Component{
				Tool:    ic.Name,
				Kind:    discover.ComponentKind(ic.Kind),
				Name:    ic.Name,
				Path:    ic.Path,
				Command: ic.Version,
			})
		}
	} else if *workspace != "" {
		wsComponents, err := discover.DiscoverWorkspace(*workspace)
		if err != nil {
			return a.inputError(fmt.Errorf("workspace discovery: %w", err))
		}
		components = wsComponents
	} else {
		if homeDir == "" {
			resolved, err := os.UserHomeDir()
			if err != nil {
				return a.inputError(fmt.Errorf("resolve home directory: %w (use --home to specify one explicitly)", err))
			}
			homeDir = resolved
		}
		locations := discover.KnownLocations(homeDir, runtime.GOOS)
		components, scanErrs = discover.Scan(locations)
	}

	if components == nil {
		components = []discover.Component{}
	}
	result := discoverResult{
		SchemaVersion: "1.0.0", Home: homeDir, Workspace: *workspace, Components: components,
		Errors: errorStrings(scanErrs),
	}

	writer, closeFn, err := outputWriter(a.Out, *output)
	if err != nil {
		return a.inputError(err)
	}
	defer closeFn()
	if *format == "json" {
		err = writeJSON(writer, result)
	} else {
		err = writeDiscoverTerminal(writer, result)
	}
	if err != nil {
		return a.internalError(err)
	}
	return ExitOK
}

type discoverResult struct {
	SchemaVersion string               `json:"schema_version"`
	Home          string               `json:"home,omitempty"`
	Workspace     string               `json:"workspace,omitempty"`
	Components    []discover.Component `json:"components"`
	Errors        []string             `json:"errors,omitempty"`
}

func errorStrings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, len(errs))
	for i, err := range errs {
		out[i] = err.Error()
	}
	return out
}

func writeDiscoverTerminal(writer io.Writer, result discoverResult) error {
	if _, err := fmt.Fprintf(writer, "LOCAL COMPONENT DISCOVERY\n\nHome: %s\nFound: %d component(s)\n\nNothing listed here has been executed or scanned — run `skil scan` or\n`skil mcp assure` explicitly on anything below to actually analyze it.\n",
		result.Home, len(result.Components)); err != nil {
		return err
	}
	if len(result.Components) == 0 {
		_, err := fmt.Fprintln(writer, "\nNo known tool locations had anything to find.")
		if err != nil {
			return err
		}
	}
	var lastTool string
	for _, component := range result.Components {
		if component.Tool != lastTool {
			if _, err := fmt.Fprintf(writer, "\n%s\n", component.Tool); err != nil {
				return err
			}
			lastTool = component.Tool
		}
		switch component.Kind {
		case discover.KindSkill:
			if _, err := fmt.Fprintf(writer, "  [skill]      %s (%s)\n", component.Name, component.Path); err != nil {
				return err
			}
		case discover.KindMCPServer:
			if _, err := fmt.Fprintf(writer, "  [mcp_server] %s: %s %v (declared in %s)\n",
				component.Name, component.Command, component.Args, component.Path); err != nil {
				return err
			}
		}
	}
	if len(result.Errors) > 0 {
		if _, err := fmt.Fprintf(writer, "\nErrors (%d)\n", len(result.Errors)); err != nil {
			return err
		}
		for _, message := range result.Errors {
			if _, err := fmt.Fprintf(writer, "  - %s\n", message); err != nil {
				return err
			}
		}
	}
	return nil
}
