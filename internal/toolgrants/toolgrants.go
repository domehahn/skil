// Package toolgrants parses scoped tool-grant declarations such as
// "Bash(git:*) Read" without ever widening their scope, and audits effective
// invocations against them.
package toolgrants

import (
	"errors"
	"fmt"
	"strings"
)

// Grant is one declared permission. Unrestricted is true only for a bare tool
// name ("Read") or an explicit full wildcard ("Bash(*)"); a malformed scoped
// grant is rejected, never degraded to unrestricted.
type Grant struct {
	Tool         string `json:"tool"`
	Scope        string `json:"scope,omitempty"` // command prefix for prefix grants, exact string otherwise
	Prefix       bool   `json:"prefix,omitempty"`
	Unrestricted bool   `json:"unrestricted,omitempty"`
	Raw          string `json:"raw"`
}

// Parse splits a declaration into grants. Separators are whitespace or commas
// outside parentheses.
func Parse(declaration string) ([]Grant, error) {
	var tokens []string
	depth, start := 0, -1
	flush := func(end int) {
		if start >= 0 {
			tokens = append(tokens, declaration[start:end])
			start = -1
		}
	}
	for i, r := range declaration {
		switch {
		case r == '(':
			depth++
			if start < 0 {
				start = i
			}
		case r == ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced ')' in tool grant")
			}
		case depth == 0 && (r == ' ' || r == '\t' || r == '\n' || r == ','):
			flush(i)
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced '(' in tool grant")
	}
	flush(len(declaration))
	grants := make([]Grant, 0, len(tokens))
	for _, tok := range tokens {
		g, err := parseOne(tok)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, nil
}

func parseOne(tok string) (Grant, error) {
	open := strings.IndexByte(tok, '(')
	if open < 0 {
		if tok == "" || strings.ContainsAny(tok, ")*") {
			return Grant{}, fmt.Errorf("invalid tool name %q", tok)
		}
		return Grant{Tool: tok, Unrestricted: true, Raw: tok}, nil
	}
	if !strings.HasSuffix(tok, ")") || open == 0 {
		return Grant{}, fmt.Errorf("malformed tool grant %q", tok)
	}
	tool, inner := tok[:open], strings.TrimSpace(tok[open+1:len(tok)-1])
	if strings.ContainsAny(tool, ")*") || strings.ContainsAny(inner, "()") {
		return Grant{}, fmt.Errorf("malformed tool grant %q", tok)
	}
	switch {
	case inner == "":
		return Grant{}, fmt.Errorf("empty scope in %q", tok)
	case inner == "*":
		return Grant{Tool: tool, Unrestricted: true, Raw: tok}, nil
	case strings.HasSuffix(inner, ":*"):
		scope := strings.TrimSpace(strings.TrimSuffix(inner, ":*"))
		if scope == "" || strings.Contains(scope, "*") {
			return Grant{}, fmt.Errorf("invalid prefix scope in %q", tok)
		}
		return Grant{Tool: tool, Scope: scope, Prefix: true, Raw: tok}, nil
	case strings.Contains(inner, "*"):
		return Grant{}, fmt.Errorf("unsupported wildcard placement in %q", tok)
	}
	return Grant{Tool: tool, Scope: inner, Raw: tok}, nil
}

const shellMeta = ";&|`$()<>\n\r\\"

// Allows reports whether the grant permits invoking tool with argument text
// (for Bash, the full command line). Scoped Bash grants additionally reject
// any command containing shell metacharacters, so "git status; rm -rf /"
// cannot ride on a "git status:*" grant.
func (g Grant) Allows(tool, command string) bool {
	if g.Tool != tool {
		return false
	}
	if g.Unrestricted {
		return true
	}
	command = strings.TrimSpace(command)
	if strings.ContainsAny(command, shellMeta) {
		return false
	}
	if !g.Prefix {
		return command == g.Scope
	}
	if command == g.Scope {
		return true
	}
	return strings.HasPrefix(command, g.Scope+" ")
}

// Violation is an effective invocation not covered by any declared grant.
type Violation struct {
	Tool    string `json:"tool"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type Invocation struct{ Tool, Command string }

// Audit compares declared grants with effective invocations. With no grants
// declared every invocation is a violation (deny by default).
func Audit(grants []Grant, invocations []Invocation) []Violation {
	var out []Violation
	for _, inv := range invocations {
		allowed := false
		for _, g := range grants {
			if g.Allows(inv.Tool, inv.Command) {
				allowed = true
				break
			}
		}
		if !allowed {
			out = append(out, Violation{Tool: inv.Tool, Command: inv.Command, Reason: "invocation is outside every declared grant"})
		}
	}
	return out
}
