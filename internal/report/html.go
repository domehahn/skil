package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

func writeHTML(w io.Writer, r skil.ScanResult) error {
	var buf strings.Builder

	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SKIL Security Assurance Report — ` + html.EscapeString(r.Artifact.Name) + `</title>
<style>
:root {
  --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8;
  --border: #334155; --critical: #ef4444; --high: #f97316; --medium: #eab308;
  --low: #3b82f6; --pass: #22c55e; --fail: #ef4444;
}
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; }
.header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; }
.badge { padding: 4px 12px; border-radius: 9999px; font-weight: bold; text-transform: uppercase; font-size: 0.85rem; }
.badge-PASS, .badge-CLEAR { background: rgba(34, 197, 94, 0.2); color: var(--pass); border: 1fr solid var(--pass); }
.badge-FAIL, .badge-BLOCK { background: rgba(239, 68, 68, 0.2); color: var(--fail); border: 1fr solid var(--fail); }
.badge-WARN, .badge-REVIEW { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1fr solid var(--medium); }
.card { background: var(--card); border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
.stat-box { background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 6px; border: 1px solid var(--border); }
.stat-val { font-size: 1.8rem; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
.sev-CRITICAL { color: var(--critical); font-weight: bold; }
.sev-HIGH { color: var(--high); font-weight: bold; }
.sev-MEDIUM { color: var(--medium); }
.sev-LOW { color: var(--low); }
code, pre { font-family: monospace; background: rgba(0, 0, 0, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
pre { padding: 12px; overflow-x: auto; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 style="margin:0;">SKIL Security Assurance Report</h1>
      <div style="color:var(--muted); font-size:0.9rem;">Artifact: <code>` + html.EscapeString(r.Artifact.Name) + `</code> | Digest: <code>sha256:` + html.EscapeString(r.Artifact.Digest) + `</code></div>
    </div>
    <div>
      <span class="badge badge-` + string(r.Status) + `">` + string(r.Status) + `</span>
      <span class="badge badge-` + string(r.Verdict) + `">` + string(r.Verdict) + `</span>
    </div>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">Risk & Coverage Overview</h3>
    <div class="grid">
      <div class="stat-box">
        <div style="color:var(--muted); font-size:0.85rem;">RISK SCORE</div>
        <div class="stat-val">` + fmt.Sprintf("%d / 100", r.RiskScore) + `</div>
      </div>
      <div class="stat-box">
        <div style="color:var(--muted); font-size:0.85rem;">MAX SEVERITY</div>
        <div class="stat-val sev-` + string(r.Maximum) + `">` + string(r.Maximum) + `</div>
      </div>
      <div class="stat-box">
        <div style="color:var(--muted); font-size:0.85rem;">INSPECTION COMPLETENESS</div>
        <div class="stat-val">` + fmt.Sprintf("%.1f%%", r.Completeness.Completeness*100) + `</div>
      </div>
      <div class="stat-box">
        <div style="color:var(--muted); font-size:0.85rem;">ANALYZA BILITY</div>
        <div class="stat-val">` + fmt.Sprintf("%.1f%%", r.Analyzable.Coverage*100) + `</div>
      </div>
    </div>
  </div>`)

	// Findings Section
	buf.WriteString(`
  <div class="card">
    <h3 style="margin-top:0;">Security Findings (` + fmt.Sprintf("%d", len(r.Findings)) + `)</h3>`)
	if len(r.Findings) == 0 {
		buf.WriteString(`<p style="color:var(--pass);">No security findings observed in this artifact.</p>`)
	} else {
		buf.WriteString(`<table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule ID</th>
          <th>Title</th>
          <th>Location</th>
          <th>Disposition</th>
        </tr>
      </thead>
      <tbody>`)
		for _, f := range r.Findings {
			disp := f.ContextDisposition
			if disp == "" {
				disp = "confirmed"
			}
			buf.WriteString(`<tr>
          <td class="sev-` + string(f.Severity) + `">` + string(f.Severity) + `</td>
          <td><code>` + html.EscapeString(f.RuleID) + `</code></td>
          <td>` + html.EscapeString(f.Title) + `</td>
          <td><code>` + html.EscapeString(f.Location.File) + `:` + fmt.Sprintf("%d", f.Location.StartLine) + `</code></td>
          <td><span class="badge">` + html.EscapeString(disp) + `</span></td>
        </tr>`)
		}
		buf.WriteString(`</tbody></table>`)
	}
	buf.WriteString(`</div>`)

	if r.DerivedViews != nil && (len(r.DerivedViews.Views) > 0 || !r.DerivedViews.Complete) {
		buf.WriteString(`<div class="card">
    <h3 style="margin-top:0;">Derived Security Views</h3>
    <p>Views: <strong>` + fmt.Sprintf("%d", len(r.DerivedViews.Views)) + `</strong> |
       Complete: <strong>` + fmt.Sprintf("%t", r.DerivedViews.Complete) + `</strong> |
       Bytes: <strong>` + fmt.Sprintf("%d", r.DerivedViews.Bytes) + `</strong> |
       Maximum depth: <strong>` + fmt.Sprintf("%d", r.DerivedViews.MaxDepth) + `</strong></p>`)
		if len(r.DerivedViews.Limitations) > 0 {
			buf.WriteString(`<p>Limitations: ` + html.EscapeString(strings.Join(r.DerivedViews.Limitations, "; ")) + `</p>`)
		}
		buf.WriteString(`</div>`)
	}

	// Transitive Closure Section if present
	if r.Closure != nil {
		buf.WriteString(`
  <div class="card">
    <h3 style="margin-top:0;">Assurance Closure</h3>
    <p>State: <strong>` + html.EscapeString(string(r.Closure.State)) + `</strong> |
       Complete: <strong>` + fmt.Sprintf("%t", r.Closure.Complete) + `</strong> |
       Verified: <strong>` + fmt.Sprintf("%t", r.Closure.Verified) + `</strong> |
       Closure Digest: <code>` + html.EscapeString(r.Closure.Digest) + `</code></p>
    <table>
      <thead>
        <tr>
          <th>Depth</th>
          <th>Source / Reference</th>
          <th>Digest</th>
          <th>Status</th>
          <th>Max Severity</th>
        </tr>
      </thead>
      <tbody>`)
		for _, n := range r.Closure.Nodes {
			buf.WriteString(`<tr>
          <td>` + fmt.Sprintf("%d", n.Depth) + `</td>
          <td><code>` + html.EscapeString(n.Source) + `</code></td>
          <td><code>` + html.EscapeString(n.Digest) + `</code></td>
          <td>` + html.EscapeString(n.ScanStatus) + `</td>
          <td class="sev-` + string(n.MaximumSeverity) + `">` + string(n.MaximumSeverity) + `</td>
        </tr>`)
		}
		buf.WriteString(`</tbody></table></div>`)
	}

	// Raw JSON evidence footer for auditability
	rawJSON, _ := json.MarshalIndent(r, "", "  ")
	buf.WriteString(`
  <div class="card">
    <h3 style="margin-top:0;">Structured JSON Evidence</h3>
    <pre><code>` + html.EscapeString(string(rawJSON)) + `</code></pre>
  </div>
</div>
</body>
</html>`)

	_, err := io.WriteString(w, buf.String())
	return err
}
