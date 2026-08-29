package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/domehahn/skil/pkg/skil"
)

func writeInteractiveWorkbench(w io.Writer, r skil.ScanResult) error {
	scanJSON, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal scan result for workbench: %w", err)
	}

	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SKIL Interactive Security Workbench — ` + html.EscapeString(r.Artifact.Name) + `</title>
<style>
:root {
  --bg: #0f172a; --card: #1e293b; --card-hover: #334155; --text: #f8fafc; --muted: #94a3b8;
  --border: #334155; --critical: #ef4444; --high: #f97316; --medium: #eab308;
  --low: #3b82f6; --pass: #22c55e; --fail: #ef4444; --accent: #6366f1;
}
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.5; }
.container { max-width: 1300px; margin: 0 auto; }
.header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; }
.nav-tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid var(--border); }
.tab-btn { background: transparent; border: none; color: var(--muted); padding: 10px 20px; font-weight: bold; cursor: pointer; border-bottom: 3px solid transparent; font-size: 0.95rem; }
.tab-btn.active { color: var(--text); border-bottom-color: var(--accent); }
.tab-content { display: none; }
.tab-content.active { display: block; }
.card { background: var(--card); border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px; }
.stat-box { background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 6px; border: 1px solid var(--border); }
.stat-val { font-size: 1.8rem; font-weight: bold; }
.badge { padding: 4px 12px; border-radius: 9999px; font-weight: bold; text-transform: uppercase; font-size: 0.85rem; }
.badge-PASS, .badge-CLEAR, .badge-ALLOW { background: rgba(34, 197, 94, 0.2); color: var(--pass); border: 1px solid var(--pass); }
.badge-FAIL, .badge-BLOCK, .badge-DENY { background: rgba(239, 68, 68, 0.2); color: var(--fail); border: 1px solid var(--fail); }
.badge-WARN, .badge-REVIEW { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
.sev-CRITICAL { color: var(--critical); font-weight: bold; }
.sev-HIGH { color: var(--high); font-weight: bold; }
.sev-MEDIUM { color: var(--medium); }
.sev-LOW { color: var(--low); }
code, pre { font-family: monospace; background: rgba(0, 0, 0, 0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
pre { padding: 12px; overflow-x: auto; }
.control-group { margin-bottom: 15px; }
label { display: block; color: var(--muted); font-size: 0.85rem; margin-bottom: 5px; font-weight: bold; }
select, input[type="text"] { width: 100%; background: #0f172a; border: 1px solid var(--border); color: var(--text); padding: 8px 12px; border-radius: 6px; }
.switch { display: flex; align-items: center; gap: 10px; cursor: pointer; }
.btn { background: var(--accent); color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
.btn:hover { opacity: 0.9; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 style="margin:0;">SKIL Interactive Security Workbench</h1>
      <div style="color:var(--muted); font-size:0.9rem;">Artifact: <code>` + html.EscapeString(r.Artifact.Name) + `</code> | Digest: <code>sha256:` + html.EscapeString(r.Artifact.Digest) + `</code></div>
    </div>
    <div>
      <span class="badge badge-` + string(r.Status) + `">` + string(r.Status) + `</span>
      <span class="badge badge-` + string(r.Verdict) + `">` + string(r.Verdict) + `</span>
    </div>
  </div>

  <div class="nav-tabs">
    <button class="tab-btn active" onclick="showTab('dashboard')">Dashboard & Metrics</button>
    <button class="tab-btn" onclick="showTab('findings')">Findings Explorer</button>
    <button class="tab-btn" onclick="showTab('policy')">Live Policy Simulator</button>
    <button class="tab-btn" onclick="showTab('surface')">Execution Surface Map</button>
  </div>

  <!-- TAB 1: DASHBOARD -->
  <div id="tab-dashboard" class="tab-content active">
    <div class="card">
      <h3 style="margin-top:0;">Risk & Completeness Overview</h3>
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
          <div style="color:var(--muted); font-size:0.85rem;">FINDINGS COUNT</div>
          <div class="stat-val">` + fmt.Sprintf("%d", len(r.Findings)) + `</div>
        </div>
        <div class="stat-box">
          <div style="color:var(--muted); font-size:0.85rem;">OBSERVATIONS</div>
          <div class="stat-val">` + fmt.Sprintf("%d", len(r.Observations)) + `</div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: FINDINGS EXPLORER -->
  <div id="tab-findings" class="tab-content">
    <div class="card">
      <div style="display:flex; gap:15px; margin-bottom:15px;">
        <input type="text" id="search-input" placeholder="Search findings by rule or title..." onkeyup="filterFindings()">
        <select id="sev-filter" onchange="filterFindings()" style="width:200px;">
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>
      <div id="findings-table-container"></div>
    </div>
  </div>

  <!-- TAB 3: POLICY SIMULATOR -->
  <div id="tab-policy" class="tab-content">
    <div class="card">
      <h3 style="margin-top:0;">Live Policy Simulator ("What-If" Analysis)</h3>
      <div class="grid" style="margin-bottom:20px;">
        <div class="control-group">
          <label>MAXIMUM SEVERITY THRESHOLD</label>
          <select id="policy-max-sev" onchange="simulatePolicy()">
            <option value="HIGH" selected>HIGH (Deny Critical)</option>
            <option value="MEDIUM">MEDIUM (Deny Critical/High)</option>
            <option value="LOW">LOW (Deny Critical/High/Medium)</option>
          </select>
        </div>
        <div class="control-group">
          <label>ALLOW SHELL HOOKS</label>
          <select id="policy-allow-shell" onchange="simulatePolicy()">
            <option value="false" selected>DENY (Strict)</option>
            <option value="true">ALLOW</option>
          </select>
        </div>
        <div class="control-group">
          <label>ALLOW PERMISSION BYPASS</label>
          <select id="policy-allow-bypass" onchange="simulatePolicy()">
            <option value="false" selected>DENY (Strict)</option>
            <option value="true">ALLOW</option>
          </select>
        </div>
      </div>

      <div class="stat-box" style="margin-bottom:15px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div style="color:var(--muted); font-size:0.85rem;">SIMULATED POLICY DECISION</div>
            <div id="simulated-verdict" class="stat-val">ALLOW</div>
          </div>
          <button class="btn" onclick="exportPolicyYAML()">Export Policy YAML</button>
        </div>
      </div>
      <div id="policy-violations-container"></div>
    </div>
  </div>

  <!-- TAB 4: SURFACE MAP -->
  <div id="tab-surface" class="tab-content">
    <div class="card">
      <h3 style="margin-top:0;">Observed Agent Capabilities & Surface</h3>
      <div id="surface-container"></div>
    </div>
  </div>
</div>

<script>
const scanData = ` + string(scanJSON) + `;

function showTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + tabId).classList.add('active');
}

function renderFindings() {
  const container = document.getElementById('findings-table-container');
  if (!scanData.findings || scanData.findings.length === 0) {
    container.innerHTML = '<p style="color:var(--pass);">No security findings observed.</p>';
    return;
  }

  let html = '<table><thead><tr><th>Severity</th><th>Rule ID</th><th>Title</th><th>Location</th></tr></thead><tbody>';
  scanData.findings.forEach(f => {
    html += '<tr class="finding-row" data-sev="' + f.severity + '" data-text="' + (f.rule_id + ' ' + f.title).toLowerCase() + '">';
    html += '<td class="sev-' + f.severity + '">' + f.severity + '</td>';
    html += '<td><code>' + f.rule_id + '</code></td>';
    html += '<td>' + f.title + '</td>';
    html += '<td><code>' + (f.location ? f.location.file : 'workspace') + '</code></td>';
    html += '</tr>';
  });
  html += '</tbody></table>';
  container.innerHTML = html;
}

function filterFindings() {
  const q = document.getElementById('search-input').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value;

  document.querySelectorAll('.finding-row').forEach(row => {
    const rowSev = row.getAttribute('data-sev');
    const rowText = row.getAttribute('data-text');
    const matchesSev = (sev === 'ALL' || rowSev === sev);
    const matchesText = rowText.includes(q);
    row.style.display = (matchesSev && matchesText) ? '' : 'none';
  });
}

function simulatePolicy() {
  const maxSev = document.getElementById('policy-max-sev').value;
  const allowShell = document.getElementById('policy-allow-shell').value === 'true';
  const allowBypass = document.getElementById('policy-allow-bypass').value === 'true';

  let violations = [];
  const sevRanks = { "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4 };

  scanData.findings.forEach(f => {
    if (sevRanks[f.severity] > sevRanks[maxSev]) {
      violations.push("Severity " + f.severity + " finding [" + f.rule_id + "] exceeds policy limit " + maxSev);
    }
    if (!allowShell && f.rule_id === "SKIL-AGENT-HOOK-001") {
      violations.push("Shell execution hook detected [" + f.rule_id + "] but allow_shell_hooks is false");
    }
    if (!allowBypass && f.rule_id === "SKIL-AGENT-PERM-001") {
      violations.push("Permission bypass mode detected [" + f.rule_id + "] but allow_permission_bypass is false");
    }
  });

  const vElement = document.getElementById('simulated-verdict');
  const container = document.getElementById('policy-violations-container');

  if (violations.length === 0) {
    vElement.textContent = "ALLOW";
    vElement.className = "stat-val badge-ALLOW";
    container.innerHTML = '<p style="color:var(--pass);">Policy simulation passed cleanly without violations.</p>';
  } else {
    vElement.textContent = "DENY";
    vElement.className = "stat-val badge-DENY";
    let h = '<h4 style="color:var(--fail);">Simulated Policy Violations (' + violations.length + '):</h4><ul>';
    violations.forEach(v => { h += '<li style="color:var(--fail);">' + v + '</li>'; });
    h += '</ul>';
    container.innerHTML = h;
  }
}

function renderSurface() {
  const container = document.getElementById('surface-container');
  if (!scanData.observations || scanData.observations.length === 0) {
    container.innerHTML = '<p style="color:var(--muted);">No execution surface capabilities recorded.</p>';
    return;
  }

  let html = '<table><thead><tr><th>Capability</th><th>Observed Value</th><th>Source File</th></tr></thead><tbody>';
  scanData.observations.forEach(o => {
    html += '<tr><td><code>' + o.capability + '</code></td><td><code>' + o.value + '</code></td><td>' + (o.file || 'workspace') + '</td></tr>';
  });
  html += '</tbody></table>';
  container.innerHTML = html;
}

function exportPolicyYAML() {
  const maxSev = document.getElementById('policy-max-sev').value;
  const allowShell = document.getElementById('policy-allow-shell').value === 'true';
  const allowBypass = document.getElementById('policy-allow-bypass').value === 'true';

  const yaml = "version: 1\nmaximum_severity: " + maxSev + "\nagent_execution:\n  allow_hooks: true\n  allow_shell_hooks: " + allowShell + "\n  allow_permission_bypass: " + allowBypass + "\n";
  const blob = new Blob([yaml], { type: 'text/yaml' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'simulated-policy.yaml';
  a.click();
}

window.onload = function() {
  renderFindings();
  simulatePolicy();
  renderSurface();
};
</script>
</body>
</html>`)

	_, err = w.Write([]byte(buf.String()))
	return err
}
