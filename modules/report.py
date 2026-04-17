"""
NTUSF — HTML Report Generator
Produces a self-contained HTML report from scan results.
"""

import sys
import os
import datetime
import pandas as pd
from modules.logger_config import setup_logger

# ---------------------------------------------------------------------------
# Vulnerability metadata: CVSS score, severity, description, remediation
# ---------------------------------------------------------------------------
VULN_META = {
    "XSS": {
        "label": "Cross-Site Scripting (XSS)",
        "cvss": 6.1,
        "severity": "Medium",
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "color": "#e67e22",
        "description": (
            "Reflected XSS allows an attacker to inject client-side scripts into "
            "pages viewed by other users. The browser executes the injected script "
            "in the context of the victim's session, potentially leading to session "
            "hijacking, credential theft, or malicious redirects."
        ),
        "remediation": (
            "<ul>"
            "<li>Encode all user-controlled output before inserting it into HTML "
            "(use context-aware escaping: HTML, JS, CSS, URL).</li>"
            "<li>Implement a strict Content-Security-Policy (CSP) header.</li>"
            "<li>Use modern frameworks that auto-escape by default (React, Vue, Angular).</li>"
            "<li>Validate and sanitize input server-side; reject unexpected characters.</li>"
            "<li>Set the <code>HttpOnly</code> and <code>Secure</code> flags on session cookies.</li>"
            "</ul>"
        ),
    },
    "SQLi": {
        "label": "SQL Injection",
        "cvss": 9.8,
        "severity": "Critical",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "color": "#c0392b",
        "description": (
            "SQL Injection allows an attacker to interfere with database queries, "
            "potentially reading sensitive data, bypassing authentication, modifying "
            "or deleting data, and in some configurations executing OS-level commands."
        ),
        "remediation": (
            "<ul>"
            "<li>Use parameterised queries / prepared statements exclusively — never "
            "concatenate user input into SQL strings.</li>"
            "<li>Apply the principle of least privilege to DB accounts.</li>"
            "<li>Use an ORM that enforces parameterisation by design.</li>"
            "<li>Implement input validation (allowlists, type checks).</li>"
            "<li>Enable a WAF rule set for SQLi patterns as a defence-in-depth layer.</li>"
            "<li>Regularly audit stored procedures and dynamic SQL.</li>"
            "</ul>"
        ),
    },
    "CSRF": {
        "label": "Cross-Site Request Forgery (CSRF)",
        "cvss": 6.5,
        "severity": "Medium",
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "color": "#e67e22",
        "description": (
            "CSRF tricks authenticated users into executing unwanted state-changing "
            "requests (e.g. changing email, transferring funds) without their knowledge. "
            "The attack is carried out by embedding a forged request in a page the "
            "victim visits."
        ),
        "remediation": (
            "<ul>"
            "<li>Use synchroniser token pattern: generate a random CSRF token per session "
            "and validate it on every state-changing request.</li>"
            "<li>Set <code>SameSite=Strict</code> or <code>SameSite=Lax</code> on session cookies.</li>"
            "<li>Verify the <code>Origin</code> / <code>Referer</code> header on sensitive endpoints.</li>"
            "<li>Require re-authentication for critical actions (password change, payments).</li>"
            "</ul>"
        ),
    },
    "Path_Traversal": {
        "label": "Path Traversal",
        "cvss": 7.5,
        "severity": "High",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "color": "#e74c3c",
        "description": (
            "Path Traversal (directory traversal) allows an attacker to read files "
            "outside the intended web root by manipulating file path parameters with "
            "<code>../</code> sequences, exposing configuration files, credentials, "
            "and system files."
        ),
        "remediation": (
            "<ul>"
            "<li>Resolve the canonical path server-side and verify it starts with the "
            "expected base directory before opening any file.</li>"
            "<li>Use a whitelist of permitted filenames / paths; reject everything else.</li>"
            "<li>Avoid passing user-controlled data directly to filesystem APIs.</li>"
            "<li>Run the web server process under a dedicated low-privilege account with "
            "a chroot / container boundary.</li>"
            "</ul>"
        ),
    },
    "Open_Redirect": {
        "label": "Open Redirect",
        "cvss": 6.1,
        "severity": "Medium",
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "color": "#e67e22",
        "description": (
            "Open Redirect allows an attacker to craft a trusted-looking URL on the "
            "target domain that transparently redirects victims to a malicious site, "
            "facilitating phishing and credential theft."
        ),
        "remediation": (
            "<ul>"
            "<li>Avoid using user-supplied data to construct redirect destinations.</li>"
            "<li>If redirects are necessary, maintain a server-side whitelist of "
            "allowed destinations and reject anything not in the list.</li>"
            "<li>Validate the full URL (scheme + host) after normalisation.</li>"
            "<li>Show an interstitial warning page before redirecting to external sites.</li>"
            "</ul>"
        ),
    },
    "SSRF": {
        "label": "Server-Side Request Forgery (SSRF)",
        "cvss": 8.6,
        "severity": "High",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "color": "#e74c3c",
        "description": (
            "SSRF allows an attacker to induce the server to make requests to internal "
            "services or cloud metadata endpoints (e.g. AWS IMDSv1), potentially "
            "exposing credentials, internal service data, or enabling pivoting into "
            "the internal network."
        ),
        "remediation": (
            "<ul>"
            "<li>Block requests to private IP ranges and cloud metadata endpoints at "
            "the network layer.</li>"
            "<li>Validate and sanitise user-supplied URLs: enforce HTTPS, allowlist "
            "permitted domains, block IP literals.</li>"
            "<li>Use IMDSv2 (require a session token) on AWS instances.</li>"
            "<li>Deploy egress filtering so the application server cannot reach "
            "unexpected internal hosts.</li>"
            "</ul>"
        ),
    },
    "SSTI": {
        "label": "Server-Side Template Injection (SSTI)",
        "cvss": 9.8,
        "severity": "Critical",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "color": "#c0392b",
        "description": (
            "SSTI allows an attacker to inject template directives that the server-side "
            "engine evaluates, leading to Remote Code Execution (RCE) in many template "
            "engines (Jinja2, Twig, Freemarker, etc.)."
        ),
        "remediation": (
            "<ul>"
            "<li>Never pass user-controlled data as a template string; always pass it "
            "as template context/variables.</li>"
            "<li>Use sandboxed template environments where available.</li>"
            "<li>Disable or restrict dangerous template features (e.g. Jinja2 sandbox).</li>"
            "<li>Treat SSTI findings as potential RCE — remediate immediately.</li>"
            "</ul>"
        ),
    },
    "CMD_Injection": {
        "label": "Command Injection",
        "cvss": 9.8,
        "severity": "Critical",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "color": "#c0392b",
        "description": (
            "Command Injection allows an attacker to execute arbitrary OS commands on "
            "the server by injecting shell metacharacters into parameters passed to "
            "system calls. This typically results in full server compromise."
        ),
        "remediation": (
            "<ul>"
            "<li>Avoid passing user input to shell commands entirely; use native library "
            "calls instead (e.g. Python's <code>os.rename</code> vs <code>shell=True</code>).</li>"
            "<li>If shell calls are unavoidable, pass arguments as a list "
            "(never as a string) and do not use <code>shell=True</code>.</li>"
            "<li>Validate input against a strict allowlist before use.</li>"
            "<li>Run the application with the minimum OS privileges required.</li>"
            "</ul>"
        ),
    },
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_BADGE = {
    "Critical": "#c0392b",
    "High": "#e74c3c",
    "Medium": "#e67e22",
    "Low": "#27ae60",
    "Info": "#2980b9",
}


def _risk_score(vuln_counts: dict) -> tuple[float, str]:
    """Compute an aggregate risk score 0-10 and a label."""
    weights = {
        "CMD_Injection": 9.8, "SSTI": 9.8, "SQLi": 9.8,
        "SSRF": 8.6, "Path_Traversal": 7.5,
        "Open_Redirect": 6.1, "CSRF": 6.5, "XSS": 6.1,
    }
    total = sum(weights.get(k, 5.0) * min(v, 20) for k, v in vuln_counts.items() if v > 0)
    max_possible = sum(weights.values()) * 5
    score = round(min(10.0, total / max_possible * 10), 1)
    if score >= 8:
        label = "Critical"
    elif score >= 6:
        label = "High"
    elif score >= 4:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "None"
    return score, label


def _rows_for_vuln(df: pd.DataFrame, col: str) -> pd.DataFrame:
    if col not in df.columns:
        return pd.DataFrame()
    return df[df[col] == 1][["URL", "Method"]].drop_duplicates()


def generate_report(base_url: str, merged_df: pd.DataFrame, output_path: str) -> None:
    logger = setup_logger(__name__)

    vuln_cols = [c for c in VULN_META if c in merged_df.columns]
    vuln_counts = {c: int(merged_df[c].sum()) for c in vuln_cols}
    total_findings = sum(vuln_counts.values())
    risk_score, risk_label = _risk_score(vuln_counts)
    risk_color = SEVERITY_BADGE.get(risk_label, "#7f8c8d")

    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------
    # Build finding cards
    # ------------------------------------------------------------------
    cards_html = ""
    for col in sorted(vuln_cols, key=lambda c: SEVERITY_ORDER.get(VULN_META[c]["severity"], 99)):
        meta = VULN_META[col]
        count = vuln_counts.get(col, 0)
        if count == 0:
            status_badge = '<span class="badge badge-ok">Not Found</span>'
        else:
            status_badge = f'<span class="badge" style="background:{meta["color"]}">{count} Found</span>'

        rows = _rows_for_vuln(merged_df, col)
        if rows.empty:
            table_html = "<p class='no-vulns'>No vulnerable endpoints detected.</p>"
        else:
            rows_html = "".join(
                f"<tr><td>{r['URL']}</td><td>{r['Method']}</td></tr>"
                for _, r in rows.iterrows()
            )
            table_html = (
                "<table class='endpoint-table'>"
                "<thead><tr><th>URL</th><th>Method</th></tr></thead>"
                f"<tbody>{rows_html}</tbody>"
                "</table>"
            )

        sev_color = SEVERITY_BADGE.get(meta["severity"], "#7f8c8d")
        cards_html += f"""
        <div class="card" id="{col}">
          <div class="card-header" style="border-left:6px solid {meta['color']}">
            <div>
              <span class="vuln-name">{meta['label']}</span>
              <span class="cvss-badge" style="background:{sev_color}">
                CVSS {meta['cvss']} &mdash; {meta['severity']}
              </span>
            </div>
            {status_badge}
          </div>
          <p class="cvss-vector"><code>{meta['vector']}</code></p>
          <h4>Description</h4>
          <p>{meta['description']}</p>
          <h4>Affected Endpoints</h4>
          {table_html}
          <h4>Remediation</h4>
          <div class="remediation">{meta['remediation']}</div>
        </div>
        """

    # ------------------------------------------------------------------
    # Summary table rows
    # ------------------------------------------------------------------
    summary_rows = ""
    for col in sorted(vuln_cols, key=lambda c: SEVERITY_ORDER.get(VULN_META[c]["severity"], 99)):
        meta = VULN_META[col]
        count = vuln_counts.get(col, 0)
        color = meta["color"] if count > 0 else "#27ae60"
        summary_rows += (
            f"<tr>"
            f"<td>{meta['label']}</td>"
            f"<td><span class='badge' style='background:{SEVERITY_BADGE[meta['severity']]}'>"
            f"{meta['severity']}</span></td>"
            f"<td style='color:{color};font-weight:bold'>{count}</td>"
            f"<td>CVSS {meta['cvss']}</td>"
            f"</tr>"
        )

    # ------------------------------------------------------------------
    # Assemble full HTML (self-contained, no external resources)
    # ------------------------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>NTUSF Scan Report &mdash; {base_url}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #2c3e50; line-height: 1.6; }}
    a {{ color: #2980b9; }}

    /* Header */
    header {{ background: #1a252f; color: #ecf0f1; padding: 2rem 3rem; }}
    header h1 {{ font-size: 1.9rem; font-weight: 700; }}
    header .sub {{ margin-top: .4rem; opacity: .8; font-size: .95rem; }}

    /* Layout */
    .container {{ max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }}

    /* Risk banner */
    .risk-banner {{ border-radius: 8px; padding: 1.5rem 2rem; margin-bottom: 2rem;
                    display: flex; align-items: center; gap: 2rem;
                    background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
    .risk-score {{ font-size: 3.5rem; font-weight: 800; color: {risk_color}; line-height:1; }}
    .risk-label {{ font-size: 1.1rem; color: {risk_color}; font-weight: 600; }}
    .risk-meta {{ font-size: .85rem; color: #7f8c8d; margin-top: .25rem; }}

    /* Summary table */
    .summary-table {{ width: 100%; border-collapse: collapse; background: #fff;
                      border-radius: 8px; overflow: hidden;
                      box-shadow: 0 2px 8px rgba(0,0,0,.08); margin-bottom: 2rem; }}
    .summary-table th {{ background: #2c3e50; color: #ecf0f1; padding: .75rem 1rem; text-align:left; }}
    .summary-table td {{ padding: .65rem 1rem; border-bottom: 1px solid #ecf0f1; }}
    .summary-table tr:last-child td {{ border-bottom: none; }}

    /* Cards */
    .card {{ background: #fff; border-radius: 8px;
             box-shadow: 0 2px 8px rgba(0,0,0,.08); margin-bottom: 1.5rem;
             overflow: hidden; }}
    .card-header {{ display: flex; justify-content: space-between; align-items: flex-start;
                    padding: 1rem 1.2rem; background: #fafafa; border-bottom: 1px solid #eee; }}
    .vuln-name {{ font-weight: 700; font-size: 1.05rem; display: block; }}
    .cvss-badge {{ font-size: .8rem; color: #fff; padding: .2rem .6rem;
                   border-radius: 4px; margin-top: .3rem; display: inline-block; }}
    .cvss-vector {{ font-size: .78rem; color: #95a5a6; padding: .4rem 1.2rem; background:#fafafa; }}
    .card h4 {{ padding: .8rem 1.2rem .3rem; font-size: .95rem; color: #34495e;
                border-top: 1px solid #f0f0f0; }}
    .card p {{ padding: .3rem 1.2rem .8rem; font-size: .92rem; }}
    .remediation {{ padding: .3rem 1.2rem 1rem; font-size: .92rem; }}
    .remediation ul {{ padding-left: 1.4rem; }}
    .remediation li {{ margin-bottom: .4rem; }}
    .no-vulns {{ color: #27ae60; padding: .5rem 1.2rem !important; }}

    /* Endpoint table */
    .endpoint-table {{ width: 100%; border-collapse: collapse; font-size: .88rem;
                       margin: .3rem 1.2rem .5rem; width: calc(100% - 2.4rem); }}
    .endpoint-table th {{ background: #ecf0f1; padding: .5rem .8rem; text-align:left; }}
    .endpoint-table td {{ padding: .45rem .8rem; border-bottom: 1px solid #f0f0f0;
                          word-break: break-all; }}

    /* Badges */
    .badge {{ font-size: .8rem; color: #fff; padding: .25rem .7rem;
              border-radius: 12px; white-space: nowrap; }}
    .badge-ok {{ background: #27ae60; }}

    /* Footer */
    footer {{ text-align: center; padding: 2rem; font-size: .85rem; color: #95a5a6; }}

    h2 {{ font-size: 1.3rem; margin-bottom: 1rem; color: #2c3e50; }}
  </style>
</head>
<body>
  <header>
    <h1>NTUSF Vulnerability Scan Report</h1>
    <div class="sub">Target: <strong>{base_url}</strong> &nbsp;|&nbsp; Generated: {scan_date}</div>
  </header>

  <div class="container">

    <!-- Risk Banner -->
    <div class="risk-banner">
      <div>
        <div class="risk-score">{risk_score}</div>
        <div style="font-size:.8rem;color:#7f8c8d;margin-top:.2rem">/ 10</div>
      </div>
      <div>
        <div class="risk-label">Risk Level: {risk_label}</div>
        <div class="risk-meta">{total_findings} total finding(s) across {len([c for c in vuln_counts if vuln_counts[c]>0])} vulnerability type(s)</div>
      </div>
    </div>

    <!-- Summary -->
    <h2>Executive Summary</h2>
    <table class="summary-table">
      <thead>
        <tr><th>Vulnerability</th><th>Severity</th><th>Count</th><th>CVSS Score</th></tr>
      </thead>
      <tbody>
        {summary_rows}
      </tbody>
    </table>

    <!-- Findings -->
    <h2>Detailed Findings</h2>
    {cards_html}

  </div>

  <footer>
    Generated by <strong>NTUSF &mdash; Not The Usual Stupid Fuzzer</strong> &mdash; {scan_date}
  </footer>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info(f"HTML report saved to: {output_path}\n")
