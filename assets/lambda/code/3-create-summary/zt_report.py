"""
Generate a Zero Trust Evidence Report from SHCA compliance data.

This module creates a standalone HTML report mapping DoD Zero Trust
activities to NIST 800-53 controls and their compliance status as
evaluated by AWS Security Hub CSPM.
"""
import logging
from collections import defaultdict

import pandas as pd

from zt_mapping import ZT_ACTIVITIES, ZT_PILLAR_COLORS
from zt_control_mapping import SH_TO_ZT_MAPPING, get_zt_activities_for_rule

logger = logging.getLogger()


def generate_zt_report(clean_condensed_data, summary_data):
    """Generate the Zero Trust HTML report using curated SH control mappings."""

    # Build rule-level pass/fail from the condensed data
    rule_status = {}
    for rule_id, grp in clean_condensed_data.groupby("rule_id"):
        passed = len(grp[grp["compliance_status"] == "PASSED"])
        failed = len(grp[grp["compliance_status"] == "FAILED"])
        total = passed + failed
        title = grp.iloc[0].get("title", "")
        remediation = grp.iloc[0].get("remediation", "")
        reference = grp.iloc[0].get("reference", "")
        rule_status[rule_id] = {
            "passed": passed,
            "failed": failed,
            "total": total,
            "status": "PASSED" if failed == 0 else "FAILED",
            "pct": (passed / total * 100) if total else 0,
            "title": title,
            "remediation": remediation,
            "reference": reference,
        }

    # Build per-activity results using the curated mapping
    zt_lookup = {a[0]: {"pillar": a[1], "level": a[2], "description": a[3], "nist_controls": a[4]} for a in ZT_ACTIVITIES}
    
    # Invert: ZT activity -> list of SH controls
    activity_to_rules = defaultdict(list)
    activity_rationales = defaultdict(list)
    for rule_id, entry in SH_TO_ZT_MAPPING.items():
        for zt_act in entry["zt_activities"]:
            if rule_id in rule_status:  # only include rules present in the data
                activity_to_rules[zt_act].append(rule_id)
                activity_rationales[zt_act].append((rule_id, entry["rationale"]))

    activity_results = []
    for activity_id, pillar, level, desc, nist_controls in ZT_ACTIVITIES:
        rules = activity_to_rules.get(activity_id, [])
        if rules:
            pcts = [rule_status[r]["pct"] for r in rules]
            avg_pct = sum(pcts) / len(pcts)
            all_passed = all(rule_status[r]["status"] == "PASSED" for r in rules)
            all_failed = all(rule_status[r]["status"] == "FAILED" for r in rules)
            if all_passed:
                overall = "compliant"
            elif all_failed:
                overall = "non-compliant"
            else:
                overall = "partially compliant"
        else:
            avg_pct = None
            overall = "no evidence"

        activity_results.append({
            "activity_id": activity_id,
            "pillar": pillar,
            "level": level,
            "description": desc,
            "nist_controls": nist_controls,
            "matched_rules": sorted(rules),
            "rationales": activity_rationales.get(activity_id, []),
            "status": overall,
            "percentage": avg_pct,
        })

    # Pillar summary
    pillar_summary = defaultdict(lambda: {"total": 0, "evidenced": 0, "compliant": 0, "partial": 0, "non_compliant": 0})
    for ar in activity_results:
        p = ar["pillar"]
        pillar_summary[p]["total"] += 1
        if ar["status"] != "no evidence":
            pillar_summary[p]["evidenced"] += 1
        if ar["status"] == "compliant":
            pillar_summary[p]["compliant"] += 1
        elif ar["status"] == "partially compliant":
            pillar_summary[p]["partial"] += 1
        elif ar["status"] == "non-compliant":
            pillar_summary[p]["non_compliant"] += 1

    total_activities = len(activity_results)
    evidenced = sum(1 for a in activity_results if a["status"] != "no evidence")
    compliant_count = sum(1 for a in activity_results if a["status"] == "compliant")

    html = _build_html(activity_results, pillar_summary, total_activities, evidenced, compliant_count, rule_status)
    return html


def _status_badge(status):
    if status == "compliant":
        return '<span class="badge badge-pass">COMPLIANT</span>'
    elif status == "non-compliant":
        return '<span class="badge badge-fail">NON-COMPLIANT</span>'
    elif status == "partially compliant":
        return '<span class="badge badge-partial">PARTIAL</span>'
    return '<span class="badge" style="background:#999;color:#fff;">NO EVIDENCE</span>'


def _pct_style(pct):
    if pct is None:
        return "color:#999;"
    if pct == 100:
        return "color:#1b8a2d;font-weight:600;"
    if pct == 0:
        return "color:#d13212;font-weight:600;"
    return "font-weight:600;"


def _build_html(activity_results, pillar_summary, total_activities, evidenced, compliant_count, rule_status):
    # Pillar summary cards
    pillar_cards = ""
    for pillar in ["User", "Device", "Network", "App/Workload", "Data", "Visibility", "Automation"]:
        ps = pillar_summary[pillar]
        color = ZT_PILLAR_COLORS.get(pillar, "#333")
        pillar_cards += f"""
            <div style="background:var(--bg-light);padding:12px 8px;border-radius:6px;text-align:center;">
                <div style="font-size:1.3rem;font-weight:700;color:{color};">{ps["evidenced"]}/{ps["total"]}</div>
                <div style="font-size:0.65rem;color:var(--text-secondary);text-transform:uppercase;">{pillar}</div>
            </div>"""

    # Evidence matrix rows
    matrix_rows = ""
    for ar in activity_results:
        color = ZT_PILLAR_COLORS.get(ar["pillar"], "#333")
        nist_codes = " ".join(f'<code>{c}</code>' for c in ar["nist_controls"])
        rule_codes = " ".join(f'<code>{r}</code>' for r in ar["matched_rules"]) if ar["matched_rules"] else '<span style="color:#999;">\u2014</span>'
        badge = _status_badge(ar["status"])
        pct_str = f'{ar["percentage"]:.0f}%' if ar["percentage"] is not None else "\u2014"
        pct_s = _pct_style(ar["percentage"])

        matrix_rows += f"""
            <tr>
                <td><strong>{ar["activity_id"]}</strong></td>
                <td><span class="pillar-badge" style="background:{color};">{ar["pillar"]}</span></td>
                <td>{ar["level"]}</td>
                <td>{ar["description"]}</td>
                <td>{nist_codes}</td>
                <td>{rule_codes}</td>
                <td>{badge}</td>
                <td style="{pct_s}">{pct_str}</td>
            </tr>"""

    # Coverage table
    coverage_rows = ""
    for pillar in ["User", "Device", "Network", "App/Workload", "Data", "Visibility", "Automation"]:
        ps = pillar_summary[pillar]
        color = ZT_PILLAR_COLORS.get(pillar, "#333")
        pct = int((ps["evidenced"] / ps["total"]) * 100) if ps["total"] else 0
        coverage_rows += f"""
            <tr>
                <td><span class="pillar-badge" style="background:{color};">{pillar}</span></td>
                <td>{ps["total"]}</td>
                <td>{ps["evidenced"]}</td>
                <td>{ps["compliant"]}</td>
                <td>{ps["partial"]}</td>
                <td>{ps["non_compliant"]}</td>
                <td>{pct}%</td>
                <td><div class="bar-container"><div class="bar" style="width:{pct}%;background:{color};">{pct}%</div></div></td>
            </tr>"""

    # Evidence details per pillar
    evidence_details = ""
    for pillar in ["User", "Device", "Network", "App/Workload", "Data", "Visibility", "Automation"]:
        color = ZT_PILLAR_COLORS.get(pillar, "#333")
        pillar_activities = [a for a in activity_results if a["pillar"] == pillar and a["status"] != "no evidence"]
        if not pillar_activities:
            continue

        detail_rows = ""
        for ar in pillar_activities:
            for rule_id, rationale in ar["rationales"]:
                if rule_id not in rule_status:
                    continue
                rs = rule_status[rule_id]
                status_color = "#1b8a2d" if rs["status"] == "PASSED" else "#d13212"
                title_short = rs["title"][:80] + ("..." if len(rs["title"]) > 80 else "")

                if rs["status"] == "PASSED":
                    explanation = rationale
                else:
                    ref_link = f' <a href="{rs["reference"]}">[Remediation]</a>' if rs["reference"] else ""
                    explanation = f'{rs["remediation"]}{ref_link}'

                detail_rows += f"""
                    <tr>
                        <td><strong>{ar["activity_id"]}</strong></td>
                        <td><code>{rule_id}</code></td>
                        <td style="font-size:0.85rem;">{title_short}</td>
                        <td style="color:{status_color};font-weight:600;">{rs["passed"]}/{rs["total"]}</td>
                        <td style="font-size:0.85rem;color:var(--text-secondary);">{explanation}</td>
                    </tr>"""

        if detail_rows:
            evidence_details += f"""
            <div class="summary-box">
                <h2 class="summary-title"><span class="pillar-badge" style="background:{color};">{pillar}</span> Evidence Details</h2>
                <table>
                    <tr><th>ZT Activity</th><th>Control</th><th>Title</th><th>Pass/Total</th><th>Rationale / Remediation</th></tr>
                    {detail_rows}
                </table>
            </div>"""

    return f"""
<html>
<head>
    <meta charset="UTF-8">
    <style>
        :root {{
            --aws-dark: #232f3e; --aws-orange: #ff9900; --pass-green: #1b8a2d; --fail-red: #d13212;
            --bg-light: #fafafa; --bg-card: #ffffff; --border: #e8e8e8;
            --text-primary: #16191f; --text-secondary: #545b64;
            --font-body: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Amazon Ember', sans-serif;
            --font-mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: var(--font-body); color: var(--text-primary); background: var(--bg-light); line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, var(--aws-dark) 0%, #37475a 100%); color: #fff; text-align: center; padding: 40px 20px; position: relative; }}
        .header h1 {{ font-size: 1.75rem; font-weight: 600; }}
        .header p {{ opacity: 0.8; margin-top: 8px; }}
        .header::after {{ content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 3px; background: var(--aws-orange); }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 20px; }}
        .summary-box {{ background: var(--bg-card); border-radius: 8px; margin-bottom: 16px; padding: 24px; border: 1px solid var(--border); border-left: 4px solid var(--aws-dark); box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
        .summary-box:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .summary-title {{ color: var(--aws-dark); font-size: 1.15rem; font-weight: 600; margin: 0 0 16px 0; padding-bottom: 12px; border-bottom: 1px solid var(--border); }}
        .summary-box p {{ color: var(--text-secondary); font-size: 0.925rem; margin-bottom: 10px; }}
        table {{ width: 100%; border-collapse: separate; border-spacing: 0; background: var(--bg-card); border-radius: 6px; overflow: hidden; border: 1px solid var(--border); font-size: 0.85rem; margin-top: 12px; }}
        th {{ background: var(--aws-dark); color: #fff; padding: 10px 12px; text-align: left; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; position: sticky; top: 0; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:nth-child(even) {{ background: var(--bg-light); }}
        tr:hover {{ background: #f0f4f8; }}
        code {{ background: #f0f2f4; padding: 2px 5px; border-radius: 3px; font-family: var(--font-mono); font-size: 0.8rem; color: var(--aws-dark); }}
        .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; font-weight: 600; display: inline-block; }}
        .badge-pass {{ background: #1b8a2d; color: #fff; }}
        .badge-fail {{ background: #d13212; color: #fff; }}
        .badge-partial {{ background: #f2a900; color: #16191f; }}
        .pillar-badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; display: inline-block; color: #fff; }}
        .bar-container {{ display: flex; background-color: #eaeded; border-radius: 20px; overflow: hidden; height: 20px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.06); }}
        .bar {{ height: 20px; display: flex; align-items: center; justify-content: center; color: white; padding: 0 8px; font-size: 0.7rem; font-weight: 600; white-space: nowrap; }}
        .disclaimer {{ background: #fff8e1; border: 1px solid #f2a900; border-left: 4px solid #f2a900; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
        .disclaimer p {{ color: var(--text-primary); font-size: 0.9rem; margin-bottom: 6px; }}
        @media print {{
            body {{ background: #fff; }}
            .summary-box {{ break-inside: avoid; box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SHCA \u2014 Zero Trust Activity Evidence Report</h1>
        <p>DoD Zero Trust Capability Execution Roadmap \u00d7 NIST SP 800-53 Rev. 5 \u00d7 AWS Security Hub CSPM</p>
    </div>
    <div class="container">

        <div class="disclaimer">
            <p><strong>\u26a0 Disclaimer:</strong> This report presents a <strong>proposed mapping</strong> between DoD Zero Trust activities and AWS Security Hub CSPM security controls. These mappings are <strong>not prescriptive</strong> and represent one interpretation of how automated cloud posture checks can provide evidence for Zero Trust activities.</p>
            <p>Organizations must review, accept, or modify these mappings based on their specific environment, risk posture, and authorization boundary. The accompanying <code>zt_mapping.csv</code> and <code>zt_mapping.json</code> files contain the complete mapping with rationale for each entry.</p>
        </div>

        <div class="summary-box" style="padding:28px;">
            <h2 class="summary-title">Zero Trust Coverage Summary</h2>
            <p>SHCA artifacts provide automated evidence for <strong>{evidenced} of {total_activities}</strong> DoD Zero Trust activities through continuous AWS Security Hub CSPM security checks. Of those, <strong>{compliant_count}</strong> are fully compliant.</p>
            <div style="display:grid;grid-template-columns:repeat(7,1fr);gap:8px;margin-top:16px;">
                {pillar_cards}
            </div>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Coverage by Pillar</h2>
            <table>
                <tr><th>Pillar</th><th>Total</th><th>Evidenced</th><th>Compliant</th><th>Partial</th><th>Non-Compliant</th><th>Coverage</th><th></th></tr>
                {coverage_rows}
            </table>
            <p style="margin-top:12px;"><em>Activities without evidence require non-technical documentation (policy, training, physical security) outside the scope of automated cloud posture management.</em></p>
        </div>

        <div class="summary-box">
            <h2 class="summary-title">Zero Trust Activity Evidence Matrix</h2>
            <p>Each row maps a DoD ZT activity to the NIST 800-53 controls and Security Hub security checks that provide automated evidence.</p>
            <table>
                <tr><th>ZT Activity</th><th>Pillar</th><th>Level</th><th>Description</th><th>NIST Controls</th><th>Security Hub Checks</th><th>Status</th><th>Score</th></tr>
                {matrix_rows}
            </table>
        </div>

        {evidence_details}

    </div>
</body>
</html>
"""
