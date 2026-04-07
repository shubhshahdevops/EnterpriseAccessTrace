import json
import os
from collections import Counter
from html import escape


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read().strip()
        if not text:
            return []
        return json.loads(text)


def safe_list(data):
    return data if isinstance(data, list) else []


def safe_dict(data):
    return data if isinstance(data, dict) else {}


def make_bar_chart_svg(data_map, title, width=760, height=260):
    if not data_map:
        return f"""
        <div class="chart-card">
            <h3>{escape(title)}</h3>
            <div class="empty-state">No data available</div>
        </div>
        """

    items = list(data_map.items())[:6]
    max_value = max(v for _, v in items) or 1
    left_margin = 160
    top_margin = 30
    bar_height = 26
    gap = 12
    chart_width = width - left_margin - 40

    svg_parts = [
        f'<div class="chart-card"><h3>{escape(title)}</h3>',
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="svg-chart">'
    ]

    for i, (label, value) in enumerate(items):
        y = top_margin + i * (bar_height + gap)
        bar_w = max(4, int((value / max_value) * chart_width))
        safe_label = escape(str(label))
        svg_parts.append(
            f'<text x="10" y="{y + 18}" fill="#cbd5e1" font-size="13">{safe_label}</text>'
        )
        svg_parts.append(
            f'<rect x="{left_margin}" y="{y}" rx="8" ry="8" width="{bar_w}" height="{bar_height}" fill="#3b82f6"></rect>'
        )
        svg_parts.append(
            f'<text x="{left_margin + bar_w + 10}" y="{y + 18}" fill="#f8fafc" font-size="13">{value}</text>'
        )

    svg_parts.append("</svg></div>")
    return "".join(svg_parts)


def make_stats_cards(stats):
    cards = []
    for label, value, sub, accent in stats:
        cards.append(f"""
        <div class="stat-card">
            <div class="stat-label">{escape(label)}</div>
            <div class="stat-value">{escape(str(value))}</div>
            <div class="stat-sub {accent}">{escape(sub)}</div>
        </div>
        """)
    return "".join(cards)


def build_table_rows(rows, columns, badge_column=None):
    if not rows:
        return f'<tr><td colspan="{len(columns)}">No records available.</td></tr>'

    html_rows = []
    for row in rows:
        html_rows.append("<tr>")
        for col in columns:
            value = row.get(col, "")
            safe_value = escape(str(value))

            if badge_column and col == badge_column:
                css_class = safe_value.lower()
                html_rows.append(f'<td><span class="badge {css_class}">{safe_value}</span></td>')
            else:
                html_rows.append(f"<td>{safe_value}</td>")
        html_rows.append("</tr>")

    return "".join(html_rows)


def build_report(output_dir: str) -> str:
    summary = safe_dict(load_json(os.path.join(output_dir, "summary.json")))
    acl_records = safe_list(load_json(os.path.join(output_dir, "acl_records.json")))
    access_paths = safe_list(load_json(os.path.join(output_dir, "access_paths.json")))
    drift_findings = safe_list(load_json(os.path.join(output_dir, "drift_findings.json")))

    root_path = summary.get("RootPath", "Unknown")
    total_acl = summary.get("TotalAclRecords", len(acl_records))
    total_paths = summary.get("TotalAccessPaths", len(access_paths))
    total_drift = summary.get("TotalDriftFindings", len(drift_findings))

    unique_paths = len({r.get("Path", "") for r in acl_records if r.get("Path")})
    unique_identities = len({r.get("Identity", "") for r in acl_records if r.get("Identity")})

    rights_counter = Counter()
    identity_counter = Counter()
    severity_counter = Counter()

    for row in acl_records:
        rights = str(row.get("Rights", "Unknown")).split(",")[0].strip()
        rights_counter[rights] += 1
        identity_counter[str(row.get("Identity", "Unknown"))] += 1

    for row in drift_findings:
        severity_counter[str(row.get("Severity", "Unknown"))] += 1

    top_rights = dict(rights_counter.most_common(6))
    top_identities = dict(identity_counter.most_common(6))
    top_severity = dict(severity_counter.most_common(6))

    risky_paths_counter = Counter(row.get("Path", "Unknown") for row in drift_findings if row.get("Path"))
    top_risky_paths = dict(risky_paths_counter.most_common(6))

    exposure_score = min(100, (total_drift * 8) + (unique_identities // 2))

    stats_html = make_stats_cards([
        ("Total ACL Records", total_acl, f"{unique_paths} paths scanned", "blue"),
        ("Resolved Access Paths", total_paths, f"{unique_identities} identities resolved", "green"),
        ("Drift Findings", total_drift, "Broad access and drift indicators", "amber"),
        ("Exposure Score", exposure_score, "Higher score suggests more review needed", "red"),
    ])

    rights_chart = make_bar_chart_svg(top_rights, "Permission Distribution")
    identity_chart = make_bar_chart_svg(top_identities, "Top Identities by Permission Presence")
    severity_chart = make_bar_chart_svg(top_severity, "Drift Findings by Severity")
    risky_chart = make_bar_chart_svg(top_risky_paths, "Top Risky Paths")

    access_rows = build_table_rows(
        access_paths[:100],
        ["Target", "Path", "IdentityMatch", "Rights", "AccessType", "Reason"]
    )

    drift_rows = build_table_rows(
        drift_findings[:100],
        ["Severity", "Category", "Path", "Description"],
        badge_column="Severity"
    )

    acl_preview_rows = build_table_rows(
        acl_records[:100],
        ["Path", "ItemType", "Identity", "Rights", "AccessType", "Inherited"]
    )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Access Trace Report</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(180deg, #0b1220 0%, #111827 100%);
            color: #f8fafc;
        }}
        .page {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 28px;
        }}
        .hero {{
            margin-bottom: 22px;
        }}
        .hero h1 {{
            margin: 0;
            font-size: 30px;
            font-weight: 800;
        }}
        .hero p {{
            margin: 10px 0 0;
            color: #94a3b8;
            font-size: 15px;
        }}
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 22px;
        }}
        .stat-card, .panel, .chart-card {{
            background: rgba(30, 41, 59, 0.92);
            border: 1px solid #334155;
            border-radius: 16px;
            box-shadow: 0 12px 28px rgba(0,0,0,0.22);
        }}
        .stat-card {{
            padding: 18px;
        }}
        .stat-label {{
            color: #94a3b8;
            font-size: 13px;
            margin-bottom: 10px;
        }}
        .stat-value {{
            font-size: 34px;
            font-weight: 800;
            margin-bottom: 8px;
        }}
        .stat-sub {{
            font-size: 13px;
        }}
        .blue {{ color: #60a5fa; }}
        .green {{ color: #4ade80; }}
        .amber {{ color: #fbbf24; }}
        .red {{ color: #f87171; }}

        .panel {{
            padding: 20px;
            margin-bottom: 22px;
        }}
        .panel h2 {{
            margin: 0 0 12px 0;
            font-size: 22px;
        }}
        .panel p {{
            color: #d1d5db;
            line-height: 1.5;
            margin: 0;
        }}

        .chart-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
            margin-bottom: 22px;
        }}
        .chart-card {{
            padding: 20px;
        }}
        .chart-card h3 {{
            margin: 0 0 14px 0;
            font-size: 18px;
        }}
        .svg-chart {{
            width: 100%;
            height: auto;
            display: block;
        }}
        .empty-state {{
            color: #94a3b8;
            padding: 20px 0;
        }}

        .table-panel {{
            background: rgba(30, 41, 59, 0.92);
            border: 1px solid #334155;
            border-radius: 16px;
            box-shadow: 0 12px 28px rgba(0,0,0,0.22);
            padding: 20px;
            margin-bottom: 22px;
        }}
        .table-panel h2 {{
            margin: 0 0 14px 0;
            font-size: 22px;
        }}
        .table-wrap {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid #334155;
            font-size: 14px;
            vertical-align: top;
        }}
        th {{
            color: #cbd5e1;
            font-weight: 700;
        }}
        td {{
            color: #e5e7eb;
        }}
        .badge {{
            display: inline-block;
            min-width: 74px;
            text-align: center;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
        }}
        .badge.high {{
            background: #7f1d1d;
            color: #fecaca;
        }}
        .badge.medium {{
            background: #78350f;
            color: #fde68a;
        }}
        .badge.low {{
            background: #14532d;
            color: #bbf7d0;
        }}
        .badge.unknown {{
            background: #334155;
            color: #e2e8f0;
        }}

        .footer-note {{
            color: #94a3b8;
            font-size: 13px;
            margin-top: 8px;
        }}

        @media (max-width: 1100px) {{
            .grid-stats {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .chart-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        @media (max-width: 640px) {{
            .grid-stats {{
                grid-template-columns: 1fr;
            }}
            .page {{
                padding: 16px;
            }}
        }}
    </style>
</head>
<body>
    <div class="page">
        <div class="hero">
            <h1>Enterprise Access Trace</h1>
            <p>Permission analysis report for {escape(str(root_path))}</p>
        </div>

        <div class="grid-stats">
            {stats_html}
        </div>

        <div class="panel">
            <h2>Executive Summary</h2>
            <p>
                This report summarizes file-system access data collected from the selected scan scope.
                It highlights permission distribution, identity concentration, matched target access paths,
                and broad-access indicators that may represent permission drift or unnecessary exposure.
            </p>
            <div class="footer-note">
                Scope scanned: {escape(str(root_path))} • Unique paths: {unique_paths} • Unique identities: {unique_identities}
            </div>
        </div>

        <div class="chart-grid">
            {rights_chart}
            {identity_chart}
            {severity_chart}
            {risky_chart}
        </div>

        <div class="table-panel">
            <h2>Access Path Matches</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Path</th>
                            <th>Identity Match</th>
                            <th>Rights</th>
                            <th>Access Type</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {access_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="table-panel">
            <h2>Permission Drift Findings</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Path</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {drift_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="table-panel">
            <h2>ACL Record Preview</h2>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Item Type</th>
                            <th>Identity</th>
                            <th>Rights</th>
                            <th>Access Type</th>
                            <th>Inherited</th>
                        </tr>
                    </thead>
                    <tbody>
                        {acl_preview_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

    report_path = os.path.join(output_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path